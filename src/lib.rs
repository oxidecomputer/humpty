// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]

use zerocopy::{AsBytes, FromBytes};

pub const DUMP_MAGIC: [u8; 4] = [0x1, 0xde, 0xde, 0xad];
pub const DUMP_UNINITIALIZED: [u8; 4] = [0xba, 0xd, 0xca, 0xfe];
pub const DUMP_SEGMENT_PAD: u8 = 0x55;
pub const DUMP_REGISTER_MAGIC: [u8; 2] = [0xab, 0xba];

pub const DUMPER_NONE: u8 = 0xff;
pub const DUMPER_EMULATED: u8 = 0xfe;

const DUMP_SEGMENT_ALIGN: usize = 4;
const DUMP_SEGMENT_MASK: usize = DUMP_SEGMENT_ALIGN - 1;

#[derive(Copy, Clone, Debug, FromBytes, AsBytes, PartialEq)]
#[repr(C, packed)]
pub struct DumpAreaHeader {
    /// Magic to indicate that this is an area header
    pub magic: [u8; 4],

    /// Address of this dump area (should match address of header)
    pub address: u32,

    /// Length of this area
    pub length: u32,

    /// Total bytes that have been actually written in this area,
    /// including all headers
    pub written: u32,

    /// Version of dump agent
    pub agent_version: u8,

    /// Version of dumper (to be written by dumper)
    pub dumper_version: u8,

    /// Number of segment headers that follow this header
    pub nsegments: u16,

    /// Next area, or zero (sorry!) if there isn't one
    pub next: u32,
}

#[derive(Copy, Clone, Debug, FromBytes, AsBytes)]
#[repr(C, packed)]
pub struct DumpSegmentHeader {
    pub address: u32,
    pub length: u32,
}

//
// A segment of actual data, as stored by the dumper into the dump area(s).  Note
// that we very much depend on endianness here:  any unused space at the end of
// of a single area will be filled with DUMP_SEGMENT_PAD.
//
#[derive(Copy, Clone, Debug, FromBytes, AsBytes)]
#[repr(C, packed)]
#[cfg(target_endian = "little")]
pub struct DumpSegmentData {
    pub address: u32,
    pub compressed_length: u16,
    pub uncompressed_length: u16,
}

#[derive(Copy, Clone, Debug, FromBytes, AsBytes)]
#[repr(C, packed)]
pub struct DumpRegister {
    /// Register magic -- must be DUMP_REGISTER_MAGIC
    pub magic: [u8; 2],

    /// Name of register
    pub register: u16,

    /// Value of register
    pub value: u32,
}

pub struct RegisterRead(pub u16, pub u32);

impl DumpRegister {
    fn new(register: RegisterRead) -> Self {
        DumpRegister {
            magic: DUMP_REGISTER_MAGIC,
            register: register.0,
            value: register.1,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum DumpError<T> {
    BufferTooSmall,
    BufferTooSmallForCompression,
    BufferSizeMisaligned,
    InvalidDumperVersion,
    BadMagic(u32),
    BadDumpHeader(u32),
    BadHeaderRead(u32, T),
    BadSegmentHeader(u32),
    BadSegmentHeaderRead(u32, T),
    BadDataRead(u32, T),
    CompressionOverflow(u32, usize, usize),
    BadHeaderWrite(u32, T),
    BadFinalHeaderWrite(u32, T),
    BadSegmentHeaderWrite(u32, T),
    BadSegmentDataWrite(u32, T),
    OutOfSpace(u32),
    CorruptHeaderAddress(u32),
    CorruptSegments(u32),
    BadRegisterRead(T),
    BadRegisterWrite(u32, T),
    OutOfRegisterSpace,
}

//
// This is sized to allow for reasonably small buffers for [`dump`] -- down
// to 128 bytes or so.
//
pub type DumpLzss = lzss::Lzss<6, 4, 0x20, { 1 << 6 }, { 2 << 6 }>;

///
/// This function performs the actual dumping.  It takes three closures:
///
/// - [`register_read`] reads a register value from the target to be made
///   present in the dump (or [`None`] to denote that there are no more
///   registers to read)
///
/// - [`read`] performs a read from the target from the specified address
///   into the provided buffer
///
/// - [`write`] performs a write into the target at the specified address
///   from the provided buffer
///
pub fn dump<T, const N: usize, const V: u8>(
    base: u32,
    mut register_read: impl FnMut() -> Result<Option<RegisterRead>, T>,
    mut read: impl FnMut(u32, &mut [u8]) -> Result<(), T>,
    mut write: impl FnMut(u32, &[u8]) -> Result<(), T>,
) -> Result<(), DumpError<T>> {
    use core::mem::size_of;

    const HEADER_SIZE: usize = size_of::<DumpAreaHeader>();
    let seg_header_size = size_of::<DumpSegmentHeader>();

    //
    // We would like to make these assertions:
    //
    //   const_assert!(N >= size_of::<DumpAreaHeader>());
    //   const_assert!(N >= Lzss::N2);
    //   const_assert!(N & DUMP_SEGMENT_MASK == 0);
    //   const_assert!(V != DUMPER_NONE && V != DUMPER_EMULATED);
    //
    // But static_assertions do not (yet?) support const generics, so we make
    // this a runtime condition instead.
    //
    if N < HEADER_SIZE {
        return Err(DumpError::BufferTooSmall);
    }

    if N < DumpLzss::MIN_OFFSET * 2 {
        return Err(DumpError::BufferTooSmallForCompression);
    }

    if N & DUMP_SEGMENT_MASK != 0 {
        return Err(DumpError::BufferSizeMisaligned);
    }

    if V == DUMPER_NONE || V == DUMPER_EMULATED {
        return Err(DumpError::InvalidDumperVersion);
    }

    let mut buf = [0u8; N];
    let mut hbuf = [0u8; HEADER_SIZE];

    if let Err(e) = read(base, &mut hbuf[..]) {
        return Err(DumpError::BadHeaderRead(base, e));
    }

    let mut header = match DumpAreaHeader::read_from(&hbuf[..]) {
        Some(header) => header,
        None => {
            return Err(DumpError::BadDumpHeader(base));
        }
    };

    if header.magic != DUMP_MAGIC {
        return Err(DumpError::BadMagic(base));
    }

    if header.address != base {
        return Err(DumpError::CorruptHeaderAddress(base));
    }

    //
    // Before we do anything else, write our registers.  We assume that all of
    // our registers can fit in our first dump segment; if they can't we will
    // fail.
    //
    loop {
        match register_read() {
            Ok(None) => break,
            Ok(Some(reg)) => {
                let rheader = DumpRegister::new(reg);
                let size = size_of::<DumpRegister>() as u32;

                if header.written + size >= header.length {
                    return Err(DumpError::OutOfRegisterSpace);
                }

                let raddr = header.address + header.written;

                if let Err(e) = write(raddr, rheader.as_bytes()) {
                    return Err(DumpError::BadRegisterWrite(raddr, e));
                }

                header.written += size;
            }
            Err(e) => return Err(DumpError::BadRegisterRead(e)),
        }
    }

    let nsegments = header.nsegments as usize;
    let mut haddr = base;

    for seg in 0..nsegments {
        let saddr = base + (HEADER_SIZE + seg * seg_header_size) as u32;

        if let Err(e) = read(saddr, &mut buf[..seg_header_size]) {
            return Err(DumpError::BadSegmentHeaderRead(saddr, e));
        }

        let segment =
            match DumpSegmentHeader::read_from(&buf[..seg_header_size]) {
                Some(segment) => segment,
                None => {
                    return Err(DumpError::BadSegmentHeader(saddr));
                }
            };

        //
        // Set our input length to be 3/8ths of our buffer size to assure that
        // we don't run out of buffer when compressing.
        //
        let input_len = (buf.len() / 2) - (buf.len() / 8);

        let mut addr = segment.address;
        let mut remain = segment.length as usize;

        while remain > 0 {
            let nbytes = core::cmp::min(remain, input_len);
            let offs = buf.len() - nbytes;
            let len = buf.len();

            if let Err(e) = read(addr, &mut buf[offs..len]) {
                return Err(DumpError::BadDataRead(addr, e));
            }

            let (mut c, rval) = DumpLzss::compress_in_place(&mut buf, offs);

            if let Some(over) = rval {
                return Err(DumpError::CompressionOverflow(addr, nbytes, over));
            }

            //
            // Our buffer now has our compressed data.  Prepare our header.
            //
            let dheader = DumpSegmentData {
                address: addr,
                compressed_length: c as u16,
                uncompressed_length: nbytes as u16,
            };

            //
            // SWD writes want to always be word-aligned, so we will put our
            // segment pad at the end of our buffer.
            //
            while c & DUMP_SEGMENT_MASK != 0 {
                buf[c] = DUMP_SEGMENT_PAD;
                c += 1;
            }

            let size = size_of::<DumpSegmentData>() + c;

            //
            // ...and now find a spot to write it.
            //
            while header.written + size as u32 >= header.length {
                //
                // We are out of room in this area; we need to write our header.
                //
                let next = header.next;
                header.dumper_version = V;

                if let Err(e) = write(haddr, header.as_bytes()) {
                    return Err(DumpError::BadHeaderWrite(haddr, e));
                }

                haddr = next;

                if haddr == 0 {
                    return Err(DumpError::OutOfSpace(addr));
                }

                if let Err(e) = read(haddr, &mut hbuf[..]) {
                    return Err(DumpError::BadHeaderRead(haddr, e));
                }

                header = match DumpAreaHeader::read_from(&hbuf[..]) {
                    Some(header) => header,
                    None => {
                        return Err(DumpError::BadDumpHeader(haddr));
                    }
                };

                if header.magic != DUMP_MAGIC {
                    return Err(DumpError::BadMagic(haddr));
                }

                if header.address != haddr {
                    return Err(DumpError::CorruptHeaderAddress(haddr));
                }

                //
                // We don't expect any segment descriptions on any but our
                // primary area; if we see a non-zero value here, something
                // deeper could be amiss.
                //
                if header.nsegments != 0 {
                    return Err(DumpError::CorruptSegments(haddr));
                }
            }

            let mut daddr = header.address + header.written;

            //
            // Okay, we have a spot!  Write our header, followed by the main
            // event:  our compressed dump data.
            //
            if let Err(e) = write(daddr, dheader.as_bytes()) {
                return Err(DumpError::BadSegmentHeaderWrite(daddr, e));
            }

            daddr += size_of::<DumpSegmentData>() as u32;

            if let Err(e) = write(daddr, &buf[0..c]) {
                return Err(DumpError::BadSegmentDataWrite(daddr, e));
            }

            header.written += size as u32;

            addr += nbytes as u32;
            remain -= nbytes;
        }
    }

    //
    // We're done!  We need to write out our last header.
    //
    header.dumper_version = V;

    if let Err(e) = write(haddr, header.as_bytes()) {
        return Err(DumpError::BadFinalHeaderWrite(haddr, e));
    }

    Ok(())
}
