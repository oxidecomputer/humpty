// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]

//! humpty: Hubris/Humility dump manipulation
//!
//! This is a no_std crate that allows for dumping the system or some number
//! of tasks to a specified region of memory.  This crate is used by several
//! different consumers across several different domains, and is used by both
//! Hubris and Humility.
//!
//! Our nomenclature:
//!
//! - *Dump area*:  a contiguous area of RAM within Hubris that holds all or
//!   part of a dump.  This is an area of RAM that is not otherwise used by
//!   the system and (obviously?) shouldn't itself be dumped.
//!
//! - *Dump contents*:  the contents of a dump area, and can be either a task
//!   (or part of a task) or the entire system (or part of it).  If an area is
//!   used for part of the system, all dump areas are used to dump the system.
//!   (That is, task dumps cannot be interspersed with system dumps.)
//!
//! - *Dump segment header*:  a header describing a contiguous region of memory
//!   to be written into a dump.  These are added to a dump area via
//!   [`add_dump_segment_header`].
//!
//! - *Dump segment*:  the actual data itself in a dump.  This can have the form
//!   of data (always compressed), or some limited metadata (registers and
//!   task information, if any).  If there is both metadata and data, the
//!   metadata will always precede the data.
//!
//! - *Dump agent proxy*.  The body of software that creates dump areas and
//!   doles them out to dump agents.
//!
//! - *Dump agent*. The software that claims a dump area from the dump agent
//!   proxy for the purpose of arranging dumping into it.
//!
//! - *Dumper*.  The body of software that actually performs the dumping:
//!   knowing only the address of a dump area, it will dump contents into dump
//!   areas such as they are available.  (Jefe, the dedicated dumper task, and
//!   Humility in its emulation modes can all act as the dumper.)
//!
//! In Hubris, Jefe always acts as the dump agent proxy.  In the case of task
//! dumps, Jefe also serves as the dump agent and the dumper (via kernel
//! facilities to read task memory).  For system dumps, the dedicated dump
//! agent serves as the agent, and an outside system (either Humility in its
//! emulation modes or a disjoint microcontroller running Hubris and connected
//! via SWD) acts as the dumper.
//!
//! Regardless of which bodies are playing which part, the flow is:
//!
//!  1. Dump agent asks dump agent proxy to claim an area on its behalf.
//!
//!  2. Dump agent adds segment headers to describe the data to be dumped.
//!
//!  3. Dumper calls [`dump`] to actually do the dumping.  [`dump`] will
//!     read and write to memory via the passed closures.
//!
//!  4. Dump is retrieved by Humility for decompressing and processing.
//!

use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};
use zerocopy::{AsBytes, FromBytes};

pub const DUMP_MAGIC: [u8; 4] = [0x1, 0xde, 0xde, 0xad];
pub const DUMP_UNINITIALIZED: [u8; 4] = [0xba, 0xd, 0xca, 0xfe];
pub const DUMP_SEGMENT_PAD: u8 = 0x55;

const DUMP_SEGMENT_ALIGN: usize = 4;
const DUMP_SEGMENT_MASK: usize = DUMP_SEGMENT_ALIGN - 1;

pub const DUMP_REGISTER_MAGIC: [u8; 2] = [0xab, 0xba];
pub const DUMP_TASK_MAGIC: [u8; 2] = [0xda, 0xda];

pub const DUMPER_NONE: u8 = 0xff;
pub const DUMPER_EMULATED: u8 = 0xfe;
pub const DUMPER_EXTERNAL: u8 = 1;
pub const DUMPER_JEFE: u8 = 2;

pub const DUMP_CONTENTS_AVAILABLE: u8 = 0;
pub const DUMP_CONTENTS_SINGLETASK: u8 = 1;
pub const DUMP_CONTENTS_WHOLESYSTEM: u8 = 2;
pub const DUMP_CONTENTS_INVALID: u8 = 0xff;

#[derive(
    Copy, Clone, Debug, SerializedSize, Serialize, Deserialize, PartialEq, Eq,
)]
pub enum DumpContents {
    /// Dump area is available
    Available,

    /// Dump area contains all/part of a single task
    SingleTask,

    /// Dump area contains all/part of the whole system
    WholeSystem,

    /// Dump area contains unknown contents
    Unknown,
}

impl From<u8> for DumpContents {
    fn from(val: u8) -> Self {
        match val {
            DUMP_CONTENTS_AVAILABLE => DumpContents::Available,
            DUMP_CONTENTS_SINGLETASK => DumpContents::SingleTask,
            DUMP_CONTENTS_WHOLESYSTEM => DumpContents::WholeSystem,
            _ => DumpContents::Unknown,
        }
    }
}

impl From<DumpContents> for u8 {
    fn from(val: DumpContents) -> Self {
        match val {
            DumpContents::Available => DUMP_CONTENTS_AVAILABLE,
            DumpContents::SingleTask => DUMP_CONTENTS_SINGLETASK,
            DumpContents::WholeSystem => DUMP_CONTENTS_WHOLESYSTEM,
            _ => DUMP_CONTENTS_INVALID,
        }
    }
}

#[derive(
    Copy, Clone, Debug, SerializedSize, Serialize, Deserialize, PartialEq, Eq,
)]
pub struct DumpArea {
    pub address: u32,
    pub length: u32,
    pub contents: DumpContents,
}

#[derive(Copy, Clone, Debug, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
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

    /// Dump contents (to be written by agent)
    pub contents: u8,

    /// Dumper (to be written by dumper)
    pub dumper: u8,

    /// Number of segment headers that follow this header
    pub nsegments: u16,

    /// Next area, or zero (sorry!) if there isn't one
    pub next: u32,
}

impl DumpAreaHeader {
    fn read_and_check<T>(
        address: u32,
        mut read: impl FnMut(u32, &mut [u8], bool) -> Result<(), T>,
    ) -> Result<Self, DumpError<T>> {
        const HEADER_SIZE: usize = core::mem::size_of::<DumpAreaHeader>();

        let mut hbuf = [0u8; HEADER_SIZE];

        if let Err(e) = read(address, &mut hbuf[..], true) {
            return Err(DumpError::BadHeaderRead(address, e));
        }

        let header = match DumpAreaHeader::read_from(&hbuf[..]) {
            Some(header) => header,
            None => {
                return Err(DumpError::BadDumpHeader(address));
            }
        };

        if header.magic != DUMP_MAGIC {
            return Err(DumpError::BadMagic(address));
        }

        if header.address != address {
            return Err(DumpError::CorruptHeaderAddress(address));
        }

        Ok(header)
    }
}

#[derive(Copy, Clone, Debug, FromBytes, AsBytes)]
#[repr(C)]
pub struct DumpSegmentHeader {
    pub address: u32,
    pub length: u32,
}

pub enum DumpSegment {
    Data(DumpSegmentData),
    Register(DumpRegister),
    Task(DumpTask),
    Unknown([u8; 2]),
}

impl DumpSegment {
    pub fn from(dump: &[u8]) -> Option<Self> {
        if dump.len() < 2 {
            None
        } else if dump[..2] == DUMP_REGISTER_MAGIC {
            DumpRegister::read_from_prefix(dump).map(DumpSegment::Register)
        } else if dump[..2] == DUMP_TASK_MAGIC {
            DumpTask::read_from_prefix(dump).map(DumpSegment::Task)
        } else if (dump[0] as usize) & DUMP_SEGMENT_MASK != 0 {
            Some(DumpSegment::Unknown([dump[0], dump[1]]))
        } else {
            DumpSegmentData::read_from_prefix(dump).map(DumpSegment::Data)
        }
    }
}

//
// A segment of actual data, as stored by the dumper into the dump area(s).
// Note that we very much depend on endianness here:  any unused space at the
// end of of a single area will be filled with DUMP_SEGMENT_PAD.
//
#[derive(Copy, Clone, Debug, FromBytes, AsBytes)]
#[repr(C)]
#[cfg(target_endian = "little")]
pub struct DumpSegmentData {
    pub address: u32,
    pub compressed_length: u16,
    pub uncompressed_length: u16,
}

#[derive(Copy, Clone, Debug, FromBytes, AsBytes)]
#[repr(C)]
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

#[derive(Copy, Clone, Debug, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct DumpTask {
    /// task magic -- must be DUMP_TASK_MAGIC
    pub magic: [u8; 2],

    /// ID of task that is dumped here (task IDs are maximum 15 bits)
    pub id: u16,

    /// Padding to allow for time
    pub pad: u32,

    /// Time that task was dumped
    pub time: u64,
}

impl DumpTask {
    pub fn new(id: u16, time: u64) -> Self {
        DumpTask { magic: DUMP_TASK_MAGIC, id, pad: 0, time }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DumpError<T> {
    BufferTooSmall,
    BufferTooSmallForCompression,
    BufferSizeMisaligned,
    InvalidDumperVersion,
    BadMagic(u32),
    BadDumpHeader(u32),
    DumpAlreadyExists,
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
    InvalidIndex,
    BadAgentWrite(u32, T),
    IncorrectlyClaimedArea(u32),
    InvalidAgent,
    OutOfSpaceForSegments,
    BadSegmentWrite(u32, T),
    OutOfTaskSpace,
    BadTaskWrite(u32, T),
    UnalignedSegmentAddress(u32),
    IncorrectlyClaimedTaskDump,
    IncorrectlyClaimedSystemDump,
}

//
// This is sized to allow for reasonably small buffers for [`dump`] -- down
// to 128 bytes or so.
//
pub type DumpLzss = lzss::Lzss<6, 4, 0x20, { 1 << 6 }, { 2 << 6 }>;

#[allow(clippy::result_unit_err)]
pub unsafe fn from_mem(addr: u32, buf: &mut [u8]) -> Result<(), ()> {
    let src = core::slice::from_raw_parts(addr as *const u8, buf.len());
    buf.copy_from_slice(src);
    Ok(())
}

#[allow(clippy::result_unit_err)]
pub unsafe fn to_mem(addr: u32, buf: &[u8]) -> Result<(), ()> {
    let dest = core::slice::from_raw_parts_mut(addr as *mut u8, buf.len());
    dest.copy_from_slice(buf);
    Ok(())
}

///
/// Initialize the dump areas based on the specified list.
///
pub fn initialize_dump_areas(
    areas: &[DumpArea],
    chunksize: Option<usize>,
) -> Option<u32> {
    let mut next = 0;

    for area in areas.iter().rev() {
        let chunksize = match chunksize {
            Some(chunksize) => chunksize,
            None => area.length as usize,
        };

        let length = area.length.min(chunksize as u32);

        for offset in (0..area.length).step_by(chunksize).rev() {
            let address = area.address + offset;

            unsafe {
                let header = address as *mut DumpAreaHeader;

                //
                // We initialize our dump headers with deliberately bad magic
                // to prevent any dumps until we have everything initialized
                //
                (*header) = DumpAreaHeader {
                    magic: DUMP_UNINITIALIZED,
                    address,
                    nsegments: 0,
                    written: core::mem::size_of::<DumpAreaHeader>() as u32,
                    length,
                    contents: area.contents.into(),
                    dumper: DUMPER_NONE,
                    next,
                }
            }

            next = address;
        }
    }

    if !areas.is_empty() {
        let mut address = areas[0].address;

        while address != 0 {
            unsafe {
                let header = address as *mut DumpAreaHeader;
                (*header).magic = DUMP_MAGIC;
                address = (*header).next;
            }
        }

        Some(areas[0].address)
    } else {
        None
    }
}

///
/// This should only be called in the context of the dump agent proxy.  Note
/// that this is searching a linked list, so it's O(N); if used to retrieve
/// every area, it will be quadratic (though N itself is generally smallish --
/// e.g., ~50).
///
pub fn get_dump_area<T>(
    base: u32,
    index: u8,
    mut read: impl FnMut(u32, &mut [u8], bool) -> Result<(), T>,
) -> Result<DumpArea, DumpError<T>> {
    let mut address = base;
    let mut i = 0;

    loop {
        let header = DumpAreaHeader::read_and_check(address, &mut read)?;

        if index == i {
            return Ok(DumpArea {
                address,
                length: header.length,
                contents: DumpContents::from(header.contents),
            });
        }

        if header.next == 0 {
            return Err(DumpError::InvalidIndex);
        }

        address = header.next;
        i += 1;
    }
}

///
/// Called by the dump agent proxy to claim a dump area on behalf of a
/// specified agent.  This will look for an area that does not have its
/// contents set to DUMP_CONTENTS_AVAILABLE.  If `claimall` is set, all areas
/// will be claimed (or none).  Areas are always claimed from the first area
/// on.
///
pub fn claim_dump_area<T>(
    base: u32,
    contents: DumpContents,
    mut read: impl FnMut(u32, &mut [u8], bool) -> Result<(), T>,
    mut write: impl FnMut(u32, &[u8]) -> Result<(), T>,
) -> Result<Option<DumpArea>, DumpError<T>> {
    let mut address = base;
    let mut rval = None;

    let claimall = match contents {
        DumpContents::SingleTask => false,
        DumpContents::WholeSystem => true,
        _ => {
            return Err(DumpError::InvalidAgent);
        }
    };

    let contents: u8 = contents.into();

    loop {
        let mut header = DumpAreaHeader::read_and_check(address, &mut read)?;

        if header.contents == DUMP_CONTENTS_AVAILABLE {
            //
            // We have a winner!  Set the contents, and write it back.
            //
            header.contents = contents;

            if let Err(e) = write(address, header.as_bytes()) {
                return Err(DumpError::BadAgentWrite(address, e));
            }

            //
            // If we want to claim all areas, keep going -- but keep track
            // of this first area as it will be the one we return.
            //
            if !claimall || address == base {
                rval = Some(DumpArea {
                    address,
                    length: header.length,
                    contents: header.contents.into(),
                })
            }

            if !claimall {
                break;
            }
        } else if claimall {
            if address == base {
                break;
            } else {
                //
                // This should be impossible:  in means that there was
                // an unclaimed area followed by a claimed one.
                //
                return Err(DumpError::IncorrectlyClaimedArea(address));
            }
        }

        if header.next == 0 {
            break;
        }

        address = header.next;
    }

    Ok(rval)
}

///
/// Add a segment header starting at `addr` bytes and running for `length`
/// bytes to the dump area indicated by `base`.  The caller must have claimed
/// the dump area.
///
pub fn add_dump_segment_header<T>(
    base: u32,
    addr: u32,
    length: u32,
    mut read: impl FnMut(u32, &mut [u8], bool) -> Result<(), T>,
    mut write: impl FnMut(u32, &[u8]) -> Result<(), T>,
) -> Result<(), DumpError<T>> {
    let mut header = DumpAreaHeader::read_and_check(base, &mut read)?;
    let nsegments = header.nsegments;

    let offset = core::mem::size_of::<DumpAreaHeader>()
        + (nsegments as usize) * core::mem::size_of::<DumpSegmentHeader>();
    let need = (offset + core::mem::size_of::<DumpSegmentHeader>()) as u32;

    if need > header.length {
        return Err(DumpError::OutOfSpaceForSegments);
    }

    let saddr = base + offset as u32;

    //
    // We enforce that addresses are at least word aligned to be able to
    // use the lower bits to denote a special segment.
    //
    if addr & DUMP_SEGMENT_MASK as u32 != 0 {
        return Err(DumpError::UnalignedSegmentAddress(addr));
    }

    let segment = DumpSegmentHeader { address: addr, length };

    header.nsegments = nsegments + 1;
    header.written = need;

    if let Err(e) = write(saddr, segment.as_bytes()) {
        return Err(DumpError::BadSegmentWrite(saddr, e));
    }

    if let Err(e) = write(base, header.as_bytes()) {
        return Err(DumpError::BadHeaderWrite(base, e));
    }

    Ok(())
}

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
    task: Option<DumpTask>,
    mut register_read: impl FnMut() -> Result<Option<RegisterRead>, T>,
    mut read: impl FnMut(u32, &mut [u8], bool) -> Result<(), T>,
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
    //   const_assert!(V != DUMPER_NONE);
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

    if V == DUMPER_NONE {
        return Err(DumpError::InvalidDumperVersion);
    }

    let mut buf = [0u8; N];
    let mut header = DumpAreaHeader::read_and_check(base, &mut read)?;

    if header.dumper != DUMPER_NONE {
        return Err(DumpError::DumpAlreadyExists);
    }

    let contents = header.contents;

    //
    // If we are dumping a task, create that metadata now.
    //
    if let Some(ref task) = task {
        let size = size_of::<DumpTask>() as u32;

        if contents != DUMP_CONTENTS_SINGLETASK {
            return Err(DumpError::IncorrectlyClaimedTaskDump);
        }

        if header.written + size >= header.length {
            return Err(DumpError::OutOfTaskSpace);
        }

        let taddr = header.address + header.written;

        if let Err(e) = write(taddr, task.as_bytes()) {
            return Err(DumpError::BadTaskWrite(taddr, e));
        }

        header.written += size;
    } else if contents == DUMP_CONTENTS_SINGLETASK {
        return Err(DumpError::IncorrectlyClaimedSystemDump);
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

        if let Err(e) = read(saddr, &mut buf[..seg_header_size], true) {
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

            if let Err(e) = read(addr, &mut buf[offs..len], false) {
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
                header.dumper = V;
                header.contents = contents;

                if let Err(e) = write(haddr, header.as_bytes()) {
                    return Err(DumpError::BadHeaderWrite(haddr, e));
                }

                haddr = next;

                if haddr == 0 {
                    return Err(DumpError::OutOfSpace(addr));
                }

                header = DumpAreaHeader::read_and_check(haddr, &mut read)?;

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
    header.dumper = V;
    header.contents = contents;

    if let Err(e) = write(haddr, header.as_bytes()) {
        return Err(DumpError::BadFinalHeaderWrite(haddr, e));
    }

    Ok(())
}
