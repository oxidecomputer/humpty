// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]

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

pub const DUMP_AGENT_NONE: u8 = 0;
pub const DUMP_AGENT_JEFE: u8 = 1;
pub const DUMP_AGENT_TASK: u8 = 2;
pub const DUMP_AGENT_INVALID: u8 = 0xff;

#[derive(
    Copy, Clone, Debug, SerializedSize, Serialize, Deserialize, PartialEq,
)]
pub enum DumpAgent {
    None,
    Jefe,
    Task,
    Unknown,
}

impl From<u8> for DumpAgent {
    fn from(val: u8) -> Self {
        match val {
            DUMP_AGENT_NONE => DumpAgent::None,
            DUMP_AGENT_JEFE => DumpAgent::Jefe,
            DUMP_AGENT_TASK => DumpAgent::Task,
            _ => DumpAgent::Unknown,
        }
    }
}

impl From<DumpAgent> for u8 {
    fn from(val: DumpAgent) -> Self {
        match val {
            DumpAgent::None => DUMP_AGENT_NONE,
            DumpAgent::Jefe => DUMP_AGENT_JEFE,
            DumpAgent::Task => DUMP_AGENT_TASK,
            _ => DUMP_AGENT_INVALID,
        }
    }
}

#[derive(
    Copy, Clone, Debug, SerializedSize, Serialize, Deserialize, PartialEq,
)]
pub struct DumpArea {
    pub address: u32,
    pub length: u32,
    pub agent: DumpAgent,
}

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

    /// Dump agent (to be written by agent)
    pub agent: u8,

    /// Dumper (to be written by dumper)
    pub dumper: u8,

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
            match DumpRegister::read_from_prefix(dump) {
                Some(reg) => Some(DumpSegment::Register(reg)),
                None => None,
            }
        } else if dump[..2] == DUMP_TASK_MAGIC {
            match DumpTask::read_from_prefix(dump) {
                Some(task) => Some(DumpSegment::Task(task)),
                None => None,
            }
        } else if (dump[0] as usize) & DUMP_SEGMENT_MASK != 0 {
            Some(DumpSegment::Unknown([dump[0], dump[1]]))
        } else {
            match DumpSegmentData::read_from_prefix(dump) {
                Some(data) => Some(DumpSegment::Data(data)),
                None => None,
            }
        }
    }
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

#[derive(Copy, Clone, Debug, FromBytes, AsBytes)]
#[repr(C, packed)]
pub struct DumpTask {
    /// task magic -- must be DUMP_TASK_MAGIC
    pub magic: [u8; 2],

    /// ID of task that is dumped here (task IDs are maximum 15 bits)
    pub task: u16,

    /// Time that task was dumped
    pub time: u64,
}

impl DumpTask {
    pub fn new(task: u16, time: u64) -> Self {
        DumpTask { magic: DUMP_TASK_MAGIC, task, time }
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
}

//
// This is sized to allow for reasonably small buffers for [`dump`] -- down
// to 128 bytes or so.
//
pub type DumpLzss = lzss::Lzss<6, 4, 0x20, { 1 << 6 }, { 2 << 6 }>;

pub fn from_mem(addr: u32, buf: &mut [u8]) -> Result<(), ()> {
    let src =
        unsafe { core::slice::from_raw_parts(addr as *const u8, buf.len()) };

    buf.copy_from_slice(src);
    Ok(())
}

pub fn to_mem(addr: u32, buf: &[u8]) -> Result<(), ()> {
    let dest =
        unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, buf.len()) };

    // dest.copy_from_slice(buf); doesn't work here?!
    for i in 0..buf.len() {
        dest[i] = buf[i];
    }

    Ok(())
}

///
/// Initialize the dump areas based on the specified list.
///
pub fn initialize_dump_areas(areas: &[DumpArea]) -> Option<u32> {
    let mut next = 0;

    for area in areas.iter().rev() {
        unsafe {
            let header = area.address as *mut DumpAreaHeader;

            //
            // We initialize our dump header with deliberately bad magic
            // to prevent any dumps until we have everything initialized
            //
            (*header) = DumpAreaHeader {
                magic: DUMP_UNINITIALIZED,
                address: area.address,
                nsegments: 0,
                written: core::mem::size_of::<DumpAreaHeader>() as u32,
                length: area.length,
                agent: area.agent.into(),
                dumper: DUMPER_NONE,
                next,
            }
        }

        next = area.address;
    }

    for area in areas.iter() {
        unsafe {
            let header = area.address as *mut DumpAreaHeader;
            (*header).magic = DUMP_MAGIC;
        }
    }

    if areas.len() > 0 {
        Some(areas[0].address)
    } else {
        None
    }
}

///
/// This should only be called in the context of the dump agent proxy.
///
pub fn get_dump_area<T>(
    base: u32,
    index: u8,
    mut read: impl FnMut(u32, &mut [u8]) -> Result<(), T>,
) -> Result<DumpArea, DumpError<T>> {
    let mut address = base;
    let mut i = 0;
    const HEADER_SIZE: usize = core::mem::size_of::<DumpAreaHeader>();

    loop {
        let mut hbuf = [0u8; HEADER_SIZE];

        if let Err(e) = read(address, &mut hbuf[..]) {
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

        if index == i {
            return Ok(DumpArea {
                address: address,
                length: header.length,
                agent: DumpAgent::from(header.agent),
            });
        }

        if header.next == 0 {
            return Err(DumpError::InvalidIndex);
        }

        address = header.next;
        i += 1;
    }
}

//
// Called by the dump agent proxy to claim a dump area on behalf of a
// specified agent.  This will look for an area that does not have its agent
// set to DUMP_AGENT_NONE.  If `claimall` is set, all areas will be claimed
// (or none).  Areas are always claimed from the first area on.
//
pub fn claim_dump_area<T>(
    base: u32,
    agent: DumpAgent,
    claimall: bool,
    mut read: impl FnMut(u32, &mut [u8]) -> Result<(), T>,
    mut write: impl FnMut(u32, &[u8]) -> Result<(), T>,
) -> Result<Option<DumpArea>, DumpError<T>> {
    let mut address = base;
    let mut rval = None;
    let agent: u8 = agent.into();

    const HEADER_SIZE: usize = core::mem::size_of::<DumpAreaHeader>();

    if agent == DUMP_AGENT_NONE {
        return Err(DumpError::InvalidAgent);
    }

    loop {
        let mut hbuf = [0u8; HEADER_SIZE];

        if let Err(e) = read(address, &mut hbuf[..]) {
            return Err(DumpError::BadHeaderRead(address, e));
        }

        let mut header = match DumpAreaHeader::read_from(&hbuf[..]) {
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

        if header.agent == DUMP_AGENT_NONE {
            //
            // We have a winner!  Set the agent, and write it back.
            //
            header.agent = agent;

            if let Err(e) = write(address, header.as_bytes()) {
                return Err(DumpError::BadAgentWrite(address, e));
            }

            //
            // If we want to claim all areas, keep going -- but keep track
            // of this first area as it will be the one we return.
            //
            if !claimall || address == base {
                rval = Some(DumpArea {
                    address: address,
                    length: header.length,
                    agent: header.agent.into(),
                })
            }

            if !claimall {
                break;
            }
        } else {
            if claimall {
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
        }

        if header.next == 0 {
            break;
        }

        address = header.next;
    }

    Ok(rval)
}

///
/// Add a segment starting at `addr` bytes and running for `length` bytes
/// to the dump area indicated by `base`.  The caller must have claimed
/// the dump area.
///
pub fn add_dump_segment<T>(
    base: u32,
    addr: u32,
    length: u32,
    mut read: impl FnMut(u32, &mut [u8]) -> Result<(), T>,
    mut write: impl FnMut(u32, &[u8]) -> Result<(), T>,
) -> Result<(), DumpError<T>> {
    const HEADER_SIZE: usize = core::mem::size_of::<DumpAreaHeader>();
    const SEG_SIZE: usize = core::mem::size_of::<DumpSegmentHeader>();

    let mut hbuf = [0u8; HEADER_SIZE];
    let mut sbuf = [0u8; SEG_SIZE];

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

    let nsegments = header.nsegments;

    let offset = core::mem::size_of::<DumpAreaHeader>()
        + (nsegments as usize) * core::mem::size_of::<DumpSegmentHeader>();
    let need = (offset + core::mem::size_of::<DumpSegmentHeader>()) as u32;

    if need > header.length {
        return Err(DumpError::OutOfSpaceForSegments);
    }

    let saddr = base + offset as u32;

    if let Err(e) = read(saddr, &mut sbuf[..]) {
        return Err(DumpError::BadSegmentHeaderRead(saddr, e));
    }

    let mut segment = match DumpSegmentHeader::read_from(&sbuf[..]) {
        Some(segment) => segment,
        None => {
            return Err(DumpError::BadSegmentHeader(saddr));
        }
    };

    //
    // We enforce that addresses are at least 32-bit aligned to be able to
    // use the lower bits to denote a special segment.
    //
    if addr & DUMP_SEGMENT_MASK as u32 != 0 {
        return Err(DumpError::UnalignedSegmentAddress(addr));
    }

    segment.address = addr;
    segment.length = length;

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

    if header.dumper != DUMPER_NONE {
        return Err(DumpError::DumpAlreadyExists);
    }

    let agent = header.agent;

    //
    // If we are dumping a task, create that metadata now.
    //
    if let Some(ref task) = task {
        let size = size_of::<DumpTask>() as u32;

        if header.written + size >= header.length {
            return Err(DumpError::OutOfTaskSpace);
        }

        let taddr = header.address + header.written;

        if let Err(e) = write(taddr, task.as_bytes()) {
            return Err(DumpError::BadTaskWrite(taddr, e));
        }

        header.written += size;
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
                header.dumper = V;
                header.agent = agent;

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
    header.dumper = V;
    header.agent = agent;

    if let Err(e) = write(haddr, header.as_bytes()) {
        return Err(DumpError::BadFinalHeaderWrite(haddr, e));
    }

    Ok(())
}
