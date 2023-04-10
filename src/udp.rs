// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Network messages for remote task dumping
//!
//! Messages from the host are serialized as a tuple `(Header, Request)`;
//! replies from the device are `(Header, Response)`, along with trailing data
//! in the packet for the actual dump (if relevant).

use crate::DumpArea;
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};

pub const VERSION: u8 = 1;
pub const DUMP_READ_SIZE: usize = 256;

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize,
)]
pub struct Header {
    /// The protocol version.
    pub version: u8,

    /// An arbitrary message ID, shared between a request and its response.
    pub message_id: u64,
}

/// Messages sent from the host to the target device
///
/// These are a thin wrapper around the `dump-agent` API in Hubris, but live in
/// a separate crate so that they can be versioned independently.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize,
)]
pub enum Request {
    /// Fetch the 256 bytes from the dump at the specified offset from the
    /// specified area.
    ReadDump { index: u8, offset: u32 },

    /// Returns information associated with the specified dump area
    GetDumpArea { index: u8 },

    /// Initialize dump context, overwriting any taken dump
    InitializeDump,

    /// Add a segment to a dump
    AddDumpSegment { address: u32, length: u32 },

    /// Take dump
    TakeDump,
}

/// Responses from the target device to the host
///
/// Most of these are simple acknowledgements, but some include data (either in
/// the variant or trailing behind in the packet).
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize,
)]
#[allow(clippy::large_enum_variant)]
pub enum Response {
    #[serde(with = "serde_big_array::BigArray")]
    ReadDump([u8; DUMP_READ_SIZE]),
    GetDumpArea(DumpArea),
    InitializeDump,
    AddDumpSegment,
    TakeDump,
}

/// Errors that can be reported by the dump agent
///
/// This is mostly to `DumpAgentError` in Hubris, but lives in a separate
/// crate so it can be versioned independently.
#[derive(
    Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize,
)]
pub enum Error {
    // New error type specific to network traffic
    //
    // This is deliberately put at the beginning so that new Hubris errors can
    // be added without changing the encoding order.
    DeserializeError,

    // Error types from `DumpAgentError`
    DumpAgentUnsupported,
    InvalidArea,
    BadOffset,
    UnalignedOffset,
    UnalignedSegmentAddress,
    UnalignedSegmentLength,
    DumpFailed,
    NotSupported,
    DumpPresent,
    UnclaimedDumpArea,
    CannotClaimDumpArea,
    DumpAreaInUse,
    BadSegmentAdd,
    ServerRestarted,

    BadDumpResponse,
    DumpMessageFailed,
    DumpFailedSetup,
    DumpFailedRead,
    DumpFailedWrite,
    DumpFailedControl,
    DumpFailedUnknown,
    DumpFailedUnknownError,
}
