// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Network messages for remote task dumping
//!
//! Messages from the host are serialized as a tuple `(Header, Request)`;
//! replies from the device are `(Header, Response)`, along with trailing data
//! in the packet for the actual dump (if relevant).

use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};

pub mod version {
    pub const V1: u8 = 1;
    pub const V2: u8 = 2;
    pub const V3: u8 = 3;

    /// The current version of the messaging protocol.
    pub const CURRENT: u8 = V3;

    /// The minimum supported version that is compatible with the current.
    ///
    /// "Compatible" means that all messages from this version may be serialized
    /// and deserialized correctly. That means that all message data in `MIN`
    /// correspond to the same values in `CURRENT` -- colloquially, `CURRENT` is
    /// a superset of `MIN`.
    ///
    /// Because this crate uses `hubpack` for serialization, this also means
    /// that no variants of the message enums have been removed or reordered. So
    /// `CURRENT` may contain _new_ items, but existing ones cannot be moved or
    /// removed.
    ///
    /// This version of the protocol is _committed_. Any changes to the types
    /// here, or [`Error`], _must_ be compatible with this version. They can
    /// add new enum variants, but _must not_ change or reorder any of the
    /// existing variants. Peers should, on a best-effort basis, decode and
    /// handle any messages that are at least this version. If the message comes
    /// from a version prior to their `CURRENT`, they _must_ be able to decode
    /// it, assuming we've not broken compatibility. If the message comes from a
    /// version _after_ `CURRENT`, they _may_ be able to decode it. If they
    /// cannot, presumably because the message was added in a later version,
    /// then they _must_ still send back a protocol error of some kind, such as
    /// `Error::VersionMismatch`. Those are guaranteed to be compatible and
    /// decodable by the peer.
    pub const MIN: u8 = V1;
}

pub const DUMP_READ_SIZE: usize = 256;
pub const IMAGE_ID_SIZE: usize = 8;

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
    /// Fetch the `DUMP_READ_SIZE` bytes from the dump at the specified offset
    /// from the specified area.
    ReadDump { index: u8, offset: u32 },

    /// Initialize dump context, overwriting any taken dump
    InitializeDump,

    /// Adds a segment to a whole-system dump
    AddDumpSegment { address: u32, length: u32 },

    /// Take a whole-system dump
    TakeDump,

    /// Trigger a dump for a particular task
    DumpTask { task_index: u32 },

    /// Trigger a dump for a region within particular task
    DumpTaskRegion { task_index: u32, start: u32, length: u32 },

    /// Reinitializes dump context, starting at the given area
    ReinitializeDumpFrom { index: u8 },

    /// Return the image ID
    GetImageId,
}

/// Complete message sent from the host to the target device
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize,
)]
#[allow(clippy::large_enum_variant)]
pub struct RequestMessage {
    pub header: Header,
    pub request: Request,
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
    InitializeDump,
    AddDumpSegment,
    TakeDump,
    DumpTask(u8),
    DumpTaskRegion(u8),
    ReinitializeDumpFrom,
    GetImageId([u8; IMAGE_ID_SIZE]),
}

/// Complete reply sent from the host to the target device
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize,
)]
#[allow(clippy::large_enum_variant)]
pub struct ResponseMessage {
    pub header: Header,
    pub response: Result<Response, Error>,
}

/// Errors that can be reported by the dump agent
///
/// This is mostly identical to `DumpAgentError` in Hubris, but lives in a
/// separate crate so it can be versioned independently.  It also includes new
/// error types specific to networked messages.
#[derive(
    Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize,
)]
pub enum Error {
    // Error types specific to network traffic
    //
    // This are deliberately put at the beginning so that new Hubris errors can
    // be added to the end without changing the encoding order.
    DeserializeError,
    VersionMismatch { ours: u8, theirs: u8 },

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

#[cfg(test)]
mod encoding_tests {
    use super::{
        Error, Header, Request, RequestMessage, Response, ResponseMessage,
        DUMP_READ_SIZE, IMAGE_ID_SIZE,
    };
    use core::convert::TryFrom;
    use hubpack::SerializedSize;

    // Tests that the current version has not broken serialization.
    //
    // This uses the fact that `hubpack` assigns IDs to each variant of an enum
    // based on the order they appear.  These are used by
    // `hubpack::{serialize,deserialize}` to determine the enum variant encoded
    // in a binary message, which are based on the _ordering_ of the enum
    // variants. I.e, we're really testing if that ordering has changed in a
    // meaningful way.
    //
    // If it _has_, we have two options:
    //
    // - Bump `MIN` -> `CURRENT`
    // - Rework the changes to avoid that change.
    //
    // Each test below checks one of the enums in the protocol.

    // Test that the error variant encoding has not changed.
    #[test]
    fn test_error_encoding_unchanged() {
        let mut buf = [0u8; Error::MAX_SIZE];
        const TEST_DATA: [Error; 24] = [
            Error::DeserializeError,
            Error::VersionMismatch { ours: 0, theirs: 0 },
            Error::DumpAgentUnsupported,
            Error::InvalidArea,
            Error::BadOffset,
            Error::UnalignedOffset,
            Error::UnalignedSegmentAddress,
            Error::UnalignedSegmentLength,
            Error::DumpFailed,
            Error::NotSupported,
            Error::DumpPresent,
            Error::UnclaimedDumpArea,
            Error::CannotClaimDumpArea,
            Error::DumpAreaInUse,
            Error::BadSegmentAdd,
            Error::ServerRestarted,
            Error::BadDumpResponse,
            Error::DumpMessageFailed,
            Error::DumpFailedSetup,
            Error::DumpFailedRead,
            Error::DumpFailedWrite,
            Error::DumpFailedControl,
            Error::DumpFailedUnknown,
            Error::DumpFailedUnknownError,
        ];

        for (variant_id, variant) in TEST_DATA.iter().enumerate() {
            buf[0] = u8::try_from(variant_id).unwrap();
            let (decoded, _rest) =
                hubpack::deserialize::<Error>(buf.as_slice()).unwrap();
            assert_eq!(
                variant, &decoded,
                "Serialization encoding changed! Either `version::CURRENT` \
                or `version::MIN` will need to be updated, \
                or the changes to `crate::udp::Error` need to be reworked to \
                avoid reordering or removing variants."
            );
        }

        let r = Error::VersionMismatch { ours: 123, theirs: 251 };
        let size = hubpack::serialize(&mut buf, &r).unwrap();
        assert_eq!(buf[..size], [1, 123, 251]);
    }

    #[test]
    fn test_request_encoding_unchanged() {
        let mut buf = [0u8; Request::MAX_SIZE];
        const TEST_DATA: [Request; 8] = [
            Request::ReadDump { index: 0, offset: 0 },
            Request::InitializeDump,
            Request::AddDumpSegment { address: 0, length: 0 },
            Request::TakeDump,
            Request::DumpTask { task_index: 0 },
            Request::DumpTaskRegion { task_index: 0, start: 0, length: 0 },
            Request::ReinitializeDumpFrom { index: 0 },
            Request::GetImageId,
        ];

        for (variant_id, variant) in TEST_DATA.iter().enumerate() {
            buf[0] = u8::try_from(variant_id).unwrap();
            let (decoded, _rest) =
                hubpack::deserialize::<Request>(buf.as_slice()).unwrap();
            assert_eq!(
                variant, &decoded,
                "Serialization encoding changed! Either `version::CURRENT` \
                or `version::MIN` will need to be updated, \
                or the changes to `crate::udp::Request` need to be reworked to \
                avoid reordering or removing variants."
            );
        }

        let r = Request::ReadDump { index: 123, offset: 456 };
        let size = hubpack::serialize(&mut buf, &r).unwrap();
        assert_eq!(buf[..size], [0, 123, 200, 1, 0, 0]);

        let r = Request::AddDumpSegment { address: 123, length: 321 };
        let size = hubpack::serialize(&mut buf, &r).unwrap();
        assert_eq!(buf[..size], [2, 123, 0, 0, 0, 65, 1, 0, 0]);

        let r = Request::DumpTask { task_index: 101 };
        let size = hubpack::serialize(&mut buf, &r).unwrap();
        assert_eq!(buf[..size], [4, 101, 0, 0, 0]);

        let r =
            Request::DumpTaskRegion { task_index: 101, start: 123, length: 99 };
        let size = hubpack::serialize(&mut buf, &r).unwrap();
        assert_eq!(buf[..size], [5, 101, 0, 0, 0, 123, 0, 0, 0, 99, 0, 0, 0]);

        let r = Request::ReinitializeDumpFrom { index: 123 };
        let size = hubpack::serialize(&mut buf, &r).unwrap();
        assert_eq!(buf[..size], [6, 123]);
    }

    #[test]
    fn test_requestmessage_encoding_unchanged() {
        let mut buf = [0u8; RequestMessage::MAX_SIZE];
        let r = RequestMessage {
            header: Header { version: 1, message_id: 1234 },
            request: Request::TakeDump,
        };
        let size = hubpack::serialize(&mut buf, &r).unwrap();
        assert_eq!(buf[..size], [1, 210, 4, 0, 0, 0, 0, 0, 0, 3]);
    }

    #[test]
    fn test_responsemessage_encoding_unchanged() {
        let mut buf = [0u8; ResponseMessage::MAX_SIZE];

        let r = ResponseMessage {
            header: Header { version: 1, message_id: 1235 },
            response: Ok(Response::TakeDump),
        };
        let size = hubpack::serialize(&mut buf, &r).unwrap();
        assert_eq!(buf[..size], [1, 211, 4, 0, 0, 0, 0, 0, 0, 0, 3]);

        let r = ResponseMessage {
            header: Header { version: 1, message_id: 1235 },
            response: Err(Error::BadOffset),
        };
        let size = hubpack::serialize(&mut buf, &r).unwrap();
        assert_eq!(buf[..size], [1, 211, 4, 0, 0, 0, 0, 0, 0, 1, 4]);
    }

    #[test]
    fn test_response_encoding_unchanged() {
        let mut buf = [0u8; Response::MAX_SIZE];
        const TEST_DATA: [Response; 8] = [
            Response::ReadDump([0u8; DUMP_READ_SIZE]),
            Response::InitializeDump,
            Response::AddDumpSegment,
            Response::TakeDump,
            Response::DumpTask(0),
            Response::DumpTaskRegion(0),
            Response::ReinitializeDumpFrom,
            Response::GetImageId([0u8; IMAGE_ID_SIZE]),
        ];

        for (variant_id, variant) in TEST_DATA.iter().enumerate() {
            buf[0] = u8::try_from(variant_id).unwrap();
            let (decoded, _rest) =
                hubpack::deserialize::<Response>(buf.as_slice()).unwrap();
            assert_eq!(
                variant, &decoded,
                "Serialization encoding changed! Either `version::CURRENT` \
                or `version::MIN` will need to be updated, \
                or the changes to `crate::udp::Response` need to be reworked \
                to avoid reordering or removing variants."
            );
        }

        let mut array = [0u8; 256];
        array[0] = 123;
        array[5] = 127;
        array[1] = 1;
        let r = Response::ReadDump(array);
        let size = hubpack::serialize(&mut buf, &r).unwrap();
        assert_eq!(size, 257);
        assert_eq!(buf[1..], array);

        let r = Response::DumpTask(123);
        let size = hubpack::serialize(&mut buf, &r).unwrap();
        assert_eq!(buf[..size], [4, 123]);

        let r = Response::DumpTaskRegion(35);
        let size = hubpack::serialize(&mut buf, &r).unwrap();
        assert_eq!(buf[..size], [5, 35]);

        let id = [0x1, 0xde, 0x0b, 0xad, 0xf0, 0xd, 0xca, 0xfe];
        let r = Response::GetImageId(id);
        let size = hubpack::serialize(&mut buf, &r).unwrap();
        assert_eq!(buf[0], 7);
        assert_eq!(buf[1..size], id);
    }
}
