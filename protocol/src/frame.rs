//! Length-prefixed framing: a big-endian `u32` byte count, then one JSON
//! [`Envelope`].

use std::fmt;
use std::io::{self, Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::message::{Envelope, PROTOCOL_VERSION};

/// Largest frame body either side accepts. A protocol constant, not a tunable:
/// both peers must agree on it for oversized input to be rejected identically.
///
/// Eight mebibytes because one dispatch carries a model's whole
/// conversation: a completion request is a single payload. The kernel sets
/// no other bound on a payload.
pub const MAX_FRAME_BYTES: usize = 8 << 20;

/// Why a frame could not be read or written.
#[derive(Debug)]
pub enum FrameError {
    /// The stream ended cleanly.
    Closed,
    /// The declared or encoded size exceeds [`MAX_FRAME_BYTES`]. The stream is
    /// no longer in sync and must be dropped.
    TooLarge(usize),
    /// The body was not a valid message.
    Malformed(String),
    /// The envelope carried a version this build does not speak.
    UnsupportedVersion(u32),
    Io(io::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("channel closed"),
            Self::TooLarge(n) => write!(f, "frame of {n} bytes exceeds {MAX_FRAME_BYTES}"),
            Self::Malformed(e) => write!(f, "malformed frame: {e}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version {v}"),
            Self::Io(e) => write!(f, "channel i/o: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Writes one frame and flushes.
pub fn write_frame<W: Write, M: Serialize>(writer: &mut W, msg: &M) -> Result<(), FrameError> {
    let body = serde_json::to_vec(&Envelope { v: PROTOCOL_VERSION, msg })
        .map_err(|e| FrameError::Malformed(e.to_string()))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(body.len()));
    }
    // The bound above guarantees the length fits.
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge(body.len()))?;
    writer.write_all(&len.to_be_bytes()).map_err(FrameError::Io)?;
    writer.write_all(&body).map_err(FrameError::Io)?;
    writer.flush().map_err(FrameError::Io)
}

/// Reads one frame. EOF before the prefix returns [`FrameError::Closed`];
/// a partial prefix returns [`FrameError::Io`].
///
/// The declared size is checked before buffering the body, returning
/// [`FrameError::TooLarge`] for an oversized declaration. For an accepted size,
/// a truncated body returns [`FrameError::Io`].
pub fn read_frame<R: Read, M: DeserializeOwned>(reader: &mut R) -> Result<M, FrameError> {
    let mut prefix = Vec::with_capacity(4);
    reader.by_ref().take(4).read_to_end(&mut prefix).map_err(FrameError::Io)?;
    let prefix: [u8; 4] = match prefix[..] {
        [] => return Err(FrameError::Closed),
        [a, b, c, d] => [a, b, c, d],
        _ => return Err(FrameError::Io(io::ErrorKind::UnexpectedEof.into())),
    };
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).map_err(FrameError::Io)?;

    #[derive(serde::Deserialize)]
    struct Version {
        v: u32,
    }
    let version: Version = serde_json::from_slice(&body).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if version.v != PROTOCOL_VERSION {
        return Err(FrameError::UnsupportedVersion(version.v));
    }
    let envelope: Envelope<M> =
        serde_json::from_slice(&body).map_err(|e| FrameError::Malformed(e.to_string()))?;
    Ok(envelope.msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::RequestId;
    use crate::message::ToKernel;

    #[test]
    fn round_trip_and_clean_close() -> Result<(), FrameError> {
        let mut wire = Vec::new();
        write_frame(&mut wire, &ToKernel::Cancel { request: RequestId(1) })?;
        let mut cursor = io::Cursor::new(wire);
        let msg: ToKernel = read_frame(&mut cursor)?;
        assert_eq!(msg, ToKernel::Cancel { request: RequestId(1) });
        assert!(matches!(read_frame::<_, ToKernel>(&mut cursor), Err(FrameError::Closed)));
        Ok(())
    }

    #[test]
    fn eof_is_clean_only_before_the_prefix_starts() {
        for bytes_read in 0..4 {
            let input = vec![0; bytes_read];
            let got = read_frame::<_, ToKernel>(&mut io::Cursor::new(input));
            if bytes_read == 0 {
                assert!(matches!(got, Err(FrameError::Closed)));
            } else {
                assert!(matches!(
                    got,
                    Err(FrameError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
                ));
            }
        }
    }

    #[test]
    fn oversized_length_is_rejected_before_reading_the_body() {
        let mut wire = u32::try_from(MAX_FRAME_BYTES + 1).unwrap_or(u32::MAX).to_be_bytes().to_vec();
        wire.extend_from_slice(b"{}");
        let got = read_frame::<_, ToKernel>(&mut io::Cursor::new(wire));
        assert!(matches!(got, Err(FrameError::TooLarge(_))));
    }

    #[test]
    fn older_and_future_versions_are_rejected_not_reinterpreted() {
        for version in [1, PROTOCOL_VERSION - 1, PROTOCOL_VERSION + 1] {
            let body = format!(r#"{{"v":{version},"msg":{{"cancel":{{"request":1}}}}}}"#);
            let mut wire = u32::try_from(body.len()).unwrap_or(0).to_be_bytes().to_vec();
            wire.extend_from_slice(body.as_bytes());
            let got = read_frame::<_, ToKernel>(&mut io::Cursor::new(wire));
            assert!(matches!(got, Err(FrameError::UnsupportedVersion(v)) if v == version));
        }
    }

    #[test]
    fn truncated_body_is_an_io_error_not_a_message() {
        let mut wire = 100u32.to_be_bytes().to_vec();
        wire.extend_from_slice(b"{\"v\":1");
        assert!(matches!(read_frame::<_, ToKernel>(&mut io::Cursor::new(wire)), Err(FrameError::Io(_))));
    }
}
