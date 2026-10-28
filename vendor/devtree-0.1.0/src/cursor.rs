// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Primitive byte-level readers.
//!
//! These return [`Option`] (for `read_u32`/`read_u64`) or [`CstrError`]
//! (for `read_cstr`). The caller maps to the appropriate stage error
//! at the call site — `MalformedKind::Truncated` when parsing the
//! header, `MalformedKind::BadString { offset }` when walking the
//! structure block.

/// Read a big-endian u32 at `offset` in `blob`.
#[inline]
pub(crate) fn read_u32(blob: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = blob.get(offset..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

/// Read a big-endian u64 at `offset` in `blob`.
#[inline]
pub(crate) fn read_u64(blob: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let bytes: [u8; 8] = blob.get(offset..end)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// Failure modes of [`read_cstr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CstrError {
    /// `offset` was past the end of `blob`.
    OutOfBounds,
    /// String was not NUL-terminated within `blob`, or was not valid UTF-8.
    BadString,
}

/// Read a NUL-terminated UTF-8 string starting at `offset`. The returned
/// slice does not include the NUL terminator.
#[inline]
pub(crate) fn read_cstr(blob: &[u8], offset: usize) -> Result<&str, CstrError> {
    let bytes = read_cstr_bytes(blob, offset)?;
    core::str::from_utf8(bytes).map_err(|_| CstrError::BadString)
}

/// Read a NUL-terminated byte string starting at `offset`. The returned
/// slice does not include the NUL terminator and is **not** UTF-8
/// validated. Use this on hot paths where the caller will compare
/// against a known-good needle (and validate only on a hit) or where
/// the bytes were already UTF-8 validated at parse time.
#[inline]
pub(crate) fn read_cstr_bytes(blob: &[u8], offset: usize) -> Result<&[u8], CstrError> {
    let tail = blob.get(offset..).ok_or(CstrError::OutOfBounds)?;
    let end = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or(CstrError::BadString)?;
    tail.get(..end).ok_or(CstrError::BadString)
}

/// Round `n` up to the next multiple of 4. Saturates on overflow.
#[inline]
pub(crate) const fn align_up_4(n: usize) -> usize {
    n.saturating_add(3) & !3
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn read_u32_basic() {
        let blob = [0x00, 0x00, 0x00, 0x2a, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(read_u32(&blob, 0), Some(42));
        assert_eq!(read_u32(&blob, 4), Some(0xdead_beef));
    }

    #[test]
    fn read_u32_oob() {
        let blob = [0x00, 0x01, 0x02];
        assert_eq!(read_u32(&blob, 0), None);
        assert_eq!(read_u32(&[0; 4], 1), None);
    }

    #[test]
    fn read_u32_overflow() {
        assert_eq!(read_u32(&[0; 4], usize::MAX - 1), None);
    }

    #[test]
    fn read_u64_basic() {
        let blob = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        assert_eq!(read_u64(&blob, 0), Some(0x1234_5678_9abc_def0));
    }

    #[test]
    fn read_cstr_basic() {
        let blob = b"hello\0world\0";
        assert_eq!(read_cstr(blob, 0), Ok("hello"));
        assert_eq!(read_cstr(blob, 6), Ok("world"));
    }

    #[test]
    fn read_cstr_unterminated() {
        let blob = b"hello";
        assert_eq!(read_cstr(blob, 0), Err(CstrError::BadString));
    }

    #[test]
    fn read_cstr_invalid_utf8() {
        let blob = [0xff, 0xfe, 0x00];
        assert_eq!(read_cstr(&blob, 0), Err(CstrError::BadString));
    }

    #[test]
    fn read_cstr_oob() {
        assert_eq!(read_cstr(b"abc", 99), Err(CstrError::OutOfBounds));
    }

    #[test]
    fn align_up_4_works() {
        assert_eq!(align_up_4(0), 0);
        assert_eq!(align_up_4(1), 4);
        assert_eq!(align_up_4(3), 4);
        assert_eq!(align_up_4(4), 4);
        assert_eq!(align_up_4(5), 8);
    }
}
