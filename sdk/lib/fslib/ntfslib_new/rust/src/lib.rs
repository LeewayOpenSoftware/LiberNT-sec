#![no_std]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

//! Leeway experimental (C1): bounded no_std Rust NTFS reparse-data validator.
//!
//! A faithful port of the corrected C validator in ntfslib_new
//! (src/filerecord/read/reparse.cpp): NtfsValidateReparseBuffer, IsNameRangeValid
//! and NtfsParseNameSurrogateReparsePoint. It is pure logic over a borrowed,
//! caller-owned buffer: no allocation, no locks, no panic paths, and checked
//! arithmetic on every offset and length. The NT structures keep their on-disk
//! layout. This does NOT replace the production path; the C validator stays the
//! primary remediation. Off by default; built for the differential harness and,
//! on the custom kernel target, for the reproducible-build gate.

use core::mem::size_of;

// ---- NTSTATUS (LONG) ----
pub type NtStatus = i32;

const STATUS_SUCCESS: NtStatus = 0x0000_0000u32 as i32;
const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000Du32 as i32;
const STATUS_IO_REPARSE_DATA_INVALID: NtStatus = 0xC000_0278u32 as i32;
const STATUS_IO_REPARSE_TAG_NOT_HANDLED: NtStatus = 0xC000_0279u32 as i32;

// ---- reparse constants (match include/public/ntfslib_new.h) ----
const NTFS_MAXIMUM_REPARSE_DATA_BUFFER_SIZE: u32 = 16 * 1024;
const NTFS_IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
const NTFS_IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
const NTFS_SYMLINK_FLAG_RELATIVE: u32 = 0x0000_0001;

const COMMON_HEADER_SIZE: u32 = 8; // sizeof(ReparsePointEx)
const GUID_HEADER_SIZE: u32 = 24; // sizeof(ThirdPartyReparsePointEx)
const SYMLINK_HEADER_SIZE: u32 = 12; // NTFS_SYMLINK_REPARSE_HEADER
const MOUNT_HEADER_SIZE: u32 = 8; // NTFS_MOUNT_POINT_REPARSE_HEADER

// ---- NT structures (layout unchanged; mirror ntfsattribdef.h / ntfslib_new.h) ----

/// $REPARSE_POINT (0xC0) common header. Layout identical to C `ReparsePointEx`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReparsePointEx {
    pub ReparseType: u32,
    pub ReparseDataLength: u16,
    pub Padding: u16,
}
const _: () = assert!(size_of::<ReparsePointEx>() == 8);

/// Validated view over a Microsoft symlink or mount-point reparse buffer.
/// Layout identical to C `NtfsReparseNameView` (asserted in the differential
/// harness with offsetof). Name pointers alias the caller-owned raw buffer.
#[repr(C)]
pub struct NtfsReparseNameView {
    pub ReparseTag: u32,
    pub Flags: u32,
    pub SubstituteName: *const u8,
    pub SubstituteNameLength: u32,
    pub PrintName: *const u8,
    pub PrintNameLength: u32,
}

// ---- bounded little-endian reads (never panic, never read out of bounds) ----

#[inline]
fn rd_u16(buf: &[u8], off: u32) -> Option<u16> {
    let o = off as usize;
    let end = o.checked_add(2)?;
    let b = buf.get(o..end)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

#[inline]
fn rd_u32(buf: &[u8], off: u32) -> Option<u32> {
    let o = off as usize;
    let end = o.checked_add(4)?;
    let b = buf.get(o..end)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

// ---- core validator (mirrors NtfsValidateReparseBuffer) ----

fn validate_reparse_buffer(buf: &[u8]) -> (NtStatus, Option<ReparsePointEx>) {
    let len = buf.len() as u32;
    if len < COMMON_HEADER_SIZE || len > NTFS_MAXIMUM_REPARSE_DATA_BUFFER_SIZE {
        return (STATUS_IO_REPARSE_DATA_INVALID, None);
    }

    let reparse_type = match rd_u32(buf, 0) {
        Some(v) => v,
        None => return (STATUS_IO_REPARSE_DATA_INVALID, None),
    };
    let reparse_data_length = match rd_u16(buf, 4) {
        Some(v) => v as u32,
        None => return (STATUS_IO_REPARSE_DATA_INVALID, None),
    };
    let padding = rd_u16(buf, 6).unwrap_or(0);

    if reparse_type <= 1 || (reparse_type & !0xF000_FFFFu32) != 0 {
        return (STATUS_IO_REPARSE_DATA_INVALID, None);
    }

    // Third-party tags (bit 31 clear) carry a GUID after the common header.
    let header_size = if (reparse_type & 0x8000_0000) != 0 {
        COMMON_HEADER_SIZE
    } else {
        GUID_HEADER_SIZE
    };
    if len < header_size || reparse_data_length > NTFS_MAXIMUM_REPARSE_DATA_BUFFER_SIZE - header_size
    {
        return (STATUS_IO_REPARSE_DATA_INVALID, None);
    }

    let expected = header_size + reparse_data_length; // both <= 16384, sum fits u32
    if expected != len {
        return (STATUS_IO_REPARSE_DATA_INVALID, None);
    }

    if (reparse_type & 0x8000_0000) == 0 {
        // Third-party: the GUID (16 bytes at offset 8) must be non-zero.
        let guid = match buf.get(COMMON_HEADER_SIZE as usize..GUID_HEADER_SIZE as usize) {
            Some(g) => g,
            None => return (STATUS_IO_REPARSE_DATA_INVALID, None),
        };
        if guid.iter().all(|&b| b == 0) {
            return (STATUS_IO_REPARSE_DATA_INVALID, None);
        }
    }

    (
        STATUS_SUCCESS,
        Some(ReparsePointEx {
            ReparseType: reparse_type,
            ReparseDataLength: reparse_data_length as u16,
            Padding: padding,
        }),
    )
}

// ---- name-range validation (mirrors IsNameRangeValid) ----

fn is_name_range_valid(path: &[u8], name_offset: u16, name_length: u16) -> bool {
    let path_len = path.len() as u32;
    let noff = name_offset as u32;
    let nlen = name_length as u32;

    if (noff & 1) != 0 || (nlen & 1) != 0 || noff > path_len {
        return false;
    }
    // path_len - noff cannot underflow: noff <= path_len checked above.
    if nlen > path_len - noff {
        return false;
    }

    let char_count = nlen / 2;
    let mut index: u32 = 0;
    while index < char_count {
        let ch = match rd_u16(path, noff + index * 2) {
            Some(v) => v,
            None => return false,
        };
        if ch == 0 {
            return false;
        }
        if (0xD800..=0xDBFF).contains(&ch) {
            // high surrogate: a valid low surrogate must follow
            index += 1;
            if index >= char_count {
                return false;
            }
            let low = match rd_u16(path, noff + index * 2) {
                Some(v) => v,
                None => return false,
            };
            if !(0xDC00..=0xDFFF).contains(&low) {
                return false;
            }
        } else if (0xDC00..=0xDFFF).contains(&ch) {
            // lone low surrogate
            return false;
        }
        index += 1;
    }
    true
}

struct ParsedView {
    tag: u32,
    flags: u32,
    path_start: u32,
    sub_off: u16,
    sub_chars: u32,
    print_off: u16,
    print_chars: u32,
}

// ---- name-surrogate parser (mirrors NtfsParseNameSurrogateReparsePoint) ----

fn parse_name_surrogate(buf: &[u8]) -> (NtStatus, Option<ParsedView>) {
    let (st, common) = validate_reparse_buffer(buf);
    if st != STATUS_SUCCESS {
        return (st, None);
    }
    let common = match common {
        Some(c) => c,
        None => return (STATUS_IO_REPARSE_DATA_INVALID, None),
    };
    let rdl = common.ReparseDataLength as u32;

    let sub_off;
    let sub_len;
    let print_off;
    let print_len;
    let flags;
    let path_start;
    let path_len;

    if common.ReparseType == NTFS_IO_REPARSE_TAG_SYMLINK {
        if rdl < SYMLINK_HEADER_SIZE {
            return (STATUS_IO_REPARSE_DATA_INVALID, None);
        }
        sub_off = read_or(buf, 8);
        sub_len = read_or(buf, 10);
        print_off = read_or(buf, 12);
        print_len = read_or(buf, 14);
        flags = match rd_u32(buf, 16) {
            Some(v) => v,
            None => return (STATUS_IO_REPARSE_DATA_INVALID, None),
        };
        if (flags & !NTFS_SYMLINK_FLAG_RELATIVE) != 0 {
            return (STATUS_IO_REPARSE_DATA_INVALID, None);
        }
        path_start = COMMON_HEADER_SIZE + SYMLINK_HEADER_SIZE; // 20
        path_len = rdl - SYMLINK_HEADER_SIZE;
    } else if common.ReparseType == NTFS_IO_REPARSE_TAG_MOUNT_POINT {
        if rdl < MOUNT_HEADER_SIZE {
            return (STATUS_IO_REPARSE_DATA_INVALID, None);
        }
        sub_off = read_or(buf, 8);
        sub_len = read_or(buf, 10);
        print_off = read_or(buf, 12);
        print_len = read_or(buf, 14);
        flags = 0;
        path_start = COMMON_HEADER_SIZE + MOUNT_HEADER_SIZE; // 16
        path_len = rdl - MOUNT_HEADER_SIZE;
    } else {
        return (STATUS_IO_REPARSE_TAG_NOT_HANDLED, None);
    }

    let path = match buf.get(path_start as usize..(path_start + path_len) as usize) {
        Some(p) => p,
        None => return (STATUS_IO_REPARSE_DATA_INVALID, None),
    };

    if sub_len == 0
        || !is_name_range_valid(path, sub_off, sub_len)
        || !is_name_range_valid(path, print_off, print_len)
    {
        return (STATUS_IO_REPARSE_DATA_INVALID, None);
    }

    (
        STATUS_SUCCESS,
        Some(ParsedView {
            tag: common.ReparseType,
            flags,
            path_start,
            sub_off,
            sub_chars: (sub_len as u32) / 2,
            print_off,
            print_chars: (print_len as u32) / 2,
        }),
    )
}

// Read a u16 header field whose presence is already guaranteed by the data-length
// check above; a short buffer yields 0 (then rejected downstream), never a panic.
#[inline]
fn read_or(buf: &[u8], off: u32) -> u16 {
    rd_u16(buf, off).unwrap_or(0)
}

// ---- C ABI ----

/// Validate the common reparse header. Mirrors `NtfsValidateReparseBuffer`.
/// `out_common` may be null. Returns NTSTATUS. Never allocates, never panics.
///
/// # Safety
/// `buffer` must be readable for `buffer_length` bytes (or null), and
/// `out_common` null or a writable `ReparsePointEx`.
#[no_mangle]
pub unsafe extern "C" fn leeway_rs_ntfs_validate_reparse_buffer(
    buffer: *const u8,
    buffer_length: u32,
    out_common: *mut ReparsePointEx,
) -> NtStatus {
    if buffer.is_null() || buffer_length as usize > isize::MAX as usize {
        return STATUS_IO_REPARSE_DATA_INVALID;
    }
    let buf = core::slice::from_raw_parts(buffer, buffer_length as usize);
    let (st, common) = validate_reparse_buffer(buf);
    if st == STATUS_SUCCESS {
        if let (false, Some(c)) = (out_common.is_null(), common) {
            core::ptr::write(out_common, c);
        }
    }
    st
}

/// Validate and project a symlink or mount-point reparse buffer into `view`.
/// Mirrors `NtfsParseNameSurrogateReparsePoint`. Returns NTSTATUS. On any
/// non-success the view is left zeroed. Never allocates, never panics.
///
/// # Safety
/// `buffer` must be readable for `buffer_length` bytes (or null), and `view`
/// a writable `NtfsReparseNameView`.
#[no_mangle]
pub unsafe extern "C" fn leeway_rs_ntfs_parse_name_surrogate_reparse_point(
    buffer: *const u8,
    buffer_length: u32,
    view: *mut NtfsReparseNameView,
) -> NtStatus {
    if view.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    core::ptr::write_bytes(view as *mut u8, 0, size_of::<NtfsReparseNameView>());

    if buffer.is_null() || buffer_length as usize > isize::MAX as usize {
        return STATUS_IO_REPARSE_DATA_INVALID;
    }
    let buf = core::slice::from_raw_parts(buffer, buffer_length as usize);

    let (st, parsed) = parse_name_surrogate(buf);
    if st == STATUS_SUCCESS {
        if let Some(v) = parsed {
            let path_base = buffer.add(v.path_start as usize);
            (*view).ReparseTag = v.tag;
            (*view).Flags = v.flags;
            (*view).SubstituteName = path_base.add(v.sub_off as usize);
            (*view).SubstituteNameLength = v.sub_chars;
            (*view).PrintName = path_base.add(v.print_off as usize);
            (*view).PrintNameLength = v.print_chars;
        }
    }
    st
}

// ---- no_std panic handler ----
// Unreachable in practice: the validator has no panic paths (checked arithmetic,
// bounds-guarded reads). panic=abort means no unwinding, so this never needs an
// eh personality, on either the custom kernel target or the host diff target.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
