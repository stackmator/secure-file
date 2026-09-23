#![cfg(windows)]

use secure_file::{Error, SecureFile};
use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{LocalFree, GENERIC_READ};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AddAccessAllowedAce, AddAccessDeniedAce, GetLengthSid, InitializeAcl,
    InitializeSecurityDescriptor, SetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, ACL, ACL_REVISION,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

/// A SID that is not the current user, so it can stand in for "someone else".
const OTHER_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";

fn aligned(bytes: usize) -> Vec<u64> {
    vec![0u64; bytes.div_ceil(8)]
}

fn wide(path: &Path) -> Vec<u16> {
    let mut buf: Vec<u16> = path.as_os_str().encode_wide().collect();
    buf.push(0);
    buf
}

/// Parses a SID string into an owned, aligned buffer. The returned pointer
/// points into the returned buffer, which must be kept alive.
fn sid_from_string(s: &str) -> (Vec<u64>, PSID) {
    let mut string: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sid: PSID = null_mut();
    let ok = unsafe { ConvertStringSidToSidW(string.as_mut_ptr(), &mut sid) };
    assert_ne!(ok, 0, "ConvertStringSidToSidW failed for {s}");

    let len = unsafe { GetLengthSid(sid) } as usize;
    let mut owned = aligned(len);
    unsafe {
        std::ptr::copy_nonoverlapping(sid as *const u8, owned.as_mut_ptr() as *mut u8, len);
        LocalFree(sid);
    }

    let pointer = owned.as_mut_ptr() as PSID;
    (owned, pointer)
}

/// Replaces `path`'s DACL with one allow ACE for the file's owner and either an
/// allow or deny ACE for `other_sid`.
fn apply_dacl(path: &Path, other_sid: PSID, other_is_deny: bool) {
    let path_wide = wide(path);

    let mut owner: PSID = null_mut();
    let mut security_descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let code = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut security_descriptor,
        )
    };
    assert_eq!(code, 0, "GetNamedSecurityInfoW failed with {code}");

    let owner_len = unsafe { GetLengthSid(owner) } as usize;
    let other_len = unsafe { GetLengthSid(other_sid) } as usize;
    let ace_overhead = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>();
    let acl_size = size_of::<ACL>() + 2 * ace_overhead + owner_len + other_len;

    let mut acl_buf = aligned(acl_size);
    let acl = acl_buf.as_mut_ptr() as *mut ACL;
    assert_ne!(
        unsafe { InitializeAcl(acl, acl_size as u32, ACL_REVISION) },
        0
    );
    assert_ne!(
        unsafe { AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, owner) },
        0
    );

    let added = if other_is_deny {
        unsafe { AddAccessDeniedAce(acl, ACL_REVISION, GENERIC_READ, other_sid) }
    } else {
        unsafe { AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_READ, other_sid) }
    };
    assert_ne!(added, 0, "failed to add the second ACE");

    let mut descriptor_buf = aligned(size_of::<SECURITY_DESCRIPTOR>());
    let descriptor = descriptor_buf.as_mut_ptr() as *mut SECURITY_DESCRIPTOR;
    assert_ne!(
        unsafe {
            InitializeSecurityDescriptor(descriptor as *mut c_void, SECURITY_DESCRIPTOR_REVISION)
        },
        0
    );
    assert_ne!(
        unsafe { SetSecurityDescriptorDacl(descriptor as *mut c_void, 1, acl, 0) },
        0
    );

    let code = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null_mut(),
        )
    };
    unsafe { LocalFree(security_descriptor) };
    assert_eq!(code, 0, "SetNamedSecurityInfoW failed with {code}");
}

#[test]
fn explicit_deny_ace_does_not_mark_file_insecure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, b"data").unwrap();

    let (_keep, other) = sid_from_string(OTHER_SID);
    apply_dacl(&path, other, true);

    let file = SecureFile::open_unchecked(&path).unwrap();
    assert!(
        file.is_private().unwrap(),
        "a deny ACE grants nobody access, so the file is still owner-only"
    );
    assert!(SecureFile::open(&path).is_ok());
}

#[test]
fn explicit_other_allow_ace_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, b"data").unwrap();

    let (_keep, other) = sid_from_string(OTHER_SID);
    apply_dacl(&path, other, false);

    let file = SecureFile::open_unchecked(&path).unwrap();
    assert!(
        !file.is_private().unwrap(),
        "another principal has an allow ACE"
    );

    let err = SecureFile::open(&path).unwrap_err();
    assert!(
        matches!(err, Error::InsecurePermissions),
        "unexpected: {err:?}"
    );
}

#[test]
fn ensure_private_replaces_crafted_dacl() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, b"data").unwrap();

    let (_keep, other) = sid_from_string(OTHER_SID);
    apply_dacl(&path, other, false);
    assert!(!SecureFile::open_unchecked(&path)
        .unwrap()
        .is_private()
        .unwrap());

    let file = SecureFile::open_unchecked(&path).unwrap();
    let file = file.ensure_private().unwrap();
    assert!(file.is_private().unwrap());
    assert!(SecureFile::open(&path).is_ok());
}
