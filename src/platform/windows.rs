use crate::{Error, Result};
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, GetSecurityInfo, SetNamedSecurityInfoW, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAce, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorDacl, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
    IsValidSid, SetSecurityDescriptorControl, SetSecurityDescriptorDacl, TokenUser,
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileAttributesW, GetFileInformationByHandle, ReOpenFile,
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, INVALID_FILE_ATTRIBUTES, OPEN_EXISTING,
    READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 5;

const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

fn invalid_input(message: &'static str) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn last_error() -> Error {
    Error::from(io::Error::last_os_error())
}

fn win32_error(code: u32) -> Error {
    Error::from(io::Error::from_raw_os_error(code as i32))
}

/// A buffer whose start is aligned to 8 bytes, suitable for the Windows
/// security structures and SIDs we build.
fn aligned(bytes: usize) -> Vec<u64> {
    vec![0u64; bytes.div_ceil(8)]
}

fn wide(path: &Path) -> Vec<u16> {
    let mut buf: Vec<u16> = path.as_os_str().encode_wide().collect();
    buf.push(0);
    buf
}

/// Reads the current process user's SID into an owned, aligned buffer.
fn current_user_sid() -> Result<Vec<u64>> {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(last_error());
        }

        let mut needed: u32 = 0;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
        if needed == 0 {
            let err = last_error();
            CloseHandle(token);
            return Err(err);
        }

        let mut info = aligned(needed as usize);
        let ok = GetTokenInformation(
            token,
            TokenUser,
            info.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        );
        CloseHandle(token);
        if ok == 0 {
            return Err(last_error());
        }

        let token_user = &*(info.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;
        if IsValidSid(sid) == 0 {
            return Err(Error::Io(io::Error::other(
                "operating system returned an invalid user SID",
            )));
        }

        let sid_len = GetLengthSid(sid) as usize;
        let mut owned = aligned(sid_len);
        std::ptr::copy_nonoverlapping(sid as *const u8, owned.as_mut_ptr() as *mut u8, sid_len);
        Ok(owned)
    }
}

struct OwnerOnlyDescriptor {
    descriptor: Vec<u64>,
    acl: Vec<u64>,
}

/// Builds a security descriptor whose DACL grants full control to `sid` only,
/// with inheritance disabled (`SE_DACL_PROTECTED`).
fn owner_only_descriptor(sid: PSID) -> Result<OwnerOnlyDescriptor> {
    unsafe {
        let sid_len = GetLengthSid(sid) as usize;
        let acl_size =
            size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid_len;

        let mut acl_buf = aligned(acl_size);
        let acl = acl_buf.as_mut_ptr() as *mut ACL;
        if InitializeAcl(acl, acl_size as u32, ACL_REVISION) == 0 {
            return Err(last_error());
        }
        if AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, sid) == 0 {
            return Err(last_error());
        }

        let mut descriptor_buf = aligned(size_of::<SECURITY_DESCRIPTOR>());
        let descriptor = descriptor_buf.as_mut_ptr() as *mut SECURITY_DESCRIPTOR;
        if InitializeSecurityDescriptor(descriptor as *mut c_void, SECURITY_DESCRIPTOR_REVISION)
            == 0
        {
            return Err(last_error());
        }
        if SetSecurityDescriptorDacl(descriptor as *mut c_void, 1, acl, 0) == 0 {
            return Err(last_error());
        }
        if SetSecurityDescriptorControl(
            descriptor as *mut c_void,
            SE_DACL_PROTECTED,
            SE_DACL_PROTECTED,
        ) == 0
        {
            return Err(last_error());
        }

        Ok(OwnerOnlyDescriptor {
            descriptor: descriptor_buf,
            acl: acl_buf,
        })
    }
}

fn security_attributes(descriptor: &OwnerOnlyDescriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.descriptor.as_ptr() as *mut c_void,
        bInheritHandle: 0,
    }
}

fn handle_from_create(handle: HANDLE) -> Result<File> {
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
}

fn attributes(file: &File) -> Result<u32> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(info.dwFileAttributes)
}

fn ensure_regular_file(file: &File) -> Result<()> {
    let attrs = attributes(file)?;
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Error::SymlinkDetected);
    }
    if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(invalid_input("path is a directory, not a file"));
    }
    Ok(())
}

fn reopen_for_security(file: &File) -> Result<HANDLE> {
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle() as HANDLE,
            READ_CONTROL | WRITE_DAC,
            SHARE_ALL,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    Ok(handle)
}

pub(crate) fn create_file(path: &Path) -> Result<File> {
    let sid = current_user_sid()?;
    let descriptor = owner_only_descriptor(sid.as_ptr() as PSID)?;
    let attributes = security_attributes(&descriptor);
    let path = wide(path);

    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            SHARE_ALL,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };

    let file = handle_from_create(handle)?;
    ensure_regular_file(&file)?;
    Ok(file)
}

pub(crate) fn open_file(path: &Path, write: bool) -> Result<File> {
    let access = if write {
        GENERIC_READ | GENERIC_WRITE
    } else {
        GENERIC_READ
    };
    let path = wide(path);

    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            SHARE_ALL,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };

    let file = handle_from_create(handle)?;
    ensure_regular_file(&file)?;
    Ok(file)
}

pub(crate) fn ensure_file_private(file: &File) -> Result<()> {
    let sid = current_user_sid()?;
    let descriptor = owner_only_descriptor(sid.as_ptr() as PSID)?;
    let handle = reopen_for_security(file)?;

    let code = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            descriptor.acl.as_ptr() as *const ACL,
            null_mut(),
        )
    };
    unsafe { CloseHandle(handle) };

    if code != 0 {
        return Err(win32_error(code));
    }
    Ok(())
}

pub(crate) fn is_file_private(file: &File) -> Result<bool> {
    let handle = reopen_for_security(file)?;
    let mut descriptor: *mut c_void = null_mut();
    let mut dacl: *mut ACL = null_mut();

    let code = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };

    if code != 0 {
        unsafe { CloseHandle(handle) };
        return Err(win32_error(code));
    }

    let sid = current_user_sid()?;
    let owner_only = dacl_is_owner_only(descriptor, sid.as_ptr() as PSID);

    unsafe {
        LocalFree(descriptor);
        CloseHandle(handle);
    }
    Ok(owner_only)
}

/// Returns `true` when the DACL grants access only to `user`.
fn dacl_is_owner_only(descriptor: *mut c_void, user: PSID) -> bool {
    unsafe {
        let mut present: BOOL = 0;
        let mut dacl: *mut ACL = null_mut();
        let mut defaulted: BOOL = 0;

        if GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) == 0 {
            return false;
        }
        // A NULL DACL grants everyone full access.
        if present == 0 || dacl.is_null() {
            return false;
        }

        let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
        if GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut c_void,
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) == 0
        {
            return false;
        }

        for index in 0..info.AceCount {
            let mut ace: *mut c_void = null_mut();
            if GetAce(dacl, index, &mut ace) == 0 || ace.is_null() {
                return false;
            }

            let header = &*(ace as *const ACE_HEADER);
            match header.AceType {
                ACCESS_ALLOWED_ACE_TYPE => {
                    let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                    let sid = &allowed.SidStart as *const u32 as PSID;
                    if EqualSid(sid, user) == 0 {
                        return false;
                    }
                }
                ACCESS_ALLOWED_OBJECT_ACE_TYPE => {
                    // Object ACEs carry a variable-length SID; be conservative.
                    return false;
                }
                _ => {}
            }
        }

        true
    }
}

pub(crate) fn create_dir(path: &Path) -> Result<()> {
    let sid = current_user_sid()?;
    let descriptor = owner_only_descriptor(sid.as_ptr() as PSID)?;
    let attributes = security_attributes(&descriptor);
    let wide_path = wide(path);

    let ok = unsafe { CreateDirectoryW(wide_path.as_ptr(), &attributes) };
    if ok == 0 {
        return Err(last_error());
    }

    // Ensure inherited ACEs cannot reappear on the new directory.
    ensure_dir_private(path)?;
    Ok(())
}

pub(crate) fn open_dir(path: &Path) -> Result<()> {
    let path = wide(path);
    let attrs = unsafe { GetFileAttributesW(path.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return Err(last_error());
    }
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Error::SymlinkDetected);
    }
    if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(invalid_input("path is not a directory"));
    }
    Ok(())
}

pub(crate) fn ensure_dir_private(path: &Path) -> Result<()> {
    let sid = current_user_sid()?;
    let descriptor = owner_only_descriptor(sid.as_ptr() as PSID)?;
    let path = wide(path);

    let code = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            descriptor.acl.as_ptr() as *const ACL,
            null_mut(),
        )
    };

    if code != 0 {
        return Err(win32_error(code));
    }
    Ok(())
}

pub(crate) fn is_dir_private(path: &Path) -> Result<bool> {
    let path = wide(path);
    let mut descriptor: *mut c_void = null_mut();
    let mut dacl: *mut ACL = null_mut();

    let code = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };

    if code != 0 {
        return Err(win32_error(code));
    }

    let sid = current_user_sid()?;
    let owner_only = dacl_is_owner_only(descriptor, sid.as_ptr() as PSID);
    unsafe { LocalFree(descriptor) };
    Ok(owner_only)
}
