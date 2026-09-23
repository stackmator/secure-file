use crate::platform::OpenParams;
use crate::{Error, Result, SecurePermissions};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

const OPEN_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_CLOEXEC;
const DIR_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY;

fn invalid_input(_message: &'static str) -> Error {
    Error::InvalidInput
}

/// Rejects symbolic links up front so callers get a precise
/// [`Error::SymlinkDetected`]. The `O_NOFOLLOW` open that follows remains the
/// actual enforcement against races; some platforms report `ENOTDIR` rather
/// than `ELOOP` for `O_NOFOLLOW | O_DIRECTORY`, which would otherwise be
/// ambiguous.
fn reject_symlink(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::SymlinkDetected),
        Ok(_) => Ok(()),
        // A missing path is fine; creation will handle it.
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(Error::from(err)),
    }
}

/// Returns whether `path` is a symbolic link (or, on other platforms, another
/// kind of link-like object). A missing path is not a link.
pub(crate) fn path_is_link(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(Error::from(err)),
    }
}

fn permissions_from_mode(mode: u32) -> SecurePermissions {
    SecurePermissions {
        owner_only: mode & 0o077 == 0,
        owner_read: mode & 0o400 != 0,
        owner_write: mode & 0o200 != 0,
        owner_execute: mode & 0o100 != 0,
    }
}

pub(crate) fn open_with(path: &Path, params: &OpenParams) -> Result<File> {
    if !params.follow_symlinks {
        reject_symlink(path)?;
    }

    let mut options = OpenOptions::new();
    options.read(params.read);
    options.write(params.write || params.append);
    if params.append {
        options.append(true);
    }
    if params.truncate {
        options.truncate(true);
    }
    if params.create_new {
        options.create_new(true);
    } else if params.create {
        options.create(true);
    }
    if params.create || params.create_new {
        options.mode(FILE_MODE);
    }
    if params.follow_symlinks {
        options.custom_flags(libc::O_CLOEXEC);
    } else {
        options.custom_flags(OPEN_FLAGS);
    }

    let file = options.open(path)?;

    if file.metadata()?.is_dir() {
        return Err(invalid_input("path is a directory, not a file"));
    }

    Ok(file)
}

pub(crate) fn create_file(path: &Path) -> Result<File> {
    open_with(
        path,
        &OpenParams {
            read: true,
            write: true,
            create_new: true,
            ..OpenParams::default()
        },
    )
}

pub(crate) fn open_file(path: &Path, write: bool) -> Result<File> {
    open_with(
        path,
        &OpenParams {
            read: true,
            write,
            ..OpenParams::default()
        },
    )
}

pub(crate) fn ensure_file_private(file: &File) -> Result<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(FILE_MODE);
    file.set_permissions(permissions)?;
    Ok(())
}

pub(crate) fn file_permissions(file: &File) -> Result<SecurePermissions> {
    Ok(permissions_from_mode(file.metadata()?.mode()))
}

pub(crate) fn create_dir(path: &Path) -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(DIR_MODE);
    builder.create(path)?;
    Ok(())
}

pub(crate) fn open_dir(path: &Path) -> Result<()> {
    reject_symlink(path)?;

    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(DIR_FLAGS)
        .open(path)?;

    if !dir.metadata()?.is_dir() {
        return Err(invalid_input("path is not a directory"));
    }

    Ok(())
}

pub(crate) fn ensure_dir_private(path: &Path) -> Result<()> {
    reject_symlink(path)?;

    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(DIR_FLAGS)
        .open(path)?;

    let mut permissions = dir.metadata()?.permissions();
    permissions.set_mode(DIR_MODE);
    dir.set_permissions(permissions)?;
    Ok(())
}

pub(crate) fn dir_permissions(path: &Path) -> Result<SecurePermissions> {
    reject_symlink(path)?;

    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(DIR_FLAGS)
        .open(path)?;

    Ok(permissions_from_mode(dir.metadata()?.mode()))
}
