use crate::{Error, Result};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

const OPEN_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_CLOEXEC;
const DIR_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY;

fn invalid_input(message: &'static str) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::InvalidInput, message))
}

/// Rejects symbolic links up front so callers get a precise
/// [`Error::SymlinkDetected`]. The `O_NOFOLLOW` open that follows remains the
/// actual enforcement against races; some platforms report `ENOTDIR` rather
/// than `ELOOP` for `O_NOFOLLOW | O_DIRECTORY`, which would otherwise be
/// ambiguous.
fn reject_symlink(path: &Path) -> Result<()> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(Error::SymlinkDetected);
    }
    Ok(())
}

pub(crate) fn create_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(OPEN_FLAGS)
        .open(path)?;
    Ok(file)
}

pub(crate) fn open_file(path: &Path, write: bool) -> Result<File> {
    reject_symlink(path)?;

    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(OPEN_FLAGS)
        .open(path)?;

    if file.metadata()?.is_dir() {
        return Err(invalid_input("path is a directory, not a file"));
    }

    Ok(file)
}

pub(crate) fn ensure_file_private(file: &File) -> Result<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(FILE_MODE);
    file.set_permissions(permissions)?;
    Ok(())
}

pub(crate) fn is_file_private(file: &File) -> Result<bool> {
    let mode = file.metadata()?.mode();
    Ok(mode & 0o077 == 0)
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

pub(crate) fn is_dir_private(path: &Path) -> Result<bool> {
    reject_symlink(path)?;

    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(DIR_FLAGS)
        .open(path)?;

    let mode = dir.metadata()?.mode();
    Ok(mode & 0o077 == 0)
}
