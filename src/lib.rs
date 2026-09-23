//! Cross-platform owner-only filesystem access for Rust.
//!
//! `secure-file` creates and opens files and directories that should only be
//! accessible by the current user, hiding the platform differences behind a
//! small API:
//!
//! | Platform    | Files  | Directories |
//! |-------------|--------|-------------|
//! | Linux/macOS | `0600` | `0700`      |
//! | Windows     | Owner-only DACL | Owner-only DACL |
//!
//! The key property is that resources are secure *from the moment they are
//! created*, rather than being created and then tightened afterwards:
//!
//! ```no_run
//! use secure_file::SecureFile;
//! use std::io::Write;
//!
//! # fn main() -> secure_file::Result<()> {
//! let mut file = SecureFile::create("credentials.json")?;
//! file.write_all(b"secret data")?;
//! # Ok(())
//! # }
//! ```
//!
//! For the common case of reading or writing a whole secret, the free functions
//! [`write_private`] and [`read_private`] are even shorter:
//!
//! ```no_run
//! # fn main() -> secure_file::Result<()> {
//! secure_file::write_private("api-key", b"secret")?;
//! let secret = secure_file::read_private("api-key")?;
//! # Ok(())
//! # }
//! ```
//!
//! To replace a file atomically — so readers never observe a partial file —
//! use [`write_private_atomic`]:
//!
//! ```no_run
//! # fn main() -> secure_file::Result<()> {
//! secure_file::write_private_atomic("api-key", b"secret")?;
//! # Ok(())
//! # }
//! ```
//!
//! For control over open flags and symlink handling, use the builder returned
//! by [`SecureFile::options`].
//!
//! Owner-only temporary files and directories are available through
//! [`SecureTempFile`] and [`SecureTempDir`], and [`app_dir`] creates an
//! application-private directory under the platform's per-user data directory.
//!
//! ```no_run
//! # fn main() -> secure_file::Result<()> {
//! use std::io::Write;
//!
//! let mut scratch = secure_file::SecureTempFile::new()?;
//! scratch.write_all(b"temporary secret")?;
//! # Ok(())
//! # }
//! ```
//!
//! # Security model
//!
//! `secure-file` protects files against access by other operating-system users
//! according to the platform's filesystem permission model. On Unix it uses
//! owner-only permission bits; on Windows it uses a restrictive DACL.
//!
//! It does **not** protect against:
//!
//! * `root` / `Administrator` (or equivalent) accounts,
//! * malware running with equivalent privileges,
//! * a compromised operating system,
//! * physical access to the storage medium,
//! * filesystem-level or full-disk encryption attacks,
//! * memory disclosure.
//!
//! This crate is **not** encryption. It only restricts who the operating system
//! allows to read or write the resource.

#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(missing_debug_implementations)]

mod appdir;
mod dir;
mod error;
mod file;
mod options;
mod permissions;
mod platform;
mod temp;

pub use crate::appdir::{app_data_dir, app_dir, app_dir_in};
pub use crate::dir::SecureDir;
pub use crate::error::{Error, Result};
pub use crate::file::SecureFile;
pub use crate::options::SecureFileOptions;
pub use crate::permissions::SecurePermissions;
pub use crate::temp::{SecureTempDir, SecureTempFile};

use std::ffi::OsString;
use std::io;
use std::path::Path;

/// Writes `data` to `path` as a file that only the current user can access.
///
/// If the file does not exist it is created atomically with owner-only
/// permissions. If it already exists it is truncated, its permissions are
/// tightened to owner-only, and then it is written. Symbolic links are always
/// rejected.
///
/// ```no_run
/// # fn main() -> secure_file::Result<()> {
/// secure_file::write_private("token", b"secret")?;
/// # Ok(())
/// # }
/// ```
pub fn write_private<P, D>(path: P, data: D) -> Result<()>
where
    P: AsRef<Path>,
    D: AsRef<[u8]>,
{
    let path = path.as_ref();
    let data = data.as_ref();

    match SecureFile::create(path) {
        Ok(mut file) => {
            file.write_all(data)?;
            file.sync_all()?;
            Ok(())
        }
        Err(Error::AlreadyExists) => {
            let file = SecureFile::open_write(path)?;
            let mut file = file.ensure_private()?;
            file.set_len(0)?;
            file.write_all(data)?;
            file.sync_all()?;
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Atomically writes `data` to `path` as a file that only the current user can
/// access.
///
/// The data is first written to a temporary file created with owner-only
/// permissions in the same directory, flushed to disk, and then renamed over
/// `path`. A reader therefore never observes a partially written file, and the
/// destination is never left in a world-readable state. Symbolic links at
/// `path` are rejected.
///
/// ```no_run
/// # fn main() -> secure_file::Result<()> {
/// secure_file::write_private_atomic("credentials.json", b"secret")?;
/// # Ok(())
/// # }
/// ```
pub fn write_private_atomic<P, D>(path: P, data: D) -> Result<()>
where
    P: AsRef<Path>,
    D: AsRef<[u8]>,
{
    let path = path.as_ref();
    let data = data.as_ref();

    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(Error::SymlinkDetected);
        }
    }

    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };

    let (temporary_path, mut temporary) = create_temporary(parent, path)?;

    let write_result = (|| -> Result<()> {
        temporary.write_all(data)?;
        temporary.sync_all()?;
        Ok(())
    })();
    drop(temporary);

    if let Err(err) = write_result {
        let _ = std::fs::remove_file(&temporary_path);
        return Err(err);
    }

    if let Err(err) = std::fs::rename(&temporary_path, path) {
        let _ = std::fs::remove_file(&temporary_path);
        return Err(Error::from(err));
    }

    sync_parent(parent);
    Ok(())
}

fn create_temporary(parent: &Path, target: &Path) -> Result<(std::path::PathBuf, SecureFile)> {
    for attempt in 0..128u32 {
        let candidate = parent.join(temporary_name(target, attempt));
        match SecureFile::create(&candidate) {
            Ok(file) => return Ok((candidate, file)),
            Err(Error::AlreadyExists) => continue,
            Err(err) => return Err(err),
        }
    }

    Err(Error::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique temporary file",
    )))
}

fn temporary_name(target: &Path, attempt: u32) -> OsString {
    let mut name = OsString::from(".");
    if let Some(file_name) = target.file_name() {
        name.push(file_name);
    }
    name.push(format!(".{}.{}.tmp", std::process::id(), attempt));
    name
}

#[cfg(unix)]
fn sync_parent(parent: &Path) {
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) {}

/// Reads the entire contents of a private file.
///
/// Returns [`Error::InsecurePermissions`] if the file is accessible by anyone
/// other than the owner.
///
/// ```no_run
/// # fn main() -> secure_file::Result<()> {
/// let secret = secure_file::read_private("token")?;
/// # Ok(())
/// # }
/// ```
pub fn read_private<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let mut file = SecureFile::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Creates a directory that only the current user can access.
///
/// Fails if the directory already exists.
///
/// ```no_run
/// # fn main() -> secure_file::Result<()> {
/// secure_file::create_dir(".myapp")?;
/// # Ok(())
/// # }
/// ```
pub fn create_dir<P: AsRef<Path>>(path: P) -> Result<SecureDir> {
    SecureDir::create(path)
}
