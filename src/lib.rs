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

mod dir;
mod error;
mod file;
mod permissions;
mod platform;

pub use crate::dir::SecureDir;
pub use crate::error::{Error, Result};
pub use crate::file::SecureFile;
pub use crate::permissions::SecurePermissions;

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
