use crate::{Error, Result, SecureDir, SecureFile};
use std::collections::hash_map::RandomState;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generates an unpredictable, collision-resistant temporary name.
///
/// Unpredictability is defence in depth; the exclusive create that follows is
/// the actual protection against a name being pre-created.
fn unique_name(prefix: &str) -> OsString {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0),
    );
    hasher.write_u32(std::process::id());
    OsString::from(format!(".{prefix}-{:016x}.tmp", hasher.finish()))
}

/// A temporary file that only the current user can access.
///
/// The file is created with owner-only permissions and is deleted when the
/// value is dropped, unless it is kept with [`SecureTempFile::keep`] or moved
/// into place with [`SecureTempFile::persist`].
pub struct SecureTempFile {
    file: Option<SecureFile>,
    path: PathBuf,
    delete_on_drop: bool,
}

impl SecureTempFile {
    /// Creates a temporary file in the system temporary directory.
    pub fn new() -> Result<Self> {
        Self::new_in(std::env::temp_dir())
    }

    /// Creates a temporary file inside `dir`.
    pub fn new_in<P: AsRef<Path>>(dir: P) -> Result<Self> {
        let dir = dir.as_ref();
        for _ in 0..128 {
            let path = dir.join(unique_name("secure-file"));
            match SecureFile::create(&path) {
                Ok(file) => {
                    return Ok(SecureTempFile {
                        file: Some(file),
                        path,
                        delete_on_drop: true,
                    })
                }
                Err(Error::AlreadyExists) => continue,
                Err(err) => return Err(err),
            }
        }

        Err(Error::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique temporary file",
        )))
    }

    /// Returns the path of this temporary file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns a shared reference to the underlying [`File`].
    pub fn as_file(&self) -> &File {
        self.file
            .as_ref()
            .expect("temporary file handle is always present")
            .as_file()
    }

    /// Returns a mutable reference to the underlying [`File`].
    pub fn as_file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .expect("temporary file handle is always present")
            .as_file_mut()
    }

    /// Prevents the file from being deleted on drop and returns its path.
    pub fn keep(mut self) -> PathBuf {
        self.delete_on_drop = false;
        self.path.clone()
    }

    /// Atomically moves the temporary file to `new_path`.
    ///
    /// The file is no longer deleted on drop. Any existing file at `new_path`
    /// is replaced (the destination is never followed if it is a symbolic
    /// link).
    pub fn persist<P: AsRef<Path>>(mut self, new_path: P) -> Result<PathBuf> {
        let new_path = new_path.as_ref().to_path_buf();
        // Close our handle first so the rename works on every platform.
        self.file = None;
        std::fs::rename(&self.path, &new_path)?;
        self.delete_on_drop = false;
        Ok(new_path)
    }
}

impl Drop for SecureTempFile {
    fn drop(&mut self) {
        if self.delete_on_drop {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Deref for SecureTempFile {
    type Target = SecureFile;

    fn deref(&self) -> &SecureFile {
        self.file
            .as_ref()
            .expect("temporary file handle is always present")
    }
}

impl DerefMut for SecureTempFile {
    fn deref_mut(&mut self) -> &mut SecureFile {
        self.file
            .as_mut()
            .expect("temporary file handle is always present")
    }
}

impl fmt::Debug for SecureTempFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureTempFile")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// A temporary directory that only the current user can access.
///
/// The directory is created with owner-only permissions and is removed when
/// the value is dropped, unless it is kept with [`SecureTempDir::keep`].
pub struct SecureTempDir {
    path: PathBuf,
    delete_on_drop: bool,
}

impl SecureTempDir {
    /// Creates a temporary directory in the system temporary directory.
    pub fn new() -> Result<Self> {
        Self::new_in(std::env::temp_dir())
    }

    /// Creates a temporary directory inside `dir`.
    pub fn new_in<P: AsRef<Path>>(dir: P) -> Result<Self> {
        let dir = dir.as_ref();
        for _ in 0..128 {
            let path = dir.join(unique_name("secure-file"));
            match SecureDir::create(&path) {
                Ok(_) => {
                    return Ok(SecureTempDir {
                        path,
                        delete_on_drop: true,
                    })
                }
                Err(Error::AlreadyExists) => continue,
                Err(err) => return Err(err),
            }
        }

        Err(Error::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique temporary directory",
        )))
    }

    /// Returns the path of this temporary directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Prevents the directory from being removed on drop and returns its path.
    pub fn keep(mut self) -> PathBuf {
        self.delete_on_drop = false;
        self.path.clone()
    }
}

impl Drop for SecureTempDir {
    fn drop(&mut self) {
        if self.delete_on_drop {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

impl fmt::Debug for SecureTempDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureTempDir")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}
