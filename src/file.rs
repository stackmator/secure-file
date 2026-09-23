use crate::platform;
use crate::{Error, Result, SecurePermissions};
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// A file that is only accessible by the current user.
///
/// Files are created with owner-only permissions from the moment they exist on
/// disk, so there is no window during which another user could read them.
///
/// On Unix the permissions are `0600`. On Windows the file receives a
/// discretionary access control list (DACL) that grants full control only to
/// the current user, with inheritance disabled.
pub struct SecureFile {
    file: File,
    path: PathBuf,
}

impl SecureFile {
    /// Creates a new file, failing if it already exists.
    ///
    /// The file is created atomically with owner-only permissions. Symbolic
    /// links (and Windows reparse points) are never followed, so a link at
    /// `path` cannot redirect the write to another location.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = platform::create_file(&path)?;
        Ok(SecureFile { file, path })
    }

    /// Opens an existing file and verifies that it is private.
    ///
    /// Returns [`Error::InsecurePermissions`] if the file is accessible by
    /// anyone other than the owner. Use [`SecureFile::open_unchecked`] followed
    /// by [`SecureFile::ensure_private`] to tighten an existing file.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = Self::open_inner(path.as_ref(), false)?;
        if !file.is_private()? {
            return Err(Error::InsecurePermissions);
        }
        Ok(file)
    }

    /// Opens an existing file without checking its permissions.
    ///
    /// Symbolic links are still rejected. The caller is responsible for
    /// verifying the result, typically via [`SecureFile::ensure_private`].
    pub fn open_unchecked<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_inner(path.as_ref(), false)
    }

    /// Opens an existing file for reading and writing without checking its
    /// permissions.
    ///
    /// Symbolic links are still rejected.
    pub fn open_write<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_inner(path.as_ref(), true)
    }

    fn open_inner(path: &Path, write: bool) -> Result<Self> {
        let path = path.to_path_buf();
        let file = platform::open_file(&path, write)?;
        Ok(SecureFile { file, path })
    }

    /// Tightens the permissions of this file to owner-only and verifies the
    /// result.
    ///
    /// This is useful for files that already existed and were created without
    /// owner-only permissions.
    pub fn ensure_private(self) -> Result<Self> {
        platform::ensure_file_private(&self.file)?;
        if !self.is_private()? {
            return Err(Error::InsecurePermissions);
        }
        Ok(self)
    }

    /// Returns `true` when only the owner can access this file.
    pub fn is_private(&self) -> Result<bool> {
        platform::is_file_private(&self.file)
    }

    /// Returns a platform-independent view of this file's permissions.
    pub fn permissions(&self) -> Result<SecurePermissions> {
        Ok(SecurePermissions {
            owner_only: self.is_private()?,
        })
    }

    /// Returns the path this file was opened with.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns a shared reference to the underlying [`File`].
    pub fn as_file(&self) -> &File {
        &self.file
    }

    /// Returns a mutable reference to the underlying [`File`].
    pub fn as_file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Consumes this wrapper and returns the underlying [`File`].
    pub fn into_file(self) -> File {
        self.file
    }

    /// Returns the metadata for this file.
    pub fn metadata(&self) -> Result<Metadata> {
        Ok(self.file.metadata()?)
    }

    /// Writes all bytes from `buf` into this file.
    pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.file.write_all(buf)?;
        Ok(())
    }

    /// Reads all bytes until EOF, appending them to `buf`.
    pub fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        Ok(self.file.read_to_end(buf)?)
    }

    /// Reads all bytes until EOF into `buf`, which must be valid UTF-8.
    pub fn read_to_string(&mut self, buf: &mut String) -> Result<usize> {
        Ok(self.file.read_to_string(buf)?)
    }

    /// Truncates or extends the file to the specified length.
    pub fn set_len(&self, len: u64) -> Result<()> {
        self.file.set_len(len)?;
        Ok(())
    }

    /// Flushes any buffered data.
    pub fn flush(&mut self) -> Result<()> {
        self.file.flush()?;
        Ok(())
    }

    /// Attempts to sync all OS-internal metadata to disk.
    pub fn sync_all(&self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }
}

impl fmt::Debug for SecureFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureFile")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Read for SecureFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for SecureFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for SecureFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}
