use crate::platform;
use crate::{Error, Result, SecurePermissions};
use std::fmt;
use std::path::{Path, PathBuf};

/// A directory that is only accessible by the current user.
///
/// Directories are created with owner-only permissions from the moment they
/// exist on disk.
///
/// On Unix the permissions are `0700`. On Windows the directory receives a
/// discretionary access control list (DACL) that grants full control only to
/// the current user, with inheritance disabled.
pub struct SecureDir {
    path: PathBuf,
}

impl SecureDir {
    /// Creates a new directory, failing if it already exists.
    ///
    /// The directory is created atomically with owner-only permissions.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        platform::create_dir(&path)?;
        Ok(SecureDir { path })
    }

    /// Opens an existing directory and verifies that it is private.
    ///
    /// Returns [`Error::InsecurePermissions`] if the directory is accessible by
    /// anyone other than the owner.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let dir = Self::open_unchecked(path)?;
        if !dir.is_private()? {
            return Err(Error::InsecurePermissions);
        }
        Ok(dir)
    }

    /// Opens an existing directory without checking its permissions.
    ///
    /// Symbolic links are still rejected. The caller is responsible for
    /// verifying the result, typically via [`SecureDir::ensure_private`].
    pub fn open_unchecked<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        platform::open_dir(&path)?;
        Ok(SecureDir { path })
    }

    /// Tightens the permissions of this directory to owner-only and verifies
    /// the result.
    pub fn ensure_private(self) -> Result<Self> {
        platform::ensure_dir_private(&self.path)?;
        if !self.is_private()? {
            return Err(Error::InsecurePermissions);
        }
        Ok(self)
    }

    /// Returns `true` when only the owner can access this directory.
    pub fn is_private(&self) -> Result<bool> {
        platform::is_dir_private(&self.path)
    }

    /// Returns a platform-independent view of this directory's permissions.
    pub fn permissions(&self) -> Result<SecurePermissions> {
        Ok(SecurePermissions {
            owner_only: self.is_private()?,
        })
    }

    /// Returns the path of this directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for SecureDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureDir")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}
