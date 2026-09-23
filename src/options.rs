use crate::platform::{self, OpenParams};
use crate::{Error, Result, SecureFile};
use std::path::Path;

/// A builder for opening or creating a [`SecureFile`] with fine-grained
/// control.
///
/// The defaults are conservative: files are opened read-only, symlinks are
/// rejected, and existing files are verified to be owner-only before being
/// returned.
///
/// ```no_run
/// # fn main() -> secure_file::Result<()> {
/// use secure_file::SecureFile;
///
/// let file = SecureFile::options()
///     .create(true)
///     .truncate(true)
///     .write(true)
///     .open("credentials.json")?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SecureFileOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    follow_symlinks: bool,
    verify_private: bool,
}

impl Default for SecureFileOptions {
    fn default() -> Self {
        SecureFileOptions {
            read: true,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            follow_symlinks: false,
            verify_private: true,
        }
    }
}

impl SecureFileOptions {
    /// Creates a new set of options with secure defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether the file is opened for reading (default `true`).
    pub fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    /// Sets whether the file is opened for writing.
    pub fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    /// Sets whether writes append to the end of the file.
    pub fn append(mut self, append: bool) -> Self {
        self.append = append;
        self
    }

    /// Sets whether the file is truncated when opened.
    pub fn truncate(mut self, truncate: bool) -> Self {
        self.truncate = truncate;
        self
    }

    /// Sets whether the file is created if it does not already exist.
    ///
    /// A newly created file receives owner-only permissions. An existing file
    /// is opened as-is and, unless [`SecureFileOptions::verify_private`] is
    /// disabled, must already be owner-only.
    ///
    /// Creation requires write (or append) access; otherwise opening fails
    /// with [`Error::InvalidInput`].
    pub fn create(mut self, create: bool) -> Self {
        self.create = create;
        self
    }

    /// Sets whether the file must be created and must not already exist.
    ///
    /// This is an exclusive, atomic create (`O_CREAT | O_EXCL` on Unix,
    /// `CREATE_NEW` on Windows) and always applies owner-only permissions.
    ///
    /// Creation requires write (or append) access; otherwise opening fails
    /// with [`Error::InvalidInput`].
    pub fn create_new(mut self, create_new: bool) -> Self {
        self.create_new = create_new;
        self
    }

    /// Sets whether symbolic links (and Windows reparse points) are followed.
    ///
    /// Defaults to `false`. Enabling this is a security risk: a link planted
    /// at the target path can redirect the operation to a different file.
    pub fn follow_symlinks(mut self, follow_symlinks: bool) -> Self {
        self.follow_symlinks = follow_symlinks;
        self
    }

    /// Sets whether an existing file must be verified to be owner-only before
    /// being returned (default `true`).
    pub fn verify_private(mut self, verify_private: bool) -> Self {
        self.verify_private = verify_private;
        self
    }

    /// Opens the file at `path` using these options.
    pub fn open<P: AsRef<Path>>(self, path: P) -> Result<SecureFile> {
        let path = path.as_ref();

        if !(self.read || self.write || self.append) {
            return Err(Error::InvalidInput);
        }
        // Creation is only supported together with write access, matching the
        // behavior of `std::fs::OpenOptions` on Unix.
        if (self.create || self.create_new) && !(self.write || self.append) {
            return Err(Error::InvalidInput);
        }
        if self.truncate && !self.write {
            return Err(Error::InvalidInput);
        }
        if self.truncate && self.append {
            return Err(Error::InvalidInput);
        }

        let params = OpenParams {
            read: self.read,
            write: self.write,
            append: self.append,
            truncate: self.truncate,
            create: self.create || self.create_new,
            create_new: self.create_new,
            follow_symlinks: self.follow_symlinks,
        };

        let existed = std::fs::symlink_metadata(path).is_ok();
        let file = platform::open_with(path, &params)?;
        let created = params.create_new || !existed;

        let file = SecureFile::from_parts(file, path.to_path_buf());
        if (created || self.verify_private) && !file.is_private()? {
            return Err(Error::InsecurePermissions);
        }

        Ok(file)
    }
}
