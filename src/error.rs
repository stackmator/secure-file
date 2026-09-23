use std::fmt;
use std::io;

/// The error type for `secure-file`.
#[derive(Debug)]
pub enum Error {
    /// A wrapped operating-system error that has no more specific mapping.
    Io(io::Error),
    /// The operation was denied by the operating system.
    PermissionDenied,
    /// The file or directory exists but its permissions allow access by
    /// parties other than the owner.
    InsecurePermissions,
    /// A symbolic link (or Windows reparse point) was found where a regular
    /// file or directory was required.
    SymlinkDetected,
    /// The target already exists and exclusive creation was requested.
    AlreadyExists,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "{err}"),
            Error::PermissionDenied => write!(f, "permission denied"),
            Error::InsecurePermissions => {
                write!(f, "file or directory is accessible by other users")
            }
            Error::SymlinkDetected => write!(f, "symbolic link detected"),
            Error::AlreadyExists => write!(f, "file or directory already exists"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        #[cfg(unix)]
        if let Some(code) = err.raw_os_error() {
            if code == libc::ELOOP {
                return Error::SymlinkDetected;
            }
        }

        match err.kind() {
            io::ErrorKind::AlreadyExists => Error::AlreadyExists,
            io::ErrorKind::PermissionDenied => Error::PermissionDenied,
            _ => Error::Io(err),
        }
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Io(err) => err,
            Error::PermissionDenied => {
                io::Error::new(io::ErrorKind::PermissionDenied, "permission denied")
            }
            Error::InsecurePermissions => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file or directory is accessible by other users",
            ),
            Error::SymlinkDetected => io::Error::other("symbolic link detected"),
            Error::AlreadyExists => io::Error::new(io::ErrorKind::AlreadyExists, "already exists"),
        }
    }
}

/// A specialized `Result` type for `secure-file`.
pub type Result<T> = std::result::Result<T, Error>;
