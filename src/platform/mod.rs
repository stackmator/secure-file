#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::*;

/// Platform-independent description of how to open or create a file.
///
/// This is the internal representation behind [`crate::SecureFileOptions`].
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct OpenParams {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub truncate: bool,
    pub create: bool,
    pub create_new: bool,
    pub follow_symlinks: bool,
}
