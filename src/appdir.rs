use crate::{Error, Result, SecureDir};
use std::path::{Component, Path, PathBuf};

/// Returns the platform's per-user application data directory, creating it if
/// necessary.
///
/// This is `%LOCALAPPDATA%` on Windows, `~/Library/Application Support` on
/// macOS, and `$XDG_DATA_HOME` (or `~/.local/share`) elsewhere.
pub fn app_data_dir() -> Result<PathBuf> {
    let base = platform_data_dir()?;
    std::fs::create_dir_all(&base)?;
    Ok(base)
}

/// Creates (or opens and tightens) an owner-only directory for `name` inside
/// the platform's application data directory.
///
/// `name` must be a single path component; it may not be absolute or contain
/// `..`.
///
/// ```no_run
/// # fn main() -> secure_file::Result<()> {
/// let dir = secure_file::app_dir("myapp")?;
/// # Ok(())
/// # }
/// ```
pub fn app_dir<N: AsRef<Path>>(name: N) -> Result<SecureDir> {
    app_dir_in(platform_data_dir()?, name)
}

/// Creates (or opens and tightens) an owner-only directory for `name` inside
/// `base`.
///
/// This is the explicit-base variant of [`app_dir`], useful for tests or for
/// applications that manage their own base directory.
pub fn app_dir_in<B: AsRef<Path>, N: AsRef<Path>>(base: B, name: N) -> Result<SecureDir> {
    let name = name.as_ref();
    validate_name(name)?;

    let base = base.as_ref();
    std::fs::create_dir_all(base)?;

    let path = base.join(name);
    match SecureDir::create(&path) {
        Ok(dir) => Ok(dir),
        Err(Error::AlreadyExists) => SecureDir::open_unchecked(&path)?.ensure_private(),
        Err(err) => Err(err),
    }
}

fn validate_name(name: &Path) -> Result<()> {
    let mut components = name.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(Error::InvalidInput),
    }
}

#[cfg(windows)]
fn platform_data_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(profile).join("AppData").join("Local"));
    }
    Err(Error::NotFound)
}

#[cfg(target_os = "macos")]
fn platform_data_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or(Error::NotFound)?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_data_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    let home = std::env::var_os("HOME").ok_or(Error::NotFound)?;
    Ok(PathBuf::from(home).join(".local").join("share"))
}
