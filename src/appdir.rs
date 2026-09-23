use crate::{Error, Result, SecureDir};
use std::ffi::OsString;
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

fn platform_data_dir() -> Result<PathBuf> {
    platform_data_dir_with(&|key| std::env::var_os(key))
}

#[cfg(windows)]
fn platform_data_dir_with(lookup: &dyn Fn(&str) -> Option<OsString>) -> Result<PathBuf> {
    if let Some(dir) = lookup("LOCALAPPDATA") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    if let Some(profile) = lookup("USERPROFILE") {
        return Ok(PathBuf::from(profile).join("AppData").join("Local"));
    }
    Err(Error::NotFound)
}

#[cfg(target_os = "macos")]
fn platform_data_dir_with(lookup: &dyn Fn(&str) -> Option<OsString>) -> Result<PathBuf> {
    let home = lookup("HOME").ok_or(Error::NotFound)?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_data_dir_with(lookup: &dyn Fn(&str) -> Option<OsString>) -> Result<PathBuf> {
    if let Some(dir) = lookup("XDG_DATA_HOME") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    let home = lookup("HOME").ok_or(Error::NotFound)?;
    Ok(PathBuf::from(home).join(".local").join("share"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup<'a>(entries: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        let map: HashMap<&str, &str> = entries.iter().copied().collect();
        move |key: &str| map.get(key).map(OsString::from)
    }

    #[cfg(windows)]
    #[test]
    fn windows_prefers_localappdata() {
        let env = lookup(&[
            ("LOCALAPPDATA", r"C:\Data"),
            ("USERPROFILE", r"C:\Users\me"),
        ]);
        assert_eq!(
            platform_data_dir_with(&env).unwrap(),
            PathBuf::from(r"C:\Data")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_falls_back_to_userprofile() {
        let env = lookup(&[("USERPROFILE", r"C:\Users\me")]);
        assert_eq!(
            platform_data_dir_with(&env).unwrap(),
            PathBuf::from(r"C:\Users\me").join("AppData").join("Local")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_without_any_env_fails() {
        let env = lookup(&[]);
        assert!(matches!(platform_data_dir_with(&env), Err(Error::NotFound)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_uses_home() {
        let env = lookup(&[("HOME", "/Users/me")]);
        assert_eq!(
            platform_data_dir_with(&env).unwrap(),
            PathBuf::from("/Users/me/Library/Application Support")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_without_home_fails() {
        let env = lookup(&[]);
        assert!(matches!(platform_data_dir_with(&env), Err(Error::NotFound)));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn linux_prefers_xdg_data_home() {
        let env = lookup(&[("XDG_DATA_HOME", "/xdg"), ("HOME", "/home/me")]);
        assert_eq!(platform_data_dir_with(&env).unwrap(), PathBuf::from("/xdg"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn linux_falls_back_to_home() {
        let env = lookup(&[("HOME", "/home/me")]);
        assert_eq!(
            platform_data_dir_with(&env).unwrap(),
            PathBuf::from("/home/me/.local/share")
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn linux_empty_xdg_falls_back_to_home() {
        let env = lookup(&[("XDG_DATA_HOME", ""), ("HOME", "/home/me")]);
        assert_eq!(
            platform_data_dir_with(&env).unwrap(),
            PathBuf::from("/home/me/.local/share")
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn linux_without_any_env_fails() {
        let env = lookup(&[]);
        assert!(matches!(platform_data_dir_with(&env), Err(Error::NotFound)));
    }
}
