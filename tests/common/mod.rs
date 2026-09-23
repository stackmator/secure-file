#![allow(dead_code)]

use std::path::Path;

/// Relaxes the permissions of a file so tests can exercise the "insecure
/// file" code paths. On Windows the default inherited ACL is already
/// non-owner-only, so nothing needs to be done.
#[cfg(unix)]
pub fn make_insecure_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[cfg(windows)]
pub fn make_insecure_file(_path: &Path) {}

/// Relaxes the permissions of a directory. See [`make_insecure_file`].
#[cfg(unix)]
pub fn make_insecure_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(windows)]
pub fn make_insecure_dir(_path: &Path) {}
