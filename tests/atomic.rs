mod common;

use secure_file::{Error, SecureFile};
use std::path::Path;

#[cfg(unix)]
fn try_symlink_file(target: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

#[cfg(windows)]
fn try_symlink_file(target: &Path, link: &Path) -> bool {
    std::os::windows::fs::symlink_file(target, link).is_ok()
}

#[test]
fn atomic_write_creates_private_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");

    secure_file::write_private_atomic(&path, b"secret").unwrap();

    assert!(SecureFile::open(&path).unwrap().is_private().unwrap());
    assert_eq!(secure_file::read_private(&path).unwrap(), b"secret");
}

#[test]
fn atomic_write_replaces_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    secure_file::write_private(&path, b"old").unwrap();

    secure_file::write_private_atomic(&path, b"new").unwrap();

    assert_eq!(secure_file::read_private(&path).unwrap(), b"new");
}

#[test]
fn atomic_write_replaces_insecure_file_with_private_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, b"old").unwrap();
    common::make_insecure_file(&path);

    secure_file::write_private_atomic(&path, b"new").unwrap();

    assert_eq!(secure_file::read_private(&path).unwrap(), b"new");
    assert!(SecureFile::open(&path).unwrap().is_private().unwrap());
}

#[test]
fn atomic_write_rejects_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, b"original").unwrap();

    let link = dir.path().join("link");
    if !try_symlink_file(&target, &link) {
        eprintln!("skipping: symlink creation not permitted");
        return;
    }

    let err = secure_file::write_private_atomic(&link, b"overwritten").unwrap_err();
    assert!(matches!(err, Error::SymlinkDetected), "unexpected: {err:?}");
    assert_eq!(std::fs::read(&target).unwrap(), b"original");
}

#[test]
fn atomic_write_with_missing_parent_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing").join("token");
    assert!(secure_file::write_private_atomic(&path, b"secret").is_err());
}

#[test]
fn atomic_write_leaves_no_temporary_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");

    secure_file::write_private_atomic(&path, b"secret").unwrap();

    let entries: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();

    assert_eq!(entries, vec!["token".to_string()], "entries: {entries:?}");
}

#[test]
fn atomic_write_empty_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");

    secure_file::write_private_atomic(&path, b"").unwrap();
    assert_eq!(secure_file::read_private(&path).unwrap(), b"");
}
