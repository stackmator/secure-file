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
fn create_new_is_private_and_writable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");

    let mut file = SecureFile::options()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(file.is_private().unwrap());
    file.write_all(b"secret").unwrap();
    drop(file);

    assert_eq!(secure_file::read_private(&path).unwrap(), b"secret");
}

#[test]
fn create_new_existing_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    secure_file::write_private(&path, b"secret").unwrap();

    let err = SecureFile::options()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap_err();
    assert!(matches!(err, Error::AlreadyExists), "unexpected: {err:?}");
}

#[test]
fn create_rejects_insecure_existing_file_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, b"data").unwrap();
    common::make_insecure_file(&path);

    let err = SecureFile::options()
        .create(true)
        .write(true)
        .open(&path)
        .unwrap_err();
    assert!(
        matches!(err, Error::InsecurePermissions),
        "unexpected: {err:?}"
    );
}

#[test]
fn create_allows_insecure_existing_file_when_verification_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, b"data").unwrap();
    common::make_insecure_file(&path);

    let file = SecureFile::options()
        .create(true)
        .write(true)
        .verify_private(false)
        .open(&path)
        .unwrap();
    assert!(!file.is_private().unwrap());
}

#[test]
fn truncate_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    secure_file::write_private(&path, b"old-data").unwrap();

    let mut file = SecureFile::options()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    file.write_all(b"new").unwrap();
    drop(file);

    assert_eq!(secure_file::read_private(&path).unwrap(), b"new");
}

#[test]
fn append_to_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    secure_file::write_private(&path, b"a").unwrap();

    let mut file = SecureFile::options().append(true).open(&path).unwrap();
    file.write_all(b"b").unwrap();
    drop(file);

    assert_eq!(secure_file::read_private(&path).unwrap(), b"ab");
}

#[test]
fn read_write_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");

    let mut file = SecureFile::options()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.write_all(b"hello").unwrap();
    drop(file);

    let mut file = SecureFile::options().read(true).open(&path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "hello");
}

#[test]
fn open_rejects_symlink_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    secure_file::write_private(&target, b"secret").unwrap();

    let link = dir.path().join("link");
    if !try_symlink_file(&target, &link) {
        eprintln!("skipping: symlink creation not permitted");
        return;
    }

    let err = SecureFile::options().open(&link).unwrap_err();
    assert!(matches!(err, Error::SymlinkDetected), "unexpected: {err:?}");
}

#[test]
fn follow_symlinks_allows_open() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    secure_file::write_private(&target, b"secret").unwrap();

    let link = dir.path().join("link");
    if !try_symlink_file(&target, &link) {
        eprintln!("skipping: symlink creation not permitted");
        return;
    }

    let mut file = SecureFile::options()
        .follow_symlinks(true)
        .open(&link)
        .unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "secret");
}

#[test]
fn options_without_access_mode_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    secure_file::write_private(&path, b"secret").unwrap();

    let err = SecureFile::options()
        .read(false)
        .write(false)
        .open(&path)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidInput), "unexpected: {err:?}");
}

#[test]
fn truncate_without_write_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    secure_file::write_private(&path, b"secret").unwrap();

    let err = SecureFile::options()
        .truncate(true)
        .open(&path)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidInput), "unexpected: {err:?}");
}

#[test]
fn truncate_with_append_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    secure_file::write_private(&path, b"secret").unwrap();

    let err = SecureFile::options()
        .append(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidInput), "unexpected: {err:?}");
}
