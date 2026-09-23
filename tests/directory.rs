mod common;

use secure_file::{Error, SecureDir};

#[test]
fn create_dir_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private");

    let secure = SecureDir::create(&path).unwrap();
    assert!(path.is_dir());
    assert!(secure.is_private().unwrap());
}

#[test]
fn create_existing_dir_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private");

    let _ = SecureDir::create(&path).unwrap();
    let err = SecureDir::create(&path).unwrap_err();
    assert!(matches!(err, Error::AlreadyExists));
}

#[test]
fn open_missing_dir_fails() {
    let dir = tempfile::tempdir().unwrap();
    assert!(SecureDir::open(dir.path().join("missing")).is_err());
}

#[test]
fn open_rejects_insecure_dir() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private");
    std::fs::create_dir(&path).unwrap();
    common::make_insecure_dir(&path);

    let err = SecureDir::open(&path).unwrap_err();
    assert!(matches!(err, Error::InsecurePermissions));
}

#[test]
fn ensure_private_tightens_existing_dir() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private");
    std::fs::create_dir(&path).unwrap();
    common::make_insecure_dir(&path);

    let secure = SecureDir::open_unchecked(&path).unwrap();
    assert!(!secure.is_private().unwrap());

    let secure = secure.ensure_private().unwrap();
    assert!(secure.is_private().unwrap());
    assert!(SecureDir::open(&path).is_ok());
}

#[test]
fn open_file_as_dir_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file");
    std::fs::write(&path, b"data").unwrap();
    assert!(SecureDir::open_unchecked(&path).is_err());
}

#[test]
fn open_dir_as_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("directory");
    std::fs::create_dir(&path).unwrap();
    assert!(secure_file::SecureFile::open_unchecked(&path).is_err());
}

#[test]
fn create_dir_free_function() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private");

    let secure = secure_file::create_dir(&path).unwrap();
    assert!(secure.is_private().unwrap());
}
