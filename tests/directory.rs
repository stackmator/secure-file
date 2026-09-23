mod common;

use secure_file::{Error, SecureDir, SecureFile};

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
    assert!(matches!(err, Error::AlreadyExists), "unexpected: {err:?}");
}

#[test]
fn create_dir_with_missing_parent_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing").join("child");
    let err = SecureDir::create(&path).unwrap_err();
    assert!(matches!(err, Error::NotFound), "unexpected: {err:?}");
}

#[test]
fn create_dir_where_file_exists_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file");
    std::fs::write(&path, b"data").unwrap();

    let err = SecureDir::create(&path).unwrap_err();
    assert!(matches!(err, Error::AlreadyExists), "unexpected: {err:?}");
}

#[test]
fn open_missing_dir_fails() {
    let dir = tempfile::tempdir().unwrap();
    assert!(SecureDir::open(dir.path().join("missing")).is_err());
}

#[test]
fn open_unchecked_missing_dir_fails() {
    let dir = tempfile::tempdir().unwrap();
    assert!(SecureDir::open_unchecked(dir.path().join("missing")).is_err());
}

#[test]
fn open_rejects_insecure_dir() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private");
    std::fs::create_dir(&path).unwrap();
    common::make_insecure_dir(&path);

    let err = SecureDir::open(&path).unwrap_err();
    assert!(
        matches!(err, Error::InsecurePermissions),
        "unexpected: {err:?}"
    );
}

#[test]
fn open_rejecting_insecure_dir_does_not_modify_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private");
    std::fs::create_dir(&path).unwrap();
    common::make_insecure_dir(&path);

    let before = dir_mode(&path);
    assert!(SecureDir::open(&path).is_err());
    assert_eq!(dir_mode(&path), before);
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
    assert!(SecureFile::open_unchecked(&path).is_err());
}

#[test]
fn create_dir_free_function() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private");

    let secure = secure_file::create_dir(&path).unwrap();
    assert!(secure.is_private().unwrap());
}

#[test]
fn create_nested_inside_secure_dir() {
    let dir = tempfile::tempdir().unwrap();
    let outer = SecureDir::create(dir.path().join("outer")).unwrap();
    let inner = SecureDir::create(outer.path().join("inner")).unwrap();

    assert!(inner.is_private().unwrap());
    let file = SecureFile::create(inner.path().join("secret")).unwrap();
    assert!(file.is_private().unwrap());
}

#[cfg(unix)]
fn dir_mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(windows)]
fn dir_mode(_path: &std::path::Path) -> u32 {
    0
}
