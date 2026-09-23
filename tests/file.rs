mod common;

use secure_file::{Error, SecureFile};

#[test]
fn create_is_private_and_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.txt");

    let mut file = SecureFile::create(&path).unwrap();
    assert!(file.is_private().unwrap());
    file.write_all(b"hello").unwrap();
    drop(file);

    let mut file = SecureFile::open(&path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "hello");
}

#[test]
fn create_existing_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.txt");

    let _ = SecureFile::create(&path).unwrap();
    let err = SecureFile::create(&path).unwrap_err();
    assert!(matches!(err, Error::AlreadyExists));
}

#[test]
fn open_missing_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.txt");
    assert!(SecureFile::open(&path).is_err());
}

#[test]
fn open_rejects_insecure_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, b"data").unwrap();
    common::make_insecure_file(&path);

    let err = SecureFile::open(&path).unwrap_err();
    assert!(matches!(err, Error::InsecurePermissions));
}

#[test]
fn ensure_private_tightens_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, b"data").unwrap();
    common::make_insecure_file(&path);

    let file = SecureFile::open_unchecked(&path).unwrap();
    assert!(!file.is_private().unwrap());

    let file = file.ensure_private().unwrap();
    assert!(file.is_private().unwrap());
    assert!(SecureFile::open(&path).is_ok());
}

#[test]
fn write_private_then_read_private() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");

    secure_file::write_private(&path, b"secret").unwrap();
    assert!(SecureFile::open(&path).unwrap().is_private().unwrap());
    assert_eq!(secure_file::read_private(&path).unwrap(), b"secret");

    secure_file::write_private(&path, b"updated").unwrap();
    assert_eq!(secure_file::read_private(&path).unwrap(), b"updated");
}

#[test]
fn read_private_rejects_insecure_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, b"secret").unwrap();
    common::make_insecure_file(&path);

    assert!(matches!(
        secure_file::read_private(&path).unwrap_err(),
        Error::InsecurePermissions
    ));
}

#[test]
fn unicode_path_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sécret-日本語-🔐.txt");

    secure_file::write_private(&path, b"secret").unwrap();
    assert_eq!(secure_file::read_private(&path).unwrap(), b"secret");
}
