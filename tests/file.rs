mod common;

use secure_file::{Error, SecureFile};
use std::io::{Seek, SeekFrom};

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
    assert!(matches!(err, Error::AlreadyExists), "unexpected: {err:?}");
}

#[test]
fn create_with_missing_parent_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing").join("secret.txt");
    let err = SecureFile::create(&path).unwrap_err();
    assert!(matches!(err, Error::Io(_)), "unexpected: {err:?}");
}

#[test]
fn create_when_parent_is_a_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, b"x").unwrap();

    let err = SecureFile::create(file.join("child")).unwrap_err();
    assert!(matches!(err, Error::Io(_)), "unexpected: {err:?}");
}

#[test]
fn create_with_empty_path_fails() {
    let err = SecureFile::create("").unwrap_err();
    assert!(matches!(err, Error::Io(_)), "unexpected: {err:?}");
}

#[test]
fn open_missing_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.txt");
    assert!(SecureFile::open(&path).is_err());
}

#[test]
fn open_unchecked_missing_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.txt");
    assert!(SecureFile::open_unchecked(&path).is_err());
}

#[test]
fn open_write_missing_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.txt");
    assert!(SecureFile::open_write(&path).is_err());
}

#[test]
fn open_rejects_insecure_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, b"data").unwrap();
    common::make_insecure_file(&path);

    let err = SecureFile::open(&path).unwrap_err();
    assert!(
        matches!(err, Error::InsecurePermissions),
        "unexpected: {err:?}"
    );
}

#[test]
fn open_rejecting_insecure_file_does_not_modify_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, b"data").unwrap();
    common::make_insecure_file(&path);

    assert!(SecureFile::open(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"data");
    let file = SecureFile::open_unchecked(&path).unwrap();
    assert!(!file.permissions().unwrap().owner_only);
}

#[test]
fn open_read_only_cannot_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.txt");
    let _ = SecureFile::create(&path).unwrap();

    let mut file = SecureFile::open(&path).unwrap();
    assert!(file.write_all(b"nope").is_err());
}

#[test]
fn open_write_accepts_insecure_file_without_verifying() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, b"data").unwrap();
    common::make_insecure_file(&path);

    let file = SecureFile::open_write(&path).unwrap();
    assert!(!file.is_private().unwrap());
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
fn write_private_tightens_insecure_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, b"old").unwrap();
    common::make_insecure_file(&path);

    secure_file::write_private(&path, b"new").unwrap();

    assert_eq!(secure_file::read_private(&path).unwrap(), b"new");
    assert!(SecureFile::open(&path).unwrap().is_private().unwrap());
}

#[test]
fn write_private_with_missing_parent_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing").join("token");
    assert!(secure_file::write_private(&path, b"secret").is_err());
}

#[test]
fn write_private_to_directory_path_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("directory");
    std::fs::create_dir(&path).unwrap();

    assert!(secure_file::write_private(&path, b"secret").is_err());
}

#[test]
fn read_private_missing_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing");
    assert!(secure_file::read_private(&path).is_err());
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
fn read_private_on_directory_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("directory");
    std::fs::create_dir(&path).unwrap();

    assert!(secure_file::read_private(&path).is_err());
}

#[test]
fn empty_data_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty");
    secure_file::write_private(&path, b"").unwrap();
    assert_eq!(secure_file::read_private(&path).unwrap(), b"");
}

#[test]
fn large_data_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large");
    let data = vec![0xABu8; 1024 * 1024];

    secure_file::write_private(&path, &data).unwrap();
    assert_eq!(secure_file::read_private(&path).unwrap(), data);
}

#[test]
fn seek_and_truncate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("seek");

    let mut file = SecureFile::create(&path).unwrap();
    file.write_all(b"hello world").unwrap();
    file.set_len(5).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();

    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "hello");
}

#[test]
fn unicode_path_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sécret-日本語-🔐.txt");

    secure_file::write_private(&path, b"secret").unwrap();
    assert_eq!(secure_file::read_private(&path).unwrap(), b"secret");
}
