mod common;

use secure_file::SecureFile;

#[test]
fn created_file_reports_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f");

    let file = SecureFile::create(&path).unwrap();
    let permissions = file.permissions().unwrap();
    assert!(permissions.owner_only);
    assert!(permissions.is_owner_only());
}

#[test]
fn created_file_owner_can_read_and_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f");

    let file = SecureFile::create(&path).unwrap();
    let permissions = file.permissions().unwrap();
    assert!(permissions.owner_read);
    assert!(permissions.owner_write);
}

#[test]
fn created_dir_owner_can_execute() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("d");

    let secure = secure_file::create_dir(&path).unwrap();
    let permissions = secure.permissions().unwrap();
    assert!(permissions.owner_read);
    assert!(permissions.owner_write);
    assert!(permissions.owner_execute);
}

#[test]
fn insecure_file_reports_not_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f");
    std::fs::write(&path, b"data").unwrap();
    common::make_insecure_file(&path);

    let file = SecureFile::open_unchecked(&path).unwrap();
    assert!(!file.permissions().unwrap().owner_only);
}

#[test]
fn created_dir_reports_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("d");

    let secure = secure_file::create_dir(&path).unwrap();
    assert!(secure.permissions().unwrap().owner_only);
}

#[test]
fn insecure_dir_reports_not_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("d");
    std::fs::create_dir(&path).unwrap();
    common::make_insecure_dir(&path);

    let secure = secure_file::SecureDir::open_unchecked(&path).unwrap();
    assert!(!secure.permissions().unwrap().owner_only);
}

#[cfg(unix)]
#[test]
fn unix_created_file_is_mode_600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f");
    let _ = SecureFile::create(&path).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[cfg(unix)]
#[test]
fn unix_created_dir_is_mode_700() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("d");
    let _ = secure_file::create_dir(&path).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}
