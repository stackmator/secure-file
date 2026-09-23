use secure_file::{Error, SecureDir, SecureFile};
use std::path::Path;

#[cfg(unix)]
fn try_symlink_file(target: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

#[cfg(windows)]
fn try_symlink_file(target: &Path, link: &Path) -> bool {
    std::os::windows::fs::symlink_file(target, link).is_ok()
}

#[cfg(unix)]
fn try_symlink_dir(target: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

#[cfg(windows)]
fn try_symlink_dir(target: &Path, link: &Path) -> bool {
    std::os::windows::fs::symlink_dir(target, link).is_ok()
}

fn skip() -> bool {
    eprintln!("skipping: symlink creation not permitted on this host");
    true
}

#[test]
fn create_does_not_follow_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, b"original").unwrap();

    let link = dir.path().join("link");
    if !try_symlink_file(&target, &link) {
        skip();
        return;
    }

    let err = SecureFile::create(&link).unwrap_err();
    assert!(
        matches!(err, Error::AlreadyExists | Error::SymlinkDetected),
        "unexpected error: {err:?}"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"original");
}

#[test]
fn create_does_not_create_symlink_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("missing-target");

    let link = dir.path().join("link");
    if !try_symlink_file(&target, &link) {
        skip();
        return;
    }

    let _ = SecureFile::create(&link);
    assert!(
        !target.exists(),
        "create must not write through the symlink"
    );
}

#[test]
fn open_rejects_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    secure_file::write_private(&target, b"secret").unwrap();

    let link = dir.path().join("link");
    if !try_symlink_file(&target, &link) {
        skip();
        return;
    }

    let err = SecureFile::open_unchecked(&link).unwrap_err();
    assert!(
        matches!(err, Error::SymlinkDetected),
        "unexpected error: {err:?}"
    );
}

#[test]
fn read_private_rejects_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    secure_file::write_private(&target, b"secret").unwrap();

    let link = dir.path().join("link");
    if !try_symlink_file(&target, &link) {
        skip();
        return;
    }

    let err = secure_file::read_private(&link).unwrap_err();
    assert!(
        matches!(err, Error::SymlinkDetected),
        "unexpected error: {err:?}"
    );
}

#[test]
fn write_private_rejects_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, b"original").unwrap();

    let link = dir.path().join("link");
    if !try_symlink_file(&target, &link) {
        skip();
        return;
    }

    let err = secure_file::write_private(&link, b"overwritten").unwrap_err();
    assert!(
        matches!(err, Error::AlreadyExists | Error::SymlinkDetected),
        "unexpected error: {err:?}"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"original");
}

#[test]
fn broken_symlink_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("dangling");
    if !try_symlink_file(&dir.path().join("missing"), &link) {
        skip();
        return;
    }

    let err = SecureFile::open_unchecked(&link).unwrap_err();
    assert!(
        matches!(err, Error::SymlinkDetected),
        "unexpected error: {err:?}"
    );
}

#[test]
fn dir_symlink_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    secure_file::create_dir(&real).unwrap();

    let link = dir.path().join("link");
    if !try_symlink_dir(&real, &link) {
        skip();
        return;
    }

    let err = SecureDir::open_unchecked(&link).unwrap_err();
    assert!(
        matches!(err, Error::SymlinkDetected),
        "unexpected error: {err:?}"
    );
}

#[test]
fn create_dir_on_symlink_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    secure_file::create_dir(&real).unwrap();

    let link = dir.path().join("link");
    if !try_symlink_dir(&real, &link) {
        skip();
        return;
    }

    let err = secure_file::create_dir(&link).unwrap_err();
    assert!(
        matches!(err, Error::AlreadyExists | Error::SymlinkDetected),
        "unexpected error: {err:?}"
    );
}
