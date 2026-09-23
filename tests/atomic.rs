mod common;

use secure_file::{Error, SecureFile};
use std::path::Path;
use std::sync::{Arc, Barrier};

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

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

    assert_eq!(entries(dir.path()), vec!["token".to_string()]);
}

#[test]
fn atomic_write_to_directory_path_fails_and_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("sub");
    std::fs::create_dir(&target).unwrap();

    let err = secure_file::write_private_atomic(&target, b"secret").unwrap_err();
    assert!(!err.to_string().is_empty(), "unexpected: {err:?}");
    assert!(target.is_dir(), "the directory must not be replaced");

    // The temporary file must have been removed on failure.
    assert_eq!(entries(dir.path()), vec!["sub".to_string()]);
}

#[test]
fn atomic_write_rejects_broken_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("dangling");
    if !try_symlink_file(&dir.path().join("missing"), &link) {
        eprintln!("skipping: symlink creation not permitted");
        return;
    }

    let err = secure_file::write_private_atomic(&link, b"secret").unwrap_err();
    assert!(matches!(err, Error::SymlinkDetected), "unexpected: {err:?}");
}

#[test]
fn concurrent_atomic_writes_leave_one_private_file() {
    const THREADS: usize = 8;

    let dir = tempfile::tempdir().unwrap();
    let path = Arc::new(dir.path().join("token"));
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|i| {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                secure_file::write_private_atomic(path.as_ref(), [b'0' + i as u8])
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap().unwrap();
    }

    assert!(SecureFile::open(path.as_ref())
        .unwrap()
        .is_private()
        .unwrap());
    assert_eq!(secure_file::read_private(path.as_ref()).unwrap().len(), 1);
    assert_eq!(entries(dir.path()), vec!["token".to_string()]);
}

#[test]
fn atomic_write_empty_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");

    secure_file::write_private_atomic(&path, b"").unwrap();
    assert_eq!(secure_file::read_private(&path).unwrap(), b"");
}

#[cfg(unix)]
#[test]
fn atomic_write_in_read_only_dir_fails_and_cleans_up() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: running as root bypasses directory permissions");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("read-only");
    std::fs::create_dir(&sub).unwrap();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o500)).unwrap();

    let result = secure_file::write_private_atomic(sub.join("token"), b"secret");

    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();

    let err = result.unwrap_err();
    assert!(
        matches!(err, Error::PermissionDenied),
        "unexpected: {err:?}"
    );
    assert_eq!(entries(&sub), Vec::<String>::new());
}

#[cfg(windows)]
#[test]
fn atomic_write_over_read_only_file_fails_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("token");
    std::fs::write(&target, b"old").unwrap();

    let original = std::fs::metadata(&target).unwrap().permissions();
    let mut readonly = original.clone();
    readonly.set_readonly(true);
    std::fs::set_permissions(&target, readonly).unwrap();

    let result = secure_file::write_private_atomic(&target, b"new");

    std::fs::set_permissions(&target, original).unwrap();

    assert!(result.is_err(), "replacing a read-only file should fail");
    assert_eq!(std::fs::read(&target).unwrap(), b"old");
    assert_eq!(entries(dir.path()), vec!["token".to_string()]);
}
