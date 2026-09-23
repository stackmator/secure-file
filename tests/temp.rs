mod common;

use secure_file::{SecureTempDir, SecureTempFile};
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
fn temp_file_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let file = SecureTempFile::new_in(dir.path()).unwrap();

    assert!(file.is_private().unwrap());
    assert!(file.path().starts_with(dir.path()));
}

#[test]
fn temp_file_write_read() {
    let dir = tempfile::tempdir().unwrap();
    let mut file = SecureTempFile::new_in(dir.path()).unwrap();
    file.write_all(b"hello").unwrap();
    file.sync_all().unwrap();

    assert_eq!(secure_file::read_private(file.path()).unwrap(), b"hello");
}

#[test]
fn temp_file_deleted_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let path;
    {
        let file = SecureTempFile::new_in(dir.path()).unwrap();
        path = file.path().to_path_buf();
        assert!(path.exists());
    }
    assert!(!path.exists(), "temporary file should be removed on drop");
}

#[test]
fn temp_file_keep_persists() {
    let dir = tempfile::tempdir().unwrap();
    let file = SecureTempFile::new_in(dir.path()).unwrap();
    let path = file.keep();

    assert!(path.exists(), "kept temporary file should remain");
}

#[test]
fn temp_file_persist_moves() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("final");

    let mut file = SecureTempFile::new_in(dir.path()).unwrap();
    file.write_all(b"data").unwrap();
    let temporary = file.path().to_path_buf();

    let result = file.persist(&target).unwrap();

    assert_eq!(result, target);
    assert!(!temporary.exists());
    assert_eq!(std::fs::read(&target).unwrap(), b"data");
    assert!(secure_file::SecureFile::open(&target)
        .unwrap()
        .is_private()
        .unwrap());
}

#[test]
fn temp_file_persist_replaces_existing() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("final");
    std::fs::write(&target, b"old").unwrap();

    let mut file = SecureTempFile::new_in(dir.path()).unwrap();
    file.write_all(b"new").unwrap();
    file.persist(&target).unwrap();

    assert_eq!(std::fs::read(&target).unwrap(), b"new");
    assert!(secure_file::SecureFile::open(&target)
        .unwrap()
        .is_private()
        .unwrap());
}

#[test]
fn temp_file_new_in_missing_dir_fails() {
    let dir = tempfile::tempdir().unwrap();
    assert!(SecureTempFile::new_in(dir.path().join("missing")).is_err());
}

#[test]
fn temp_file_persist_replaces_symlink_destination() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, b"original").unwrap();

    let link = dir.path().join("link");
    if !try_symlink_file(&target, &link) {
        eprintln!("skipping: symlink creation not permitted");
        return;
    }

    let mut file = SecureTempFile::new_in(dir.path()).unwrap();
    file.write_all(b"new").unwrap();
    file.persist(&link).unwrap();

    // The link itself is replaced; the link's target is untouched.
    assert_eq!(std::fs::read(&target).unwrap(), b"original");
    assert_eq!(std::fs::read(&link).unwrap(), b"new");
    assert!(!std::fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn temp_files_have_unique_paths() {
    let dir = tempfile::tempdir().unwrap();
    let a = SecureTempFile::new_in(dir.path()).unwrap();
    let b = SecureTempFile::new_in(dir.path()).unwrap();

    assert_ne!(a.path(), b.path());
}

#[test]
fn temp_file_new_uses_system_temp() {
    let file = SecureTempFile::new().unwrap();
    assert!(file.is_private().unwrap());
}

#[test]
fn concurrent_temp_files_are_unique() {
    use std::sync::{Arc, Barrier};

    const THREADS: usize = 16;

    let dir = tempfile::tempdir().unwrap();
    let base = Arc::new(dir.path().to_path_buf());
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let base = Arc::clone(&base);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                SecureTempFile::new_in(base.as_path())
                    .unwrap()
                    .path()
                    .to_path_buf()
            })
        })
        .collect();

    let mut paths: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    paths.sort();
    paths.dedup();

    assert_eq!(paths.len(), THREADS);
}

#[test]
fn temp_dir_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let temp = SecureTempDir::new_in(dir.path()).unwrap();

    assert!(temp.path().is_dir());
    assert!(secure_file::SecureDir::open(temp.path())
        .unwrap()
        .is_private()
        .unwrap());
}

#[test]
fn temp_dir_deleted_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let path;
    {
        let temp = SecureTempDir::new_in(dir.path()).unwrap();
        path = temp.path().to_path_buf();
        assert!(path.exists());
    }
    assert!(
        !path.exists(),
        "temporary directory should be removed on drop"
    );
}

#[test]
fn temp_dir_removes_contents_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let path;
    {
        let temp = SecureTempDir::new_in(dir.path()).unwrap();
        path = temp.path().to_path_buf();
        secure_file::write_private(path.join("file"), b"data").unwrap();
    }
    assert!(!path.exists());
}

#[test]
fn temp_dir_keep_persists() {
    let dir = tempfile::tempdir().unwrap();
    let temp = SecureTempDir::new_in(dir.path()).unwrap();
    let path = temp.keep();

    assert!(path.exists(), "kept temporary directory should remain");
}

#[test]
fn temp_dir_new_in_missing_parent_fails() {
    let dir = tempfile::tempdir().unwrap();
    assert!(SecureTempDir::new_in(dir.path().join("missing")).is_err());
}
