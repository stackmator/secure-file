//! Tests that need CI-prepared filesystems. Each test is skipped unless the
//! corresponding environment variable is set, so the normal test jobs ignore
//! them. The `mount-dependent` CI job creates the mounts and sets the
//! variables.

use secure_file::{SecureFile, SecureTempFile};
use std::path::PathBuf;

fn read_only_dir() -> Option<PathBuf> {
    std::env::var_os("SECURE_FILE_RO_DIR").map(PathBuf::from)
}

fn second_volume_dir() -> Option<PathBuf> {
    std::env::var_os("SECURE_FILE_CROSS_DIR").map(PathBuf::from)
}

#[test]
fn create_on_read_only_filesystem_fails() {
    let Some(dir) = read_only_dir() else {
        eprintln!("skipping: SECURE_FILE_RO_DIR not set");
        return;
    };

    let target = dir.join("token");

    let err = SecureFile::create(&target).unwrap_err();
    assert!(!err.to_string().is_empty(), "unexpected: {err:?}");
    assert!(!target.exists());

    let err = secure_file::write_private_atomic(&target, b"secret").unwrap_err();
    assert!(!err.to_string().is_empty(), "unexpected: {err:?}");
    assert!(!target.exists());
}

#[test]
fn persist_across_volumes_fails_cleanly() {
    let Some(cross) = second_volume_dir() else {
        eprintln!("skipping: SECURE_FILE_CROSS_DIR not set");
        return;
    };

    // A temporary file on the default volume, moved onto the second volume.
    let temp = SecureTempFile::new().unwrap();
    let temporary = temp.path().to_path_buf();
    let target = cross.join("token-across-volumes");

    let err = temp.persist(&target).unwrap_err();
    assert!(!err.to_string().is_empty(), "unexpected: {err:?}");
    assert!(!target.exists());
    assert!(!temporary.exists(), "temporary file should be cleaned up");
}

#[test]
fn persist_within_the_second_volume_succeeds() {
    let Some(cross) = second_volume_dir() else {
        eprintln!("skipping: SECURE_FILE_CROSS_DIR not set");
        return;
    };

    let mut temp = SecureTempFile::new_in(&cross).unwrap();
    temp.write_all(b"data").unwrap();

    let target = cross.join("token-same-volume");
    temp.persist(&target).unwrap();

    assert_eq!(secure_file::read_private(&target).unwrap(), b"data");
}
