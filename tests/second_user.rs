//! Tests that need a genuine second operating-system user. They are skipped
//! unless `SECURE_FILE_OTHER_USER` names an existing user that the current
//! process can run commands as via `sudo -n -u`. The `second-user` CI job
//! creates that user.

#![cfg(unix)]

use secure_file::{Error, SecureFile};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn other_user() -> Option<String> {
    std::env::var("SECURE_FILE_OTHER_USER").ok()
}

/// A world-writable (non-sticky) directory so either user can create entries,
/// while the owner (us) can still clean everything up.
fn shared_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    dir
}

fn can_sudo_as(user: &str) -> bool {
    Command::new("sudo")
        .args(["-n", "-u", user, "true"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Runs `sh -c <script> sh <path>` as `user`; `$1` is the path.
fn run_as(user: &str, script: &str, path: &Path) -> std::process::Output {
    Command::new("sudo")
        .args(["-n", "-u", user, "sh", "-c", script, "sh"])
        .arg(path)
        .output()
        .expect("failed to run sudo")
}

#[test]
fn other_user_cannot_read_our_private_file() {
    let Some(user) = other_user() else {
        eprintln!("skipping: SECURE_FILE_OTHER_USER not set");
        return;
    };
    if !can_sudo_as(&user) {
        eprintln!("skipping: cannot run commands as {user}");
        return;
    }

    let dir = shared_dir();
    let path = dir.path().join("private");
    secure_file::write_private(&path, b"secret").unwrap();

    let output = run_as(&user, "cat \"$1\"", &path);
    assert!(
        !output.status.success(),
        "another user must not be able to read a private file"
    );

    // Sanity check: the owner can still read it.
    assert_eq!(secure_file::read_private(&path).unwrap(), b"secret");
}

#[test]
fn our_api_denies_another_users_private_file() {
    let Some(user) = other_user() else {
        eprintln!("skipping: SECURE_FILE_OTHER_USER not set");
        return;
    };
    if !can_sudo_as(&user) {
        eprintln!("skipping: cannot run commands as {user}");
        return;
    }

    let dir = shared_dir();
    let path = dir.path().join("other-private");
    let output = run_as(&user, "umask 077; printf secret > \"$1\"", &path);
    assert!(
        output.status.success(),
        "failed to create the other user's file"
    );

    let err = SecureFile::open_unchecked(&path).unwrap_err();
    assert!(
        matches!(err, Error::PermissionDenied),
        "unexpected: {err:?}"
    );

    let err = secure_file::read_private(&path).unwrap_err();
    assert!(
        matches!(err, Error::PermissionDenied),
        "unexpected: {err:?}"
    );
}

#[test]
fn another_users_world_readable_file_is_not_private() {
    let Some(user) = other_user() else {
        eprintln!("skipping: SECURE_FILE_OTHER_USER not set");
        return;
    };
    if !can_sudo_as(&user) {
        eprintln!("skipping: cannot run commands as {user}");
        return;
    }

    let dir = shared_dir();
    let path = dir.path().join("other-readable");
    let output = run_as(&user, "umask 022; printf data > \"$1\"", &path);
    assert!(
        output.status.success(),
        "failed to create the other user's file"
    );

    let file = SecureFile::open_unchecked(&path).unwrap();
    assert!(
        !file.is_private().unwrap(),
        "a world-readable file owned by another user is not private"
    );
}
