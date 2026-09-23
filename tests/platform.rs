use secure_file::SecureFile;

#[test]
fn overlong_filename_errors_without_panicking() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a".repeat(300));

    let err = SecureFile::create(&path).unwrap_err();
    assert!(!err.to_string().is_empty(), "unexpected: {err:?}");
}

#[cfg(unix)]
mod unix {
    use super::*;
    use secure_file::{Error, SecureDir};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn create_in_unwritable_dir_is_denied() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root bypasses directory permissions");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("read-only");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = SecureFile::create(sub.join("secret"));

        // Restore so the temporary directory can be cleaned up.
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();

        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::PermissionDenied),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn opening_unreadable_file_is_denied() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root bypasses file permissions");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        secure_file::write_private(&path, b"data").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = SecureFile::open_unchecked(&path);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::PermissionDenied),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn opening_unreadable_dir_is_denied() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root bypasses directory permissions");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("locked");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = SecureDir::open_unchecked(&sub);

        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();

        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::PermissionDenied),
            "unexpected: {err:?}"
        );
    }

    // Linux permits arbitrary bytes in filenames; macOS requires valid UTF-8,
    // so this is only meaningful on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_path_round_trip() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OsStr::from_bytes(b"secret-\xff\xfe"));

        secure_file::write_private(&path, b"data").unwrap();
        assert_eq!(secure_file::read_private(&path).unwrap(), b"data");
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn deeply_nested_path_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let mut path = dir.path().to_path_buf();
        for i in 0..40 {
            path.push(format!("segment-{i:02}"));
        }

        // Long-path support may or may not be enabled; either way the call must
        // return a normal error rather than panicking.
        let _ = SecureFile::create(&path);
    }

    #[test]
    fn extended_length_path_over_max_path_works() {
        let dir = tempfile::tempdir().unwrap();

        // `\\?\` opts into extended-length paths, bypassing MAX_PATH.
        let mut extended = PathBuf::from(format!(r"\\?\{}", dir.path().display()));
        while extended.as_os_str().len() < 320 {
            extended.push("segment-0123456789");
        }

        std::fs::create_dir_all(&extended).unwrap();
        let target = extended.join("token");

        secure_file::write_private(&target, b"secret").unwrap();
        assert_eq!(secure_file::read_private(&target).unwrap(), b"secret");
        assert!(SecureFile::open(&target).unwrap().is_private().unwrap());
    }
}
