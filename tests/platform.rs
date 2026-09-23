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
    use secure_file::Error;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
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
    fn non_utf8_path_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OsStr::from_bytes(b"secret-\xff\xfe"));

        secure_file::write_private(&path, b"data").unwrap();
        assert_eq!(secure_file::read_private(&path).unwrap(), b"data");
    }
}

#[cfg(windows)]
mod windows {
    use super::*;

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
}
