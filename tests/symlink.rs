use secure_file::{Error, SecureFile};

#[cfg(unix)]
mod unix {
    use super::*;
    use secure_file::SecureDir;
    use std::os::unix::fs::symlink;

    #[test]
    fn create_does_not_follow_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"original").unwrap();

        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();

        let err = SecureFile::create(&link).unwrap_err();
        assert!(matches!(err, Error::AlreadyExists | Error::SymlinkDetected));
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
    }

    #[test]
    fn open_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        secure_file::write_private(&target, b"secret").unwrap();

        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();

        let err = SecureFile::open_unchecked(&link).unwrap_err();
        assert!(matches!(err, Error::SymlinkDetected));
    }

    #[test]
    fn broken_symlink_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("dangling");
        symlink(dir.path().join("missing"), &link).unwrap();

        let err = SecureFile::open_unchecked(&link).unwrap_err();
        assert!(matches!(err, Error::SymlinkDetected));
    }

    #[test]
    fn dir_symlink_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        secure_file::create_dir(&real).unwrap();

        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();

        let err = SecureDir::open_unchecked(&link).unwrap_err();
        assert!(matches!(err, Error::SymlinkDetected));
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::fs::symlink_file;
    use std::path::Path;

    fn try_symlink(target: &Path, link: &Path) -> bool {
        symlink_file(target, link).is_ok()
    }

    #[test]
    fn create_does_not_follow_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"original").unwrap();

        let link = dir.path().join("link");
        if !try_symlink(&target, &link) {
            eprintln!("skipping: symlink creation not permitted");
            return;
        }

        let err = SecureFile::create(&link).unwrap_err();
        assert!(matches!(err, Error::AlreadyExists | Error::SymlinkDetected));
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
    }

    #[test]
    fn open_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        secure_file::write_private(&target, b"secret").unwrap();

        let link = dir.path().join("link");
        if !try_symlink(&target, &link) {
            eprintln!("skipping: symlink creation not permitted");
            return;
        }

        let err = SecureFile::open_unchecked(&link).unwrap_err();
        assert!(matches!(err, Error::SymlinkDetected));
    }
}
