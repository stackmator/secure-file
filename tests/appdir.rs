mod common;

use secure_file::Error;

#[test]
fn app_dir_in_creates_private() {
    let base = tempfile::tempdir().unwrap();
    let dir = secure_file::app_dir_in(base.path(), "myapp").unwrap();

    assert_eq!(dir.path(), base.path().join("myapp"));
    assert!(dir.is_private().unwrap());
}

#[test]
fn app_dir_in_reuses_existing_private_dir() {
    let base = tempfile::tempdir().unwrap();
    let first = secure_file::app_dir_in(base.path(), "myapp").unwrap();
    let path = first.path().to_path_buf();
    drop(first);

    let second = secure_file::app_dir_in(base.path(), "myapp").unwrap();
    assert_eq!(second.path(), path);
    assert!(second.is_private().unwrap());
}

#[test]
fn app_dir_in_tightens_insecure_existing_dir() {
    let base = tempfile::tempdir().unwrap();
    let path = base.path().join("myapp");
    std::fs::create_dir(&path).unwrap();
    common::make_insecure_dir(&path);

    let dir = secure_file::app_dir_in(base.path(), "myapp").unwrap();
    assert!(dir.is_private().unwrap());
}

#[test]
fn app_dir_in_creates_missing_base() {
    let parent = tempfile::tempdir().unwrap();
    let base = parent.path().join("nested").join("base");

    let dir = secure_file::app_dir_in(&base, "myapp").unwrap();
    assert_eq!(dir.path(), base.join("myapp"));
    assert!(dir.is_private().unwrap());
}

#[test]
fn app_dir_in_rejects_path_separator() {
    let base = tempfile::tempdir().unwrap();
    let err = secure_file::app_dir_in(base.path(), "a/b").unwrap_err();
    assert!(matches!(err, Error::InvalidInput), "unexpected: {err:?}");
}

#[test]
fn app_dir_in_rejects_parent_dir() {
    let base = tempfile::tempdir().unwrap();
    let err = secure_file::app_dir_in(base.path(), "..").unwrap_err();
    assert!(matches!(err, Error::InvalidInput), "unexpected: {err:?}");
}

#[test]
fn app_dir_in_rejects_absolute_path() {
    let base = tempfile::tempdir().unwrap();
    let err = secure_file::app_dir_in(base.path(), "/etc/evil").unwrap_err();
    assert!(matches!(err, Error::InvalidInput), "unexpected: {err:?}");
}

#[test]
fn app_dir_in_rejects_empty_name() {
    let base = tempfile::tempdir().unwrap();
    let err = secure_file::app_dir_in(base.path(), "").unwrap_err();
    assert!(matches!(err, Error::InvalidInput), "unexpected: {err:?}");
}
