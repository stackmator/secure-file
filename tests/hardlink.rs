mod common;

use secure_file::SecureFile;

fn try_hard_link(original: &std::path::Path, link: &std::path::Path) -> bool {
    std::fs::hard_link(original, link).is_ok()
}

#[test]
fn hard_link_is_opened_as_a_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original");
    secure_file::write_private(&original, b"secret").unwrap();

    let link = dir.path().join("link");
    if !try_hard_link(&original, &link) {
        eprintln!("skipping: hard links not supported here");
        return;
    }

    let mut file = SecureFile::open(&link).unwrap();
    assert!(file.is_private().unwrap());

    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "secret");
}

#[test]
fn tightening_through_a_hard_link_affects_both_names() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original");
    std::fs::write(&original, b"data").unwrap();
    common::make_insecure_file(&original);

    let link = dir.path().join("link");
    if !try_hard_link(&original, &link) {
        eprintln!("skipping: hard links not supported here");
        return;
    }

    // Both names refer to the same inode, so the link is insecure too.
    assert!(!SecureFile::open_unchecked(&link)
        .unwrap()
        .is_private()
        .unwrap());

    // Tightening through one name tightens the shared inode.
    let file = SecureFile::open_unchecked(&original).unwrap();
    file.ensure_private().unwrap();

    assert!(SecureFile::open(&link).unwrap().is_private().unwrap());
}
