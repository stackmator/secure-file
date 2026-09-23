use secure_file::Error;
use std::error::Error as StdError;
use std::io::{self, ErrorKind};

#[test]
fn display_messages_are_non_empty() {
    let variants = [
        Error::Io(io::Error::other("boom")),
        Error::PermissionDenied,
        Error::InsecurePermissions,
        Error::SymlinkDetected,
        Error::AlreadyExists,
    ];

    for err in variants {
        assert!(!err.to_string().is_empty(), "empty display for {err:?}");
    }
}

#[test]
fn source_is_only_set_for_io() {
    let io_err = Error::Io(io::Error::other("boom"));
    assert!(io_err.source().is_some());

    assert!(Error::PermissionDenied.source().is_none());
    assert!(Error::InsecurePermissions.source().is_none());
    assert!(Error::SymlinkDetected.source().is_none());
    assert!(Error::AlreadyExists.source().is_none());
}

#[test]
fn io_error_kinds_map_to_specific_variants() {
    let already = Error::from(io::Error::new(ErrorKind::AlreadyExists, "x"));
    assert!(matches!(already, Error::AlreadyExists));

    let denied = Error::from(io::Error::new(ErrorKind::PermissionDenied, "x"));
    assert!(matches!(denied, Error::PermissionDenied));

    let missing = Error::from(io::Error::new(ErrorKind::NotFound, "x"));
    assert!(matches!(missing, Error::Io(_)));
}

#[test]
fn error_converts_back_to_io_error() {
    assert_eq!(
        io::Error::from(Error::AlreadyExists).kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        io::Error::from(Error::PermissionDenied).kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        io::Error::from(Error::InsecurePermissions).kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        io::Error::from(Error::SymlinkDetected).kind(),
        ErrorKind::Other
    );

    let io_err = io::Error::new(ErrorKind::NotFound, "gone");
    assert_eq!(
        io::Error::from(Error::Io(io_err)).kind(),
        ErrorKind::NotFound
    );
}

#[test]
fn error_is_a_std_error_trait_object() {
    let err: Box<dyn StdError> = Box::new(Error::SymlinkDetected);
    assert!(!err.to_string().is_empty());
}
