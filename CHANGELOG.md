# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-09-23

### Changed

- First stable release. The public API of `SecureFile`, `SecureDir`,
  `SecureTempFile`, `SecureTempDir`, `SecureFileOptions`, `SecurePermissions`,
  `Error`, and the free functions is now considered stable.

## [0.3.0] - 2026-09-23

### Added

- `SecureTempFile`: owner-only temporary files with unpredictable names,
  automatic deletion on drop, `keep()`, and atomic `persist()`.
- `SecureTempDir`: owner-only temporary directories with automatic recursive
  removal on drop and `keep()`.
- `app_data_dir()`, `app_dir()`, and `app_dir_in()` for application-private
  directories under the platform's per-user data directory.

## [0.2.0] - 2026-09-23

### Added

- `write_private_atomic()`: write via an owner-only temporary file and an
  atomic rename.
- `SecureFileOptions` builder (`SecureFile::options()`) with control over
  `read`/`write`/`append`/`truncate`/`create`/`create_new`, symlink handling
  (`follow_symlinks`), and permission verification (`verify_private`).
- Richer `SecurePermissions` with `owner_read`, `owner_write`, and
  `owner_execute`.
- `Error::NotFound`, `Error::InvalidInput`, and `Error::kind()`.
- Cross-compilation checks for FreeBSD, NetBSD, illumos, and aarch64 Linux.

### Changed

- `SecureFile::open`/`SecureDir::open` verification behavior is unchanged, but
  creation without write access is now consistently `Error::InvalidInput`
  across platforms.

## [0.1.0] - 2026-09-23

### Added

- `SecureFile` and `SecureDir` with `create`, `open`, `open_unchecked`, and
  `ensure_private`.
- `write_private`, `read_private`, and `create_dir` convenience functions.
- Owner-only permissions (`0600`/`0700` on Unix, restrictive DACL on Windows)
  applied atomically at creation.
- Symbolic link rejection and exclusive creation.
- `Error`, `Result`, and `SecurePermissions`.

[Unreleased]: https://github.com/stackmator/secure-file/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/stackmator/secure-file/compare/v0.3.0...v1.0.0
[0.3.0]: https://github.com/stackmator/secure-file/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/stackmator/secure-file/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/stackmator/secure-file/releases/tag/v0.1.0
