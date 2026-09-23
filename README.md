# secure-file

Cross-platform owner-only filesystem access for Rust.

`secure-file` provides a small API for creating and opening files and
directories that should only be accessible by the current user. It hides the
platform-specific details — Unix permission bits and Windows DACLs — behind a
single abstraction.

| Platform    | Files  | Directories |
|-------------|--------|-------------|
| Linux/macOS | `0600` | `0700`      |
| Windows     | Owner-only DACL | Owner-only DACL |

The important property is that resources are secure **from the moment they are
created**, rather than being created and then tightened afterwards:

```rust
use secure_file::SecureFile;
use std::io::Write;

let mut file = SecureFile::create("credentials.json")?;
file.write_all(b"secret data")?;
# Ok::<(), secure_file::Error>(())
```

That is conceptually `open(..., O_CREAT | O_EXCL, 0600)` on Unix and
`CreateFile` with a restrictive security descriptor on Windows, so there is no
window during which another user could open the file.

## Usage

Write and read a whole secret:

```rust
secure_file::write_private("~/.myapp/api-key", api_key)?;
let api_key = secure_file::read_private("~/.myapp/api-key")?;
```

Replace a file atomically, so a reader never observes a partial or insecure
file:

```rust
secure_file::write_private_atomic("~/.myapp/api-key", api_key)?;
```

Create a private directory:

```rust
let dir = secure_file::create_dir("~/.myapp")?;
```

Open an existing file and verify that it is private:

```rust
let file = SecureFile::open("credentials.json")?; // errors if not private
```

Tighten an existing file that was created without owner-only permissions:

```rust
let file = SecureFile::open_unchecked("credentials.json")?;
let file = file.ensure_private()?;
```

Inspect permissions in a platform-independent way:

```rust
let permissions = SecureFile::open("credentials.json")?.permissions()?;
if permissions.owner_only {
    println!("Safe");
}
println!(
    "read={} write={} execute={}",
    permissions.owner_read, permissions.owner_write, permissions.owner_execute
);
```

Take fine-grained control over open flags and symlink handling:

```rust
use secure_file::SecureFile;

let file = SecureFile::options()
    .create(true)
    .truncate(true)
    .write(true)
    .open("credentials.json")?;
```

## Security model

`secure-file` protects files against access by other operating-system users
according to the platform's filesystem permission model. On Unix it uses
owner-only permission bits; on Windows it uses a restrictive DACL.

It does **not** protect against:

- `root` / `Administrator` (or equivalent) accounts,
- malware running with equivalent privileges,
- a compromised operating system,
- physical access to the storage medium,
- filesystem-level or full-disk encryption attacks,
- memory disclosure.

This crate is **not** encryption. It only restricts who the operating system
allows to read or write the resource.

## Behavior details

- **Exclusive creation.** `SecureFile::create` / `SecureDir::create` fail with
  `Error::AlreadyExists` if the path already exists, avoiding TOCTOU races.
- **Symlinks are rejected.** Files are opened with `O_NOFOLLOW` on Unix and
  `FILE_FLAG_OPEN_REPARSE_POINT` on Windows; reparse points are detected and
  rejected. Use `SecureFile::options().follow_symlinks(true)` to opt out.
- **Open verifies by default.** `SecureFile::open` / `SecureDir::open` return
  `Error::InsecurePermissions` when the resource is accessible by others. Use
  the `open_unchecked` variants to inspect or repair such resources, or
  `SecureFile::options().verify_private(false)`.
- **Atomic writes.** `write_private_atomic` writes to an owner-only temporary
  file in the same directory, flushes it, and renames it into place, so readers
  never see a partial file.
- **Creation requires write access.** As with `std::fs::OpenOptions` on Unix,
  `SecureFile::options().create(..)` must be combined with write or append
  access; otherwise it fails with `Error::InvalidInput`.

## Supported platforms

Linux, macOS and Windows are tested on every commit. The Unix implementation
also builds for FreeBSD, NetBSD, illumos and other architectures (checked in
CI).

## Roadmap

- **v0.1** — `SecureFile` and `SecureDir` create/open/ensure, `write_private`,
  `read_private`, Linux/macOS/Windows.
- **v0.2** — atomic writes, symlink controls, richer permission inspection,
  more Unix targets. *(current)*
- **v0.3** — secure temporary files and directories, application-private
  directories, further Windows improvements.
- **v1.0** — stable API and a strong cross-platform test suite.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your
option.
