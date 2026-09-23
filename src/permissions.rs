/// A platform-independent view of whether a file or directory is protected.
///
/// On Unix this reflects the `0600` / `0700` permission bits; on Windows it
/// reflects the discretionary access control list (DACL). The platform-specific
/// details are intentionally not exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecurePermissions {
    /// `true` when only the owner can access the resource.
    pub owner_only: bool,
}

impl SecurePermissions {
    /// Returns `true` when only the owner can access the resource.
    pub fn is_owner_only(&self) -> bool {
        self.owner_only
    }
}
