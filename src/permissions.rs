/// A platform-independent view of a file or directory's permissions.
///
/// On Unix the `owner_*` fields reflect the owner permission bits; on Windows
/// they reflect the access granted to the current user by the discretionary
/// access control list (DACL). The platform-specific details are intentionally
/// not exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecurePermissions {
    /// `true` when only the owner can access the resource.
    pub owner_only: bool,
    /// `true` when the owner may read the resource.
    pub owner_read: bool,
    /// `true` when the owner may write to the resource.
    pub owner_write: bool,
    /// `true` when the owner may execute or traverse the resource.
    pub owner_execute: bool,
}

impl SecurePermissions {
    /// Returns `true` when only the owner can access the resource.
    pub fn is_owner_only(&self) -> bool {
        self.owner_only
    }
}
