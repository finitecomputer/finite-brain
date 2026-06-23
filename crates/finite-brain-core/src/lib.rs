//! FiniteBrain Portable v1 core domain and validation logic.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

const RESERVED_TOP_LEVEL_NAMES: [&str; 3] = [".finitebrain", "_admin", ".git"];

/// Returns the crate name used in workspace status surfaces.
pub fn crate_name() -> &'static str {
    "finite-brain-core"
}

/// Core domain validation errors.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CoreError {
    /// A stable id is empty or not path-safe.
    InvalidId { field: &'static str, value: String },
    /// A display name is empty or contains forbidden characters.
    InvalidName { field: &'static str, value: String },
    /// A path is not a safe relative path.
    InvalidPath { field: &'static str, value: String },
    /// A case-sensitive product identity collision occurred.
    Collision { field: &'static str, value: String },
    /// A folder hierarchy operation is invalid.
    InvalidHierarchy { reason: String },
    /// Bootstrap input is incomplete or violates the Vault kind rules.
    InvalidBootstrapInput { reason: String },
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId { field, value } => {
                write!(f, "invalid id for {field}: {value}")
            }
            Self::InvalidName { field, value } => {
                write!(f, "invalid name for {field}: {value}")
            }
            Self::InvalidPath { field, value } => {
                write!(f, "invalid path for {field}: {value}")
            }
            Self::Collision { field, value } => {
                write!(f, "collision for {field}: {value}")
            }
            Self::InvalidHierarchy { reason } => write!(f, "invalid hierarchy: {reason}"),
            Self::InvalidBootstrapInput { reason } => {
                write!(f, "invalid bootstrap input: {reason}")
            }
        }
    }
}

impl Error for CoreError {}

/// Stable Vault id.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct VaultId(String);

impl VaultId {
    /// Validate and create a Vault id.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        validate_stable_id("vault_id", value.into(), 1, 128).map(Self)
    }

    /// Borrow the normalized id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VaultId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable Folder id.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct FolderId(String);

impl FolderId {
    /// Validate and create a Folder id.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        validate_stable_id("folder_id", value.into(), 1, 128).map(Self)
    }

    /// Borrow the normalized id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FolderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable Folder Object id.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct ObjectId(String);

impl ObjectId {
    /// Validate and create a Folder Object id.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let normalized = validate_stable_id("object_id", value.into(), 16, 128)?;
        if normalized.contains('.') {
            return Err(CoreError::InvalidId {
                field: "object_id",
                value: normalized,
            });
        }
        Ok(Self(normalized))
    }

    /// Borrow the normalized id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Nostr user id as stored by FiniteBrain.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct UserId(String);

impl UserId {
    /// Validate and create a user id.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        let normalized = normalize_nfc(&value);
        if normalized.is_empty() || contains_nul_or_control(&normalized) {
            return Err(CoreError::InvalidId {
                field: "user_id",
                value,
            });
        }
        Ok(Self(normalized))
    }

    /// Borrow the normalized id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// User-facing Folder or Vault display name.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct DisplayName(String);

impl DisplayName {
    /// Validate and normalize a display name.
    pub fn new(field: &'static str, value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        let normalized = normalize_nfc(&value);
        if normalized.is_empty()
            || normalized.contains('/')
            || contains_nul_or_control(&normalized)
            || normalized == "."
            || normalized == ".."
        {
            return Err(CoreError::InvalidName { field, value });
        }
        Ok(Self(normalized))
    }

    /// Borrow the normalized display name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DisplayName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Safe relative path normalized to Unicode NFC.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct SafeRelativePath(String);

impl SafeRelativePath {
    /// Validate a Folder path or decrypted object path.
    pub fn new(field: &'static str, value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        let normalized = normalize_nfc(&value);

        if normalized.is_empty()
            || normalized.starts_with('/')
            || normalized.contains('\\')
            || contains_nul_or_control(&normalized)
        {
            return Err(CoreError::InvalidPath { field, value });
        }

        let segments = normalized.split('/').collect::<Vec<_>>();
        if segments
            .iter()
            .any(|segment| segment.is_empty() || *segment == "." || *segment == "..")
        {
            return Err(CoreError::InvalidPath { field, value });
        }

        if RESERVED_TOP_LEVEL_NAMES.contains(&segments[0]) {
            return Err(CoreError::InvalidPath { field, value });
        }

        Ok(Self(normalized))
    }

    /// Borrow the normalized path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeRelativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Vault kind.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultKind {
    /// Personal Vault owned by one user.
    Personal,
    /// Organization Vault with members and admins.
    Organization,
}

/// Folder role.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderRole {
    /// Personal home folder.
    PersonalHome,
    /// Organization operations/admin folder.
    VaultOps,
    /// Organization general folder.
    General,
    /// Ordinary folder.
    Folder,
}

/// Binary access mode for a Folder.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderAccessMode {
    /// Personal Vault owner only.
    Owner,
    /// Organization Vault admins only.
    AdminOnly,
    /// Organization members and admins.
    AllMembers,
    /// Admins plus explicitly listed members.
    Restricted,
}

/// Vault member metadata.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultMember {
    /// Member user id.
    pub user_id: UserId,
    /// Explicit restricted Folder Access entries.
    pub folder_access: BTreeSet<FolderId>,
}

/// Folder metadata.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Folder {
    /// Stable folder id.
    pub id: FolderId,
    /// User-facing display name.
    pub name: DisplayName,
    /// Folder role.
    pub role: FolderRole,
    /// Binary access mode.
    pub access: FolderAccessMode,
    /// Optional parent Folder id.
    pub parent_folder_id: Option<FolderId>,
    /// Decorated Folder hierarchy path.
    pub path: SafeRelativePath,
    /// Current Folder Key version.
    pub current_key_version: u32,
    /// Whether this Folder is a shared-folder source.
    pub shared_folder_source: bool,
}

/// Folder Object metadata without encrypted bytes.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FolderObject {
    /// Stable object id.
    pub object_id: ObjectId,
    /// Containing Folder id.
    pub folder_id: FolderId,
    /// Encrypted plaintext path.
    pub plaintext_path: SafeRelativePath,
}

/// Vault metadata.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Vault {
    /// Stable Vault id.
    pub id: VaultId,
    /// Vault kind.
    pub kind: VaultKind,
    /// User-facing Vault name.
    pub name: DisplayName,
    /// Personal Vault owner, if this is a personal Vault.
    pub owner_user_id: Option<UserId>,
    /// Folders in this Vault.
    pub folders: Vec<Folder>,
    /// Organization members.
    pub members: Vec<VaultMember>,
    /// Organization admins.
    pub admins: Vec<UserId>,
}

/// Required current Folder Key Grant recipient produced by bootstrap.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequiredFolderKeyGrant {
    /// Folder receiving a grant.
    pub folder_id: FolderId,
    /// Recipient user id.
    pub recipient_user_id: UserId,
    /// Folder Key version.
    pub key_version: u32,
}

/// Bootstrap output for an initial Vault.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootstrapOutput {
    /// Created Vault metadata.
    pub vault: Vault,
    /// Required current key grants.
    pub required_key_grants: Vec<RequiredFolderKeyGrant>,
}

/// Mutable pure-domain collection used to enforce hierarchy collisions.
#[derive(Debug, Clone, Default)]
pub struct VaultDraft {
    folders_by_id: BTreeMap<FolderId, Folder>,
    sibling_names: BTreeSet<(Option<FolderId>, DisplayName)>,
    object_paths: BTreeSet<(FolderId, SafeRelativePath)>,
    object_ids: BTreeSet<(FolderId, ObjectId)>,
}

impl VaultDraft {
    /// Add a Folder while enforcing id, parent, and sibling-name uniqueness.
    pub fn add_folder(&mut self, folder: Folder) -> Result<(), CoreError> {
        if self.folders_by_id.contains_key(&folder.id) {
            return Err(CoreError::Collision {
                field: "folder_id",
                value: folder.id.to_string(),
            });
        }

        if let Some(parent_id) = &folder.parent_folder_id
            && !self.folders_by_id.contains_key(parent_id)
        {
            return Err(CoreError::InvalidHierarchy {
                reason: format!("missing parent folder: {parent_id}"),
            });
        }

        let sibling_key = (folder.parent_folder_id.clone(), folder.name.clone());
        if !self.sibling_names.insert(sibling_key) {
            return Err(CoreError::Collision {
                field: "sibling_folder_name",
                value: folder.name.to_string(),
            });
        }

        self.folders_by_id.insert(folder.id.clone(), folder);
        Ok(())
    }

    /// Add a Folder Object while enforcing object id and page-path uniqueness per Folder.
    pub fn add_object(&mut self, object: FolderObject) -> Result<(), CoreError> {
        if !self.folders_by_id.contains_key(&object.folder_id) {
            return Err(CoreError::InvalidHierarchy {
                reason: format!("missing object folder: {}", object.folder_id),
            });
        }

        if !self
            .object_ids
            .insert((object.folder_id.clone(), object.object_id.clone()))
        {
            return Err(CoreError::Collision {
                field: "object_id",
                value: object.object_id.as_str().to_owned(),
            });
        }

        if !self
            .object_paths
            .insert((object.folder_id.clone(), object.plaintext_path.clone()))
        {
            return Err(CoreError::Collision {
                field: "object_path",
                value: object.plaintext_path.to_string(),
            });
        }

        Ok(())
    }

    /// Return folders in id order for deterministic tests/smoke output.
    pub fn folders(&self) -> Vec<Folder> {
        self.folders_by_id.values().cloned().collect()
    }
}

/// Build the initial personal Vault shape.
pub fn bootstrap_personal_vault(
    vault_id: impl Into<String>,
    name: impl Into<String>,
    owner_user_id: impl Into<String>,
) -> Result<BootstrapOutput, CoreError> {
    let vault_id = VaultId::new(vault_id)?;
    let name = DisplayName::new("vault_name", name)?;
    let owner_user_id = UserId::new(owner_user_id)?;

    let home = root_folder(
        "home",
        "home",
        FolderRole::PersonalHome,
        FolderAccessMode::Owner,
    )?;

    let grant = RequiredFolderKeyGrant {
        folder_id: home.id.clone(),
        recipient_user_id: owner_user_id.clone(),
        key_version: 1,
    };

    let vault = Vault {
        id: vault_id,
        kind: VaultKind::Personal,
        name,
        owner_user_id: Some(owner_user_id),
        folders: vec![home],
        members: Vec::new(),
        admins: Vec::new(),
    };

    Ok(BootstrapOutput {
        vault,
        required_key_grants: vec![grant],
    })
}

/// Build the initial organization Vault shape.
pub fn bootstrap_organization_vault(
    vault_id: impl Into<String>,
    name: impl Into<String>,
    admin_user_id: impl Into<String>,
) -> Result<BootstrapOutput, CoreError> {
    let vault_id = VaultId::new(vault_id)?;
    let name = DisplayName::new("vault_name", name)?;
    let admin_user_id = UserId::new(admin_user_id)?;

    let vault_ops = root_folder(
        "vault-ops",
        "vault-ops",
        FolderRole::VaultOps,
        FolderAccessMode::AdminOnly,
    )?;
    let general = root_folder(
        "general",
        "general",
        FolderRole::General,
        FolderAccessMode::AllMembers,
    )?;

    let required_key_grants = vec![
        RequiredFolderKeyGrant {
            folder_id: vault_ops.id.clone(),
            recipient_user_id: admin_user_id.clone(),
            key_version: 1,
        },
        RequiredFolderKeyGrant {
            folder_id: general.id.clone(),
            recipient_user_id: admin_user_id.clone(),
            key_version: 1,
        },
    ];

    let vault = Vault {
        id: vault_id,
        kind: VaultKind::Organization,
        name,
        owner_user_id: None,
        folders: vec![vault_ops, general],
        members: vec![VaultMember {
            user_id: admin_user_id.clone(),
            folder_access: BTreeSet::new(),
        }],
        admins: vec![admin_user_id],
    };

    Ok(BootstrapOutput {
        vault,
        required_key_grants,
    })
}

/// Development-only deterministic bootstrap summary used by the smoke server.
pub fn smoke_bootstrap_summary() -> Result<BootstrapSmokeSummary, CoreError> {
    let personal =
        bootstrap_personal_vault("personal-smoke", "Personal Smoke", "npub-smoke-owner")?;
    let organization =
        bootstrap_organization_vault("org-smoke", "Organization Smoke", "npub-smoke-admin")?;

    Ok(BootstrapSmokeSummary {
        personal: BootstrapVaultSummary::from_output(&personal),
        organization: BootstrapVaultSummary::from_output(&organization),
    })
}

/// Development smoke summary for both bootstrap shapes.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootstrapSmokeSummary {
    /// Personal Vault summary.
    pub personal: BootstrapVaultSummary,
    /// Organization Vault summary.
    pub organization: BootstrapVaultSummary,
}

/// Compact bootstrap summary safe to return from smoke endpoints.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootstrapVaultSummary {
    /// Vault kind.
    pub kind: VaultKind,
    /// Folder ids created by bootstrap.
    pub folder_ids: Vec<String>,
    /// Number of current required Folder Key Grants.
    pub required_grants: usize,
    /// Admin count.
    pub admin_count: usize,
    /// Member count.
    pub member_count: usize,
}

impl BootstrapVaultSummary {
    fn from_output(output: &BootstrapOutput) -> Self {
        Self {
            kind: output.vault.kind,
            folder_ids: output
                .vault
                .folders
                .iter()
                .map(|folder| folder.id.to_string())
                .collect(),
            required_grants: output.required_key_grants.len(),
            admin_count: output.vault.admins.len(),
            member_count: output.vault.members.len(),
        }
    }
}

fn root_folder(
    id: &str,
    name: &str,
    role: FolderRole,
    access: FolderAccessMode,
) -> Result<Folder, CoreError> {
    if RESERVED_TOP_LEVEL_NAMES.contains(&name) {
        return Err(CoreError::InvalidName {
            field: "folder_name",
            value: name.to_owned(),
        });
    }

    Ok(Folder {
        id: FolderId::new(id)?,
        name: DisplayName::new("folder_name", name)?,
        role,
        access,
        parent_folder_id: None,
        path: SafeRelativePath::new("folder_path", name)?,
        current_key_version: 1,
        shared_folder_source: false,
    })
}

fn validate_stable_id(
    field: &'static str,
    value: String,
    min_len: usize,
    max_len: usize,
) -> Result<String, CoreError> {
    let normalized = normalize_nfc(&value);
    let valid_len = (min_len..=max_len).contains(&normalized.len());
    let valid_chars = normalized
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');

    if !valid_len || !valid_chars {
        return Err(CoreError::InvalidId { field, value });
    }

    Ok(normalized)
}

fn normalize_nfc(value: &str) -> String {
    value.nfc().collect::<String>()
}

fn contains_nul_or_control(value: &str) -> bool {
    value.chars().any(|c| c == '\0' || c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_core_crate_name() {
        assert_eq!(crate_name(), "finite-brain-core");
    }

    #[test]
    fn bootstraps_personal_vault() {
        let output = bootstrap_personal_vault("personal", "Austin", "npub-owner").unwrap();

        assert_eq!(output.vault.kind, VaultKind::Personal);
        assert_eq!(
            output.vault.owner_user_id,
            Some(UserId::new("npub-owner").unwrap())
        );
        assert!(output.vault.members.is_empty());
        assert!(output.vault.admins.is_empty());
        assert_eq!(output.vault.folders.len(), 1);

        let home = &output.vault.folders[0];
        assert_eq!(home.id, FolderId::new("home").unwrap());
        assert_eq!(home.role, FolderRole::PersonalHome);
        assert_eq!(home.access, FolderAccessMode::Owner);
        assert_eq!(home.current_key_version, 1);
        assert_eq!(
            home.path,
            SafeRelativePath::new("folder_path", "home").unwrap()
        );
        assert_eq!(
            output.required_key_grants,
            vec![RequiredFolderKeyGrant {
                folder_id: FolderId::new("home").unwrap(),
                recipient_user_id: UserId::new("npub-owner").unwrap(),
                key_version: 1
            }]
        );
    }

    #[test]
    fn bootstraps_organization_vault() {
        let output = bootstrap_organization_vault("org", "Finite", "npub-admin").unwrap();

        assert_eq!(output.vault.kind, VaultKind::Organization);
        assert_eq!(output.vault.owner_user_id, None);
        assert_eq!(
            output.vault.admins,
            vec![UserId::new("npub-admin").unwrap()]
        );
        assert_eq!(output.vault.members.len(), 1);
        assert_eq!(
            output.vault.members[0].user_id,
            UserId::new("npub-admin").unwrap()
        );
        assert_eq!(output.vault.folders.len(), 2);
        assert_eq!(output.required_key_grants.len(), 2);

        let vault_ops = &output.vault.folders[0];
        assert_eq!(vault_ops.id, FolderId::new("vault-ops").unwrap());
        assert_eq!(vault_ops.role, FolderRole::VaultOps);
        assert_eq!(vault_ops.access, FolderAccessMode::AdminOnly);

        let general = &output.vault.folders[1];
        assert_eq!(general.id, FolderId::new("general").unwrap());
        assert_eq!(general.role, FolderRole::General);
        assert_eq!(general.access, FolderAccessMode::AllMembers);
    }

    #[test]
    fn validates_paths_and_names() {
        let decomposed = "Cafe\u{301}/notes.md";
        let path = SafeRelativePath::new("page_path", decomposed).unwrap();
        assert_eq!(path.as_str(), "Café/notes.md");

        assert_eq!(
            SafeRelativePath::new("page_path", "/absolute").unwrap_err(),
            CoreError::InvalidPath {
                field: "page_path",
                value: "/absolute".to_owned()
            }
        );
        assert_eq!(
            SafeRelativePath::new("page_path", "a/../b").unwrap_err(),
            CoreError::InvalidPath {
                field: "page_path",
                value: "a/../b".to_owned()
            }
        );
        assert_eq!(
            SafeRelativePath::new("page_path", ".git/config").unwrap_err(),
            CoreError::InvalidPath {
                field: "page_path",
                value: ".git/config".to_owned()
            }
        );
        assert!(DisplayName::new("folder_name", "bad/name").is_err());
        assert!(DisplayName::new("folder_name", "bad\u{0}name").is_err());
        assert!(ObjectId::new("too-short").is_err());
        assert!(ObjectId::new("object_id_with_extension.md").is_err());
    }

    #[test]
    fn folder_and_page_collisions_are_case_sensitive() {
        let mut draft = VaultDraft::default();
        let root = root_folder(
            "root",
            "Root",
            FolderRole::Folder,
            FolderAccessMode::Restricted,
        )
        .unwrap();
        draft.add_folder(root.clone()).unwrap();

        let duplicate = Folder {
            id: FolderId::new("other").unwrap(),
            name: root.name.clone(),
            role: FolderRole::Folder,
            access: FolderAccessMode::Restricted,
            parent_folder_id: None,
            path: SafeRelativePath::new("folder_path", "Root 2").unwrap(),
            current_key_version: 1,
            shared_folder_source: false,
        };
        assert_eq!(
            draft.add_folder(duplicate).unwrap_err(),
            CoreError::Collision {
                field: "sibling_folder_name",
                value: "Root".to_owned()
            }
        );

        draft
            .add_folder(Folder {
                id: FolderId::new("lower").unwrap(),
                name: DisplayName::new("folder_name", "root").unwrap(),
                role: FolderRole::Folder,
                access: FolderAccessMode::Restricted,
                parent_folder_id: None,
                path: SafeRelativePath::new("folder_path", "root").unwrap(),
                current_key_version: 1,
                shared_folder_source: false,
            })
            .unwrap();

        let object = FolderObject {
            object_id: ObjectId::new("object_0000000001").unwrap(),
            folder_id: root.id.clone(),
            plaintext_path: SafeRelativePath::new("page_path", "wiki/Intro.md").unwrap(),
        };
        draft.add_object(object.clone()).unwrap();
        assert_eq!(
            draft
                .add_object(FolderObject {
                    object_id: ObjectId::new("object_0000000002").unwrap(),
                    ..object
                })
                .unwrap_err(),
            CoreError::Collision {
                field: "object_path",
                value: "wiki/Intro.md".to_owned()
            }
        );
    }

    #[test]
    fn child_access_is_independent_from_parent_access() {
        let mut draft = VaultDraft::default();
        let parent = root_folder(
            "parent",
            "Parent",
            FolderRole::Folder,
            FolderAccessMode::AllMembers,
        )
        .unwrap();
        draft.add_folder(parent.clone()).unwrap();

        let child = Folder {
            id: FolderId::new("child").unwrap(),
            name: DisplayName::new("folder_name", "Child").unwrap(),
            role: FolderRole::Folder,
            access: FolderAccessMode::Restricted,
            parent_folder_id: Some(parent.id.clone()),
            path: SafeRelativePath::new("folder_path", "Parent/Child").unwrap(),
            current_key_version: 1,
            shared_folder_source: false,
        };
        draft.add_folder(child.clone()).unwrap();

        let folders = draft.folders();
        let stored_parent = folders
            .iter()
            .find(|folder| folder.id == parent.id)
            .unwrap();
        let stored_child = folders.iter().find(|folder| folder.id == child.id).unwrap();

        assert_eq!(stored_parent.access, FolderAccessMode::AllMembers);
        assert_eq!(stored_child.access, FolderAccessMode::Restricted);
        assert_ne!(stored_parent.access, stored_child.access);
    }

    #[test]
    fn rejects_invalid_hierarchy() {
        let mut draft = VaultDraft::default();
        let orphan = Folder {
            id: FolderId::new("orphan").unwrap(),
            name: DisplayName::new("folder_name", "Orphan").unwrap(),
            role: FolderRole::Folder,
            access: FolderAccessMode::Restricted,
            parent_folder_id: Some(FolderId::new("missing").unwrap()),
            path: SafeRelativePath::new("folder_path", "Missing/Orphan").unwrap(),
            current_key_version: 1,
            shared_folder_source: false,
        };

        assert_eq!(
            draft.add_folder(orphan).unwrap_err(),
            CoreError::InvalidHierarchy {
                reason: "missing parent folder: missing".to_owned()
            }
        );
    }

    #[test]
    fn smoke_bootstrap_summary_is_stable() {
        let summary = smoke_bootstrap_summary().unwrap();

        assert_eq!(summary.personal.kind, VaultKind::Personal);
        assert_eq!(summary.personal.folder_ids, vec!["home"]);
        assert_eq!(summary.personal.required_grants, 1);

        assert_eq!(summary.organization.kind, VaultKind::Organization);
        assert_eq!(
            summary.organization.folder_ids,
            vec!["vault-ops".to_owned(), "general".to_owned()]
        );
        assert_eq!(summary.organization.required_grants, 2);
        assert_eq!(summary.organization.admin_count, 1);
        assert_eq!(summary.organization.member_count, 1);
    }
}
