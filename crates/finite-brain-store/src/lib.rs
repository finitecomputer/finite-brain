//! FiniteBrain SQLite store and transaction boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::path::Path;

use finite_brain_core::{
    BootstrapOutput, CoreError, DisplayName, Folder, FolderAccessMode, FolderId, FolderRole,
    RequiredFolderKeyGrant, SafeRelativePath, UserId, Vault, VaultId, VaultKind, VaultMember,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

const MIGRATION_VERSION: i64 = 1;
const GRANT_FORMAT_NIP59: &str = "NIP-59";

/// Returns the crate name used in workspace status surfaces.
pub fn crate_name() -> &'static str {
    "finite-brain-store"
}

/// Store-level validation and SQLite boundary errors.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StoreError {
    /// Core domain validation failed.
    Core(CoreError),
    /// SQLite returned an error.
    Database { message: String },
    /// A requested Vault does not exist.
    MissingVault { vault_id: String },
    /// A requested Folder does not exist.
    MissingFolder { folder_id: String },
    /// A stable id already exists in the scoped table.
    DuplicateId { field: &'static str, value: String },
    /// Grant metadata did not include a required current recipient.
    MissingRequiredGrant { recipient_user_id: String },
    /// Stored state would violate Vault, member, admin, access, or grant rules.
    BrokenInvariant { reason: String },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(f, "{error}"),
            Self::Database { message } => write!(f, "database error: {message}"),
            Self::MissingVault { vault_id } => write!(f, "missing vault: {vault_id}"),
            Self::MissingFolder { folder_id } => write!(f, "missing folder: {folder_id}"),
            Self::DuplicateId { field, value } => {
                write!(f, "duplicate id for {field}: {value}")
            }
            Self::MissingRequiredGrant { recipient_user_id } => {
                write!(f, "missing required grant for {recipient_user_id}")
            }
            Self::BrokenInvariant { reason } => write!(f, "broken invariant: {reason}"),
        }
    }
}

impl Error for StoreError {}

impl From<CoreError> for StoreError {
    fn from(value: CoreError) -> Self {
        Self::Core(value)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database {
            message: value.to_string(),
        }
    }
}

/// Stored Folder Key Grant metadata. The encrypted key remains opaque to the server.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FolderKeyGrantMetadata {
    /// Stable grant id.
    pub id: String,
    /// Folder id.
    pub folder_id: FolderId,
    /// Folder Key version.
    pub key_version: u32,
    /// Issuer npub.
    pub issuer_npub: UserId,
    /// Recipient npub.
    pub recipient_npub: UserId,
    /// Envelope format, currently `NIP-59`.
    pub format: String,
    /// Stored wrapped event JSON.
    pub wrapped_event_json: String,
    /// Optional signed admin access-change event JSON.
    pub access_change_event_json: Option<String>,
    /// Creation timestamp.
    pub created_at: String,
}

/// Reloaded Vault state with store-only metadata attached.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StoredVault {
    /// Core Vault metadata.
    pub vault: Vault,
    /// Explicit restricted Folder access by Folder id.
    pub folder_access: BTreeMap<FolderId, BTreeSet<UserId>>,
    /// Stored Folder Key Grant metadata.
    pub grants: Vec<FolderKeyGrantMetadata>,
    /// Folders that still need current grants.
    pub setup_incomplete_folder_ids: BTreeSet<FolderId>,
}

/// Narrow SQLite-backed authoritative store.
pub struct BrainStore {
    conn: Connection,
}

impl BrainStore {
    /// Open or create a SQLite store at `path` and apply migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    /// Open an in-memory SQLite store. Useful for fast unit tests only.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, StoreError> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let mut store = Self { conn };
        store.apply_migrations()?;
        Ok(store)
    }

    /// Persist a fresh bootstrap output and its required current grants.
    pub fn create_vault_bootstrap(
        &mut self,
        output: &BootstrapOutput,
        grants: &[FolderKeyGrantMetadata],
    ) -> Result<(), StoreError> {
        validate_bootstrap_output(output)?;
        validate_required_grants(&output.vault, &output.required_key_grants, grants)?;

        let tx = self.conn.transaction()?;
        insert_vault(&tx, &output.vault)?;
        insert_members_and_admins(&tx, &output.vault)?;
        for folder in &output.vault.folders {
            insert_folder(&tx, &output.vault.id, folder, false)?;
        }
        for grant in grants {
            insert_grant(&tx, &output.vault.id, grant)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Add an organization Vault Member.
    pub fn add_member(&mut self, vault_id: &VaultId, user_id: &UserId) -> Result<(), StoreError> {
        self.require_organization_vault(vault_id)?;
        self.conn.execute(
            "INSERT INTO vault_members (vault_id, user_id) VALUES (?1, ?2)",
            params![vault_id.as_str(), user_id.as_str()],
        )?;
        Ok(())
    }

    /// Add an organization Vault Admin. The user must already be a member.
    pub fn add_admin(&mut self, vault_id: &VaultId, user_id: &UserId) -> Result<(), StoreError> {
        self.require_organization_vault(vault_id)?;
        if !self.member_exists(vault_id, user_id)? {
            return Err(StoreError::BrokenInvariant {
                reason: "vault admin must already be a vault member".to_owned(),
            });
        }
        self.conn.execute(
            "INSERT INTO vault_admins (vault_id, user_id) VALUES (?1, ?2)",
            params![vault_id.as_str(), user_id.as_str()],
        )?;
        Ok(())
    }

    /// Create a complete Folder and its current grants in one transaction.
    pub fn create_folder(
        &mut self,
        vault_id: &VaultId,
        folder: &Folder,
        access_user_ids: &BTreeSet<UserId>,
        grants: &[FolderKeyGrantMetadata],
    ) -> Result<(), StoreError> {
        if folder.current_key_version != 1 {
            return Err(StoreError::BrokenInvariant {
                reason: "new folders must start at key version 1".to_owned(),
            });
        }

        let vault = self.load_core_vault(vault_id)?;
        self.validate_folder_request(&vault, folder, access_user_ids, grants)?;

        let tx = self.conn.transaction()?;
        insert_folder(&tx, vault_id, folder, false)?;
        insert_folder_access(&tx, vault_id, &folder.id, access_user_ids)?;
        for grant in grants {
            insert_grant(&tx, vault_id, grant)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Insert an empty legacy Folder that can later be repaired by Finish Setup.
    pub fn insert_setup_incomplete_folder_for_repair(
        &mut self,
        vault_id: &VaultId,
        folder: &Folder,
        access_user_ids: &BTreeSet<UserId>,
    ) -> Result<(), StoreError> {
        let vault = self.load_core_vault(vault_id)?;
        validate_hierarchy(&self.conn, vault_id, folder)?;
        validate_access_list_shape(folder, access_user_ids)?;
        validate_access_membership(&vault, access_user_ids)?;

        let tx = self.conn.transaction()?;
        insert_folder(&tx, vault_id, folder, true)?;
        insert_folder_access(&tx, vault_id, &folder.id, access_user_ids)?;
        tx.commit()?;
        Ok(())
    }

    /// Finish setup for an empty Folder by writing the required current grants.
    pub fn finish_folder_setup(
        &mut self,
        vault_id: &VaultId,
        folder_id: &FolderId,
        grants: &[FolderKeyGrantMetadata],
    ) -> Result<(), StoreError> {
        let stored = self.load_vault(vault_id)?;
        let folder = stored
            .vault
            .folders
            .iter()
            .find(|folder| folder.id == *folder_id)
            .ok_or_else(|| StoreError::MissingFolder {
                folder_id: folder_id.to_string(),
            })?;

        if !stored.setup_incomplete_folder_ids.contains(folder_id) {
            return Err(StoreError::BrokenInvariant {
                reason: "folder setup is already complete".to_owned(),
            });
        }

        let access_user_ids = stored
            .folder_access
            .get(folder_id)
            .cloned()
            .unwrap_or_default();
        let required = required_recipients(&stored.vault, folder, &access_user_ids)?;
        validate_folder_grants(&stored.vault, folder, &required, grants)?;

        let tx = self.conn.transaction()?;
        for grant in grants {
            insert_grant(&tx, vault_id, grant)?;
        }
        tx.execute(
            "UPDATE folders SET setup_incomplete = 0 WHERE vault_id = ?1 AND id = ?2",
            params![vault_id.as_str(), folder_id.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Reload a Vault and all current access/grant metadata.
    pub fn load_vault(&self, vault_id: &VaultId) -> Result<StoredVault, StoreError> {
        let mut vault = self.load_core_vault(vault_id)?;
        let folder_access = self.load_folder_access(vault_id)?;
        for member in &mut vault.members {
            member.folder_access = folder_access
                .iter()
                .filter_map(|(folder_id, users)| {
                    users.contains(&member.user_id).then_some(folder_id.clone())
                })
                .collect();
        }

        Ok(StoredVault {
            vault,
            folder_access,
            grants: self.load_grants(vault_id)?,
            setup_incomplete_folder_ids: self.load_setup_incomplete_folder_ids(vault_id)?,
        })
    }

    /// Test/support helper for checking rollback behavior without exposing SQL.
    pub fn folder_exists(
        &self,
        vault_id: &VaultId,
        folder_id: &FolderId,
    ) -> Result<bool, StoreError> {
        let exists = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM folders WHERE vault_id = ?1 AND id = ?2)",
            params![vault_id.as_str(), folder_id.as_str()],
            |row| row.get::<_, bool>(0),
        )?;
        Ok(exists)
    }

    /// Test/support helper for checking grant rollback behavior without exposing SQL.
    pub fn grant_exists(&self, grant_id: &str) -> Result<bool, StoreError> {
        let exists = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM folder_key_grants WHERE id = ?1)",
            params![grant_id],
            |row| row.get::<_, bool>(0),
        )?;
        Ok(exists)
    }

    fn apply_migrations(&mut self) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        tx.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            "#,
        )?;

        let applied = tx
            .query_row(
                "SELECT 1 FROM schema_migrations WHERE version = ?1",
                params![MIGRATION_VERSION],
                |_| Ok(()),
            )
            .optional()?
            .is_some();

        if !applied {
            tx.execute_batch(SCHEMA_V1)?;
            tx.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                params![MIGRATION_VERSION, "2026-06-23T00:00:00.000Z"],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    fn require_organization_vault(&self, vault_id: &VaultId) -> Result<(), StoreError> {
        let vault = self.load_core_vault(vault_id)?;
        if vault.kind != VaultKind::Organization {
            return Err(StoreError::BrokenInvariant {
                reason: "member/admin mutation requires an organization vault".to_owned(),
            });
        }
        Ok(())
    }

    fn member_exists(&self, vault_id: &VaultId, user_id: &UserId) -> Result<bool, StoreError> {
        let exists = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM vault_members WHERE vault_id = ?1 AND user_id = ?2)",
            params![vault_id.as_str(), user_id.as_str()],
            |row| row.get::<_, bool>(0),
        )?;
        Ok(exists)
    }

    fn validate_folder_request(
        &self,
        vault: &Vault,
        folder: &Folder,
        access_user_ids: &BTreeSet<UserId>,
        grants: &[FolderKeyGrantMetadata],
    ) -> Result<(), StoreError> {
        validate_hierarchy(&self.conn, &vault.id, folder)?;
        validate_access_list_shape(folder, access_user_ids)?;
        validate_access_membership(vault, access_user_ids)?;
        let required = required_recipients(vault, folder, access_user_ids)?;
        validate_folder_grants(vault, folder, &required, grants)
    }

    fn load_core_vault(&self, vault_id: &VaultId) -> Result<Vault, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, kind, name, owner_user_id FROM vaults WHERE id = ?1",
                params![vault_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StoreError::MissingVault {
                vault_id: vault_id.to_string(),
            })?;

        let kind = parse_vault_kind(&row.1)?;
        let mut vault = Vault {
            id: VaultId::new(row.0)?,
            kind,
            name: DisplayName::new("vault_name", row.2)?,
            owner_user_id: row.3.map(UserId::new).transpose()?,
            folders: self.load_folders(vault_id)?,
            members: self.load_members(vault_id)?,
            admins: self.load_admins(vault_id)?,
        };
        validate_loaded_vault(&vault)?;

        if vault.kind == VaultKind::Organization {
            let folder_access = self.load_folder_access(vault_id)?;
            for member in &mut vault.members {
                member.folder_access = folder_access
                    .iter()
                    .filter_map(|(folder_id, users)| {
                        users.contains(&member.user_id).then_some(folder_id.clone())
                    })
                    .collect();
            }
        }

        Ok(vault)
    }

    fn load_folders(&self, vault_id: &VaultId) -> Result<Vec<Folder>, StoreError> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, name, role, access, parent_folder_id, path, current_key_version,
                   shared_folder_source
            FROM folders
            WHERE vault_id = ?1
            ORDER BY id
            "#,
        )?;
        let rows = stmt.query_map(params![vault_id.as_str()], |row| {
            Ok(StoredFolderRow {
                id: row.get(0)?,
                name: row.get(1)?,
                role: row.get(2)?,
                access: row.get(3)?,
                parent_folder_id: row.get(4)?,
                path: row.get(5)?,
                current_key_version: row.get(6)?,
                shared_folder_source: row.get(7)?,
            })
        })?;

        let mut folders = Vec::new();
        for row in rows {
            folders.push(row?.try_into_folder()?);
        }
        Ok(folders)
    }

    fn load_members(&self, vault_id: &VaultId) -> Result<Vec<VaultMember>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT user_id FROM vault_members WHERE vault_id = ?1 ORDER BY user_id")?;
        let rows = stmt.query_map(params![vault_id.as_str()], |row| row.get::<_, String>(0))?;

        let mut members = Vec::new();
        for row in rows {
            members.push(VaultMember {
                user_id: UserId::new(row?)?,
                folder_access: BTreeSet::new(),
            });
        }
        Ok(members)
    }

    fn load_admins(&self, vault_id: &VaultId) -> Result<Vec<UserId>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT user_id FROM vault_admins WHERE vault_id = ?1 ORDER BY user_id")?;
        let rows = stmt.query_map(params![vault_id.as_str()], |row| row.get::<_, String>(0))?;

        let mut admins = Vec::new();
        for row in rows {
            admins.push(UserId::new(row?)?);
        }
        Ok(admins)
    }

    fn load_folder_access(
        &self,
        vault_id: &VaultId,
    ) -> Result<BTreeMap<FolderId, BTreeSet<UserId>>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT folder_id, user_id FROM folder_access WHERE vault_id = ?1 ORDER BY folder_id, user_id",
        )?;
        let rows = stmt.query_map(params![vault_id.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut access = BTreeMap::new();
        for row in rows {
            let (folder_id, user_id) = row?;
            access
                .entry(FolderId::new(folder_id)?)
                .or_insert_with(BTreeSet::new)
                .insert(UserId::new(user_id)?);
        }
        Ok(access)
    }

    fn load_grants(&self, vault_id: &VaultId) -> Result<Vec<FolderKeyGrantMetadata>, StoreError> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, folder_id, key_version, issuer_npub, recipient_npub, format,
                   wrapped_event_json, access_change_event_json, created_at
            FROM folder_key_grants
            WHERE vault_id = ?1
            ORDER BY folder_id, key_version, recipient_npub, id
            "#,
        )?;
        let rows = stmt.query_map(params![vault_id.as_str()], |row| {
            Ok(StoredGrantRow {
                id: row.get(0)?,
                folder_id: row.get(1)?,
                key_version: row.get(2)?,
                issuer_npub: row.get(3)?,
                recipient_npub: row.get(4)?,
                format: row.get(5)?,
                wrapped_event_json: row.get(6)?,
                access_change_event_json: row.get(7)?,
                created_at: row.get(8)?,
            })
        })?;

        let mut grants = Vec::new();
        for row in rows {
            grants.push(row?.try_into_grant()?);
        }
        Ok(grants)
    }

    fn load_setup_incomplete_folder_ids(
        &self,
        vault_id: &VaultId,
    ) -> Result<BTreeSet<FolderId>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id FROM folders WHERE vault_id = ?1 AND setup_incomplete = 1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![vault_id.as_str()], |row| row.get::<_, String>(0))?;

        let mut ids = BTreeSet::new();
        for row in rows {
            ids.insert(FolderId::new(row?)?);
        }
        Ok(ids)
    }
}

const SCHEMA_V1: &str = r#"
CREATE TABLE vaults (
    id TEXT PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('personal', 'organization')),
    name TEXT NOT NULL,
    owner_user_id TEXT,
    created_at TEXT NOT NULL,
    CHECK (
        (kind = 'personal' AND owner_user_id IS NOT NULL) OR
        (kind = 'organization' AND owner_user_id IS NULL)
    )
);

CREATE TABLE vault_members (
    vault_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (vault_id, user_id),
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
);

CREATE TABLE vault_admins (
    vault_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (vault_id, user_id),
    FOREIGN KEY (vault_id, user_id) REFERENCES vault_members(vault_id, user_id)
        ON DELETE CASCADE
);

CREATE TABLE folders (
    vault_id TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('personal_home', 'vault_ops', 'general', 'folder')),
    access TEXT NOT NULL CHECK (access IN ('owner', 'admin_only', 'all_members', 'restricted')),
    parent_folder_id TEXT,
    parent_folder_key TEXT NOT NULL,
    path TEXT NOT NULL,
    current_key_version INTEGER NOT NULL CHECK (current_key_version > 0),
    shared_folder_source INTEGER NOT NULL CHECK (shared_folder_source IN (0, 1)),
    setup_incomplete INTEGER NOT NULL CHECK (setup_incomplete IN (0, 1)),
    created_at TEXT NOT NULL,
    PRIMARY KEY (vault_id, id),
    UNIQUE (vault_id, parent_folder_key, name),
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE,
    FOREIGN KEY (vault_id, parent_folder_id) REFERENCES folders(vault_id, id)
        ON DELETE RESTRICT
);

CREATE TABLE folder_access (
    vault_id TEXT NOT NULL,
    folder_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (vault_id, folder_id, user_id),
    FOREIGN KEY (vault_id, folder_id) REFERENCES folders(vault_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (vault_id, user_id) REFERENCES vault_members(vault_id, user_id)
        ON DELETE CASCADE
);

CREATE TABLE folder_key_grants (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    folder_id TEXT NOT NULL,
    key_version INTEGER NOT NULL CHECK (key_version > 0),
    issuer_npub TEXT NOT NULL,
    recipient_npub TEXT NOT NULL,
    format TEXT NOT NULL CHECK (format = 'NIP-59'),
    wrapped_event_json TEXT NOT NULL,
    access_change_event_json TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (vault_id, folder_id, key_version, recipient_npub),
    FOREIGN KEY (vault_id, folder_id) REFERENCES folders(vault_id, id)
        ON DELETE CASCADE
);
"#;

#[derive(Debug)]
struct StoredFolderRow {
    id: String,
    name: String,
    role: String,
    access: String,
    parent_folder_id: Option<String>,
    path: String,
    current_key_version: u32,
    shared_folder_source: bool,
}

impl StoredFolderRow {
    fn try_into_folder(self) -> Result<Folder, StoreError> {
        Ok(Folder {
            id: FolderId::new(self.id)?,
            name: DisplayName::new("folder_name", self.name)?,
            role: parse_folder_role(&self.role)?,
            access: parse_folder_access(&self.access)?,
            parent_folder_id: self.parent_folder_id.map(FolderId::new).transpose()?,
            path: SafeRelativePath::new("folder_path", self.path)?,
            current_key_version: self.current_key_version,
            shared_folder_source: self.shared_folder_source,
        })
    }
}

#[derive(Debug)]
struct StoredGrantRow {
    id: String,
    folder_id: String,
    key_version: u32,
    issuer_npub: String,
    recipient_npub: String,
    format: String,
    wrapped_event_json: String,
    access_change_event_json: Option<String>,
    created_at: String,
}

impl StoredGrantRow {
    fn try_into_grant(self) -> Result<FolderKeyGrantMetadata, StoreError> {
        Ok(FolderKeyGrantMetadata {
            id: self.id,
            folder_id: FolderId::new(self.folder_id)?,
            key_version: self.key_version,
            issuer_npub: UserId::new(self.issuer_npub)?,
            recipient_npub: UserId::new(self.recipient_npub)?,
            format: self.format,
            wrapped_event_json: self.wrapped_event_json,
            access_change_event_json: self.access_change_event_json,
            created_at: self.created_at,
        })
    }
}

fn validate_bootstrap_output(output: &BootstrapOutput) -> Result<(), StoreError> {
    validate_loaded_vault(&output.vault)?;
    if output.vault.folders.is_empty() {
        return Err(StoreError::BrokenInvariant {
            reason: "bootstrap must create at least one folder".to_owned(),
        });
    }
    Ok(())
}

fn validate_loaded_vault(vault: &Vault) -> Result<(), StoreError> {
    match vault.kind {
        VaultKind::Personal => {
            if vault.owner_user_id.is_none()
                || !vault.members.is_empty()
                || !vault.admins.is_empty()
            {
                return Err(StoreError::BrokenInvariant {
                    reason: "personal vault must have an owner and no ordinary members/admins"
                        .to_owned(),
                });
            }
        }
        VaultKind::Organization => {
            if vault.owner_user_id.is_some() || vault.admins.is_empty() {
                return Err(StoreError::BrokenInvariant {
                    reason: "organization vault must have admins and no owner".to_owned(),
                });
            }
            let members = vault
                .members
                .iter()
                .map(|member| member.user_id.clone())
                .collect::<BTreeSet<_>>();
            if vault.admins.iter().any(|admin| !members.contains(admin)) {
                return Err(StoreError::BrokenInvariant {
                    reason: "every vault admin must also be a member".to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn validate_required_grants(
    vault: &Vault,
    required: &[RequiredFolderKeyGrant],
    grants: &[FolderKeyGrantMetadata],
) -> Result<(), StoreError> {
    let provided = grants
        .iter()
        .map(|grant| {
            (
                grant.folder_id.clone(),
                grant.recipient_npub.clone(),
                grant.key_version,
            )
        })
        .collect::<BTreeSet<_>>();

    for required_grant in required {
        let key = (
            required_grant.folder_id.clone(),
            required_grant.recipient_user_id.clone(),
            required_grant.key_version,
        );
        if !provided.contains(&key) {
            return Err(StoreError::MissingRequiredGrant {
                recipient_user_id: required_grant.recipient_user_id.to_string(),
            });
        }
    }

    if grants.len() != required.len() || provided.len() != required.len() {
        return Err(StoreError::BrokenInvariant {
            reason: "bootstrap grants must exactly match required recipients".to_owned(),
        });
    }

    for grant in grants {
        validate_grant_metadata(grant)?;
        validate_grant_issuer(vault, grant)?;
    }
    Ok(())
}

fn validate_folder_grants(
    vault: &Vault,
    folder: &Folder,
    required_recipients: &BTreeSet<UserId>,
    grants: &[FolderKeyGrantMetadata],
) -> Result<(), StoreError> {
    let mut provided = BTreeSet::new();
    for grant in grants {
        validate_grant_metadata(grant)?;
        validate_grant_issuer(vault, grant)?;
        if grant.folder_id != folder.id {
            return Err(StoreError::BrokenInvariant {
                reason: "grant folder id must match folder metadata".to_owned(),
            });
        }
        if grant.key_version != folder.current_key_version {
            return Err(StoreError::BrokenInvariant {
                reason: "grant key version must match folder current key version".to_owned(),
            });
        }
        provided.insert(grant.recipient_npub.clone());
    }

    for recipient in required_recipients {
        if !provided.contains(recipient) {
            return Err(StoreError::MissingRequiredGrant {
                recipient_user_id: recipient.to_string(),
            });
        }
    }

    if &provided != required_recipients {
        return Err(StoreError::BrokenInvariant {
            reason: "grant recipients must exactly match required recipients".to_owned(),
        });
    }
    Ok(())
}

fn validate_grant_issuer(vault: &Vault, grant: &FolderKeyGrantMetadata) -> Result<(), StoreError> {
    match vault.kind {
        VaultKind::Personal => {
            if vault.owner_user_id.as_ref() != Some(&grant.issuer_npub) {
                return Err(StoreError::BrokenInvariant {
                    reason: "personal vault grants must be issued by the owner".to_owned(),
                });
            }
        }
        VaultKind::Organization => {
            if !vault.admins.contains(&grant.issuer_npub) {
                return Err(StoreError::BrokenInvariant {
                    reason: "organization folder grants must be issued by a vault admin".to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn validate_grant_metadata(grant: &FolderKeyGrantMetadata) -> Result<(), StoreError> {
    if grant.id.trim().is_empty() || grant.id.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(StoreError::BrokenInvariant {
            reason: "grant id must be non-empty and printable".to_owned(),
        });
    }
    if grant.format != GRANT_FORMAT_NIP59 {
        return Err(StoreError::BrokenInvariant {
            reason: "folder key grants must use NIP-59 format".to_owned(),
        });
    }
    if grant.wrapped_event_json.trim().is_empty() {
        return Err(StoreError::BrokenInvariant {
            reason: "folder key grant wrapped event JSON is required".to_owned(),
        });
    }
    Ok(())
}

fn validate_access_list_shape(
    folder: &Folder,
    access_user_ids: &BTreeSet<UserId>,
) -> Result<(), StoreError> {
    if folder.access != FolderAccessMode::Restricted && !access_user_ids.is_empty() {
        return Err(StoreError::BrokenInvariant {
            reason: "explicit folder access users are only valid for restricted folders".to_owned(),
        });
    }
    Ok(())
}

fn validate_hierarchy(
    conn: &Connection,
    vault_id: &VaultId,
    folder: &Folder,
) -> Result<(), StoreError> {
    let exists = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM folders WHERE vault_id = ?1 AND id = ?2)",
        params![vault_id.as_str(), folder.id.as_str()],
        |row| row.get::<_, bool>(0),
    )?;
    if exists {
        return Err(StoreError::DuplicateId {
            field: "folder_id",
            value: folder.id.to_string(),
        });
    }

    if let Some(parent_id) = &folder.parent_folder_id {
        let parent_exists = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM folders WHERE vault_id = ?1 AND id = ?2)",
            params![vault_id.as_str(), parent_id.as_str()],
            |row| row.get::<_, bool>(0),
        )?;
        if !parent_exists {
            return Err(StoreError::MissingFolder {
                folder_id: parent_id.to_string(),
            });
        }
    }

    Ok(())
}

fn validate_access_membership(
    vault: &Vault,
    access_user_ids: &BTreeSet<UserId>,
) -> Result<(), StoreError> {
    if vault.kind == VaultKind::Personal && !access_user_ids.is_empty() {
        return Err(StoreError::BrokenInvariant {
            reason: "personal vault folder access is not ordinary membership access".to_owned(),
        });
    }

    let members = vault
        .members
        .iter()
        .map(|member| member.user_id.clone())
        .collect::<BTreeSet<_>>();
    for user_id in access_user_ids {
        if !members.contains(user_id) {
            return Err(StoreError::BrokenInvariant {
                reason: format!("folder access user is not a vault member: {user_id}"),
            });
        }
    }
    Ok(())
}

fn required_recipients(
    vault: &Vault,
    folder: &Folder,
    access_user_ids: &BTreeSet<UserId>,
) -> Result<BTreeSet<UserId>, StoreError> {
    let mut recipients = BTreeSet::new();
    match folder.access {
        FolderAccessMode::Owner => {
            let owner = vault
                .owner_user_id
                .clone()
                .ok_or_else(|| StoreError::BrokenInvariant {
                    reason: "owner access requires a personal vault owner".to_owned(),
                })?;
            recipients.insert(owner);
        }
        FolderAccessMode::AdminOnly => {
            recipients.extend(vault.admins.iter().cloned());
        }
        FolderAccessMode::AllMembers => {
            recipients.extend(vault.admins.iter().cloned());
            recipients.extend(vault.members.iter().map(|member| member.user_id.clone()));
        }
        FolderAccessMode::Restricted => {
            recipients.extend(vault.admins.iter().cloned());
            recipients.extend(access_user_ids.iter().cloned());
        }
    }

    if recipients.is_empty() {
        return Err(StoreError::BrokenInvariant {
            reason: "current folder key must have at least one recipient".to_owned(),
        });
    }
    Ok(recipients)
}

fn insert_vault(tx: &Transaction<'_>, vault: &Vault) -> Result<(), StoreError> {
    tx.execute(
        r#"
        INSERT INTO vaults (id, kind, name, owner_user_id, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            vault.id.as_str(),
            vault_kind_str(vault.kind),
            vault.name.as_str(),
            vault.owner_user_id.as_ref().map(UserId::as_str),
            "2026-06-23T00:00:00.000Z"
        ],
    )
    .map_err(map_insert_error("vault_id", vault.id.as_str()))?;
    Ok(())
}

fn insert_members_and_admins(tx: &Transaction<'_>, vault: &Vault) -> Result<(), StoreError> {
    for member in &vault.members {
        tx.execute(
            "INSERT INTO vault_members (vault_id, user_id) VALUES (?1, ?2)",
            params![vault.id.as_str(), member.user_id.as_str()],
        )?;
    }
    for admin in &vault.admins {
        tx.execute(
            "INSERT INTO vault_admins (vault_id, user_id) VALUES (?1, ?2)",
            params![vault.id.as_str(), admin.as_str()],
        )?;
    }
    Ok(())
}

fn insert_folder(
    tx: &Transaction<'_>,
    vault_id: &VaultId,
    folder: &Folder,
    setup_incomplete: bool,
) -> Result<(), StoreError> {
    tx.execute(
        r#"
        INSERT INTO folders (
            vault_id, id, name, role, access, parent_folder_id, parent_folder_key, path,
            current_key_version, shared_folder_source, setup_incomplete, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
        params![
            vault_id.as_str(),
            folder.id.as_str(),
            folder.name.as_str(),
            folder_role_str(folder.role),
            folder_access_str(folder.access),
            folder.parent_folder_id.as_ref().map(FolderId::as_str),
            folder
                .parent_folder_id
                .as_ref()
                .map_or("", FolderId::as_str),
            folder.path.as_str(),
            folder.current_key_version,
            folder.shared_folder_source,
            setup_incomplete,
            "2026-06-23T00:00:00.000Z"
        ],
    )
    .map_err(map_insert_error("folder_id", folder.id.as_str()))?;
    Ok(())
}

fn insert_folder_access(
    tx: &Transaction<'_>,
    vault_id: &VaultId,
    folder_id: &FolderId,
    access_user_ids: &BTreeSet<UserId>,
) -> Result<(), StoreError> {
    for user_id in access_user_ids {
        tx.execute(
            "INSERT INTO folder_access (vault_id, folder_id, user_id) VALUES (?1, ?2, ?3)",
            params![vault_id.as_str(), folder_id.as_str(), user_id.as_str()],
        )?;
    }
    Ok(())
}

fn insert_grant(
    tx: &Transaction<'_>,
    vault_id: &VaultId,
    grant: &FolderKeyGrantMetadata,
) -> Result<(), StoreError> {
    tx.execute(
        r#"
        INSERT INTO folder_key_grants (
            id, vault_id, folder_id, key_version, issuer_npub, recipient_npub, format,
            wrapped_event_json, access_change_event_json, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
        params![
            grant.id,
            vault_id.as_str(),
            grant.folder_id.as_str(),
            grant.key_version,
            grant.issuer_npub.as_str(),
            grant.recipient_npub.as_str(),
            grant.format,
            grant.wrapped_event_json,
            grant.access_change_event_json,
            grant.created_at
        ],
    )
    .map_err(map_insert_error("folder_key_grant_id", &grant.id))?;
    Ok(())
}

fn map_insert_error(
    field: &'static str,
    value: &str,
) -> impl FnOnce(rusqlite::Error) -> StoreError {
    let value = value.to_owned();
    move |error| match error {
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(inner.code, rusqlite::ErrorCode::ConstraintViolation) =>
        {
            StoreError::DuplicateId { field, value }
        }
        other => StoreError::from(other),
    }
}

fn vault_kind_str(kind: VaultKind) -> &'static str {
    match kind {
        VaultKind::Personal => "personal",
        VaultKind::Organization => "organization",
    }
}

fn parse_vault_kind(value: &str) -> Result<VaultKind, StoreError> {
    match value {
        "personal" => Ok(VaultKind::Personal),
        "organization" => Ok(VaultKind::Organization),
        _ => Err(StoreError::BrokenInvariant {
            reason: format!("unknown vault kind: {value}"),
        }),
    }
}

fn folder_role_str(role: FolderRole) -> &'static str {
    match role {
        FolderRole::PersonalHome => "personal_home",
        FolderRole::VaultOps => "vault_ops",
        FolderRole::General => "general",
        FolderRole::Folder => "folder",
    }
}

fn parse_folder_role(value: &str) -> Result<FolderRole, StoreError> {
    match value {
        "personal_home" => Ok(FolderRole::PersonalHome),
        "vault_ops" => Ok(FolderRole::VaultOps),
        "general" => Ok(FolderRole::General),
        "folder" => Ok(FolderRole::Folder),
        _ => Err(StoreError::BrokenInvariant {
            reason: format!("unknown folder role: {value}"),
        }),
    }
}

fn folder_access_str(access: FolderAccessMode) -> &'static str {
    match access {
        FolderAccessMode::Owner => "owner",
        FolderAccessMode::AdminOnly => "admin_only",
        FolderAccessMode::AllMembers => "all_members",
        FolderAccessMode::Restricted => "restricted",
    }
}

fn parse_folder_access(value: &str) -> Result<FolderAccessMode, StoreError> {
    match value {
        "owner" => Ok(FolderAccessMode::Owner),
        "admin_only" => Ok(FolderAccessMode::AdminOnly),
        "all_members" => Ok(FolderAccessMode::AllMembers),
        "restricted" => Ok(FolderAccessMode::Restricted),
        _ => Err(StoreError::BrokenInvariant {
            reason: format!("unknown folder access mode: {value}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use finite_brain_core::{bootstrap_organization_vault, bootstrap_personal_vault};
    use tempfile::TempDir;

    #[test]
    fn exposes_store_crate_name() {
        assert_eq!(crate_name(), "finite-brain-store");
    }

    #[test]
    fn persists_and_reloads_personal_bootstrap() {
        let temp = TempDir::new().unwrap();
        let db = temp.path().join("vault-sync.sqlite3");
        let output = bootstrap_personal_vault("personal", "Austin", "npub-owner").unwrap();
        let grants = grants_for_required(&output.required_key_grants, "npub-owner");

        {
            let mut store = BrainStore::open(&db).unwrap();
            store.create_vault_bootstrap(&output, &grants).unwrap();
        }

        let store = BrainStore::open(&db).unwrap();
        let stored = store
            .load_vault(&VaultId::new("personal").unwrap())
            .unwrap();

        assert_eq!(stored.vault.kind, VaultKind::Personal);
        assert_eq!(
            stored.vault.owner_user_id,
            Some(UserId::new("npub-owner").unwrap())
        );
        assert_eq!(stored.vault.folders.len(), 1);
        assert_eq!(stored.vault.folders[0].id, FolderId::new("home").unwrap());
        assert_same_grants(&stored.grants, &grants);
        assert!(stored.setup_incomplete_folder_ids.is_empty());
    }

    #[test]
    fn persists_and_reloads_organization_bootstrap() {
        let temp = TempDir::new().unwrap();
        let db = temp.path().join("vault-sync.sqlite3");
        let output = bootstrap_organization_vault("acme", "Acme", "npub-admin").unwrap();
        let grants = grants_for_required(&output.required_key_grants, "npub-admin");

        {
            let mut store = BrainStore::open(&db).unwrap();
            store.create_vault_bootstrap(&output, &grants).unwrap();
        }

        let store = BrainStore::open(&db).unwrap();
        let stored = store.load_vault(&VaultId::new("acme").unwrap()).unwrap();

        assert_eq!(stored.vault.kind, VaultKind::Organization);
        assert_eq!(stored.vault.members.len(), 1);
        assert_eq!(
            stored.vault.admins,
            vec![UserId::new("npub-admin").unwrap()]
        );
        assert_eq!(
            stored
                .vault
                .folders
                .iter()
                .map(|folder| folder.id.to_string())
                .collect::<Vec<_>>(),
            vec!["general".to_owned(), "vault-ops".to_owned()]
        );
        assert_same_grants(&stored.grants, &grants);
    }

    #[test]
    fn creates_restricted_folder_with_required_grants_transactionally() {
        let mut store = bootstrapped_org_store();
        let vault_id = VaultId::new("acme").unwrap();
        let member = UserId::new("npub-member").unwrap();
        store.add_member(&vault_id, &member).unwrap();

        let folder = strategy_folder();
        let access_user_ids = BTreeSet::from([member.clone()]);
        let grants = vec![
            grant(
                "grant-strategy-admin",
                "strategy",
                1,
                "npub-admin",
                "npub-admin",
            ),
            grant(
                "grant-strategy-member",
                "strategy",
                1,
                "npub-admin",
                member.as_str(),
            ),
        ];

        store
            .create_folder(&vault_id, &folder, &access_user_ids, &grants)
            .unwrap();
        let stored = store.load_vault(&vault_id).unwrap();

        assert!(stored.vault.folders.iter().any(|stored| stored == &folder));
        assert_eq!(
            stored.folder_access.get(&folder.id),
            Some(&BTreeSet::from([member]))
        );
        for expected_grant in grants {
            assert!(stored.grants.contains(&expected_grant));
        }
    }

    #[test]
    fn rejects_missing_required_grant_without_partial_folder() {
        let mut store = bootstrapped_org_store();
        let vault_id = VaultId::new("acme").unwrap();
        let member = UserId::new("npub-member").unwrap();
        store.add_member(&vault_id, &member).unwrap();

        let folder = strategy_folder();
        let access_user_ids = BTreeSet::from([member]);
        let grants = vec![grant(
            "grant-strategy-admin",
            "strategy",
            1,
            "npub-admin",
            "npub-admin",
        )];

        assert_eq!(
            store
                .create_folder(&vault_id, &folder, &access_user_ids, &grants)
                .unwrap_err(),
            StoreError::MissingRequiredGrant {
                recipient_user_id: "npub-member".to_owned()
            }
        );
        assert!(!store.folder_exists(&vault_id, &folder.id).unwrap());
    }

    #[test]
    fn rolls_back_folder_creation_when_grant_insert_fails() {
        let mut store = bootstrapped_org_store();
        let vault_id = VaultId::new("acme").unwrap();
        assert!(store.grant_exists("grant-general-npub-admin").unwrap());

        let folder = strategy_folder();
        let grants = vec![grant(
            "grant-general-npub-admin",
            "strategy",
            1,
            "npub-admin",
            "npub-admin",
        )];

        assert!(matches!(
            store
                .create_folder(&vault_id, &folder, &BTreeSet::new(), &grants)
                .unwrap_err(),
            StoreError::DuplicateId {
                field: "folder_key_grant_id",
                ..
            }
        ));
        assert!(!store.folder_exists(&vault_id, &folder.id).unwrap());
    }

    #[test]
    fn detects_and_repairs_setup_incomplete_folder_across_restart() {
        let temp = TempDir::new().unwrap();
        let db = temp.path().join("vault-sync.sqlite3");
        let vault_id = VaultId::new("acme").unwrap();
        let folder = strategy_folder();
        let grants = vec![grant(
            "grant-strategy-admin",
            "strategy",
            1,
            "npub-admin",
            "npub-admin",
        )];

        {
            let mut store = BrainStore::open(&db).unwrap();
            let output = bootstrap_organization_vault("acme", "Acme", "npub-admin").unwrap();
            let bootstrap_grants = grants_for_required(&output.required_key_grants, "npub-admin");
            store
                .create_vault_bootstrap(&output, &bootstrap_grants)
                .unwrap();
            store
                .insert_setup_incomplete_folder_for_repair(&vault_id, &folder, &BTreeSet::new())
                .unwrap();
        }

        {
            let mut store = BrainStore::open(&db).unwrap();
            let stored = store.load_vault(&vault_id).unwrap();
            assert_eq!(
                stored.setup_incomplete_folder_ids,
                BTreeSet::from([folder.id.clone()])
            );

            store
                .finish_folder_setup(&vault_id, &folder.id, &grants)
                .unwrap();
        }

        let store = BrainStore::open(&db).unwrap();
        let stored = store.load_vault(&vault_id).unwrap();
        assert!(stored.setup_incomplete_folder_ids.is_empty());
        assert!(stored.grants.contains(&grants[0]));
    }

    #[test]
    fn rejects_invalid_hierarchy_duplicate_ids_and_admin_invariants() {
        let mut store = bootstrapped_org_store();
        let vault_id = VaultId::new("acme").unwrap();

        let mut missing_parent = strategy_folder();
        missing_parent.parent_folder_id = Some(FolderId::new("missing").unwrap());
        missing_parent.path = SafeRelativePath::new("folder_path", "Missing/Strategy").unwrap();
        assert_eq!(
            store
                .create_folder(
                    &vault_id,
                    &missing_parent,
                    &BTreeSet::new(),
                    &[grant(
                        "grant-missing-parent",
                        "strategy",
                        1,
                        "npub-admin",
                        "npub-admin"
                    )],
                )
                .unwrap_err(),
            StoreError::MissingFolder {
                folder_id: "missing".to_owned()
            }
        );

        let folder = strategy_folder();
        let grants = vec![grant(
            "grant-strategy-admin",
            "strategy",
            1,
            "npub-admin",
            "npub-admin",
        )];
        store
            .create_folder(&vault_id, &folder, &BTreeSet::new(), &grants)
            .unwrap();
        assert_eq!(
            store
                .create_folder(
                    &vault_id,
                    &folder,
                    &BTreeSet::new(),
                    &[grant(
                        "grant-strategy-admin-2",
                        "strategy",
                        1,
                        "npub-admin",
                        "npub-admin"
                    )],
                )
                .unwrap_err(),
            StoreError::DuplicateId {
                field: "folder_id",
                value: "strategy".to_owned()
            }
        );

        assert_eq!(
            store
                .add_admin(&vault_id, &UserId::new("npub-non-member").unwrap())
                .unwrap_err(),
            StoreError::BrokenInvariant {
                reason: "vault admin must already be a vault member".to_owned()
            }
        );

        let bad_issuer_folder = Folder {
            id: FolderId::new("bad-issuer-strategy").unwrap(),
            name: DisplayName::new("folder_name", "Bad Issuer Strategy").unwrap(),
            path: SafeRelativePath::new("folder_path", "general/Bad Issuer Strategy").unwrap(),
            ..strategy_folder()
        };
        assert_eq!(
            store
                .create_folder(
                    &vault_id,
                    &bad_issuer_folder,
                    &BTreeSet::new(),
                    &[grant(
                        "grant-bad-issuer",
                        "bad-issuer-strategy",
                        1,
                        "npub-non-admin",
                        "npub-admin"
                    )],
                )
                .unwrap_err(),
            StoreError::BrokenInvariant {
                reason: "organization folder grants must be issued by a vault admin".to_owned()
            }
        );
        assert!(
            !store
                .folder_exists(&vault_id, &bad_issuer_folder.id)
                .unwrap()
        );
    }

    #[test]
    fn rejects_personal_member_mutation() {
        let mut store = BrainStore::open_in_memory().unwrap();
        let output = bootstrap_personal_vault("personal", "Austin", "npub-owner").unwrap();
        let grants = grants_for_required(&output.required_key_grants, "npub-owner");
        store.create_vault_bootstrap(&output, &grants).unwrap();

        assert_eq!(
            store
                .add_member(
                    &VaultId::new("personal").unwrap(),
                    &UserId::new("npub-member").unwrap(),
                )
                .unwrap_err(),
            StoreError::BrokenInvariant {
                reason: "member/admin mutation requires an organization vault".to_owned()
            }
        );
    }

    fn bootstrapped_org_store() -> BrainStore {
        let mut store = BrainStore::open_in_memory().unwrap();
        let output = bootstrap_organization_vault("acme", "Acme", "npub-admin").unwrap();
        let grants = grants_for_required(&output.required_key_grants, "npub-admin");
        store.create_vault_bootstrap(&output, &grants).unwrap();
        store
    }

    fn strategy_folder() -> Folder {
        Folder {
            id: FolderId::new("strategy").unwrap(),
            name: DisplayName::new("folder_name", "Strategy").unwrap(),
            role: FolderRole::Folder,
            access: FolderAccessMode::Restricted,
            parent_folder_id: Some(FolderId::new("general").unwrap()),
            path: SafeRelativePath::new("folder_path", "general/Strategy").unwrap(),
            current_key_version: 1,
            shared_folder_source: false,
        }
    }

    fn grants_for_required(
        required: &[RequiredFolderKeyGrant],
        issuer: &str,
    ) -> Vec<FolderKeyGrantMetadata> {
        required
            .iter()
            .map(|required| {
                grant(
                    &format!(
                        "grant-{}-{}",
                        required.folder_id,
                        required.recipient_user_id.as_str()
                    ),
                    required.folder_id.as_str(),
                    required.key_version,
                    issuer,
                    required.recipient_user_id.as_str(),
                )
            })
            .collect()
    }

    fn assert_same_grants(actual: &[FolderKeyGrantMetadata], expected: &[FolderKeyGrantMetadata]) {
        assert_eq!(actual.len(), expected.len());
        for grant in expected {
            assert!(actual.contains(grant), "missing grant: {grant:?}");
        }
    }

    fn grant(
        id: &str,
        folder_id: &str,
        key_version: u32,
        issuer: &str,
        recipient: &str,
    ) -> FolderKeyGrantMetadata {
        FolderKeyGrantMetadata {
            id: id.to_owned(),
            folder_id: FolderId::new(folder_id).unwrap(),
            key_version,
            issuer_npub: UserId::new(issuer).unwrap(),
            recipient_npub: UserId::new(recipient).unwrap(),
            format: GRANT_FORMAT_NIP59.to_owned(),
            wrapped_event_json: "{\"kind\":1059}".to_owned(),
            access_change_event_json: Some("{\"kind\":30078}".to_owned()),
            created_at: "2026-06-23T00:00:00.000Z".to_owned(),
        }
    }
}
