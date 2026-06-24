//! Portable readable export/import and local index planning.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CoreError, FolderAccessMode, FolderId, ObjectId, SafeRelativePath, UserId, Vault};

/// Portability-layer errors.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PortabilityError {
    /// Core validation failed.
    Core(CoreError),
    /// A bundle path would be duplicated.
    DuplicateBundlePath { path: String },
    /// A source page path was duplicated in one Folder.
    DuplicatePagePath { folder_id: String, path: String },
    /// Overwrite was requested without explicit confirmation.
    OverwriteRequiresConfirmation,
    /// A readable working-tree path collided with another materialized path.
    WorkingTreePathCollision { path: String },
}

impl fmt::Display for PortabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(f, "{error}"),
            Self::DuplicateBundlePath { path } => write!(f, "duplicate OKF bundle path: {path}"),
            Self::DuplicatePagePath { folder_id, path } => {
                write!(f, "duplicate opened page path in {folder_id}: {path}")
            }
            Self::OverwriteRequiresConfirmation => {
                write!(f, "OKF overwrite import requires explicit confirmation")
            }
            Self::WorkingTreePathCollision { path } => {
                write!(f, "working tree path collision: {path}")
            }
        }
    }
}

impl Error for PortabilityError {}

impl From<CoreError> for PortabilityError {
    fn from(value: CoreError) -> Self {
        Self::Core(value)
    }
}

/// One decrypted page that the caller already proved accessible.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OpenedPage {
    /// Folder containing the page.
    pub folder_id: FolderId,
    /// Current encrypted object id.
    pub object_id: ObjectId,
    /// Display path of the containing Folder in a readable bundle.
    pub folder_display_path: SafeRelativePath,
    /// Plaintext path inside the Folder.
    pub page_path: SafeRelativePath,
    /// Decrypted Markdown body.
    pub markdown: String,
    /// Current object revision.
    pub revision: u64,
    /// Folder Key version used by the current object.
    pub key_version: u32,
    /// MIME content type.
    pub content_type: String,
}

/// Omitted Folder marker for readable exports.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OkfOmittedFolder {
    /// Folder id.
    pub folder_id: FolderId,
    /// User-visible Folder path. Page-level details remain omitted.
    pub display_path: SafeRelativePath,
    /// Omission reason.
    pub reason: String,
}

/// OKF export input.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OkfExportInput {
    /// Export timestamp.
    pub exported_at: String,
    /// Acting npub.
    pub exported_by_npub: UserId,
    /// Source Vault metadata.
    pub source_vault: Vault,
    /// Decrypted pages visible to the actor.
    pub opened_pages: Vec<OpenedPage>,
    /// Folder-level omissions. These must not contain page paths or snippets.
    pub omissions: Vec<OkfOmittedFolder>,
}

/// Readable OKF bundle.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OkfBundle {
    /// Manifest.
    pub manifest: OkfManifest,
    /// Safe relative bundle path to UTF-8 file contents.
    pub files: BTreeMap<String, String>,
}

/// `okf-vault.json`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OkfManifest {
    /// Manifest version.
    pub version: String,
    /// Export timestamp.
    pub exported_at: String,
    /// Acting npub.
    pub exported_by_npub: String,
    /// Source Vault summary.
    pub source_vault: OkfSourceVault,
    /// Folder manifest entries.
    pub folders: Vec<OkfFolderManifestEntry>,
    /// Exported object entries.
    pub objects: Vec<OkfObjectManifestEntry>,
    /// Omitted folder entries.
    pub omissions: Vec<OkfOmissionManifestEntry>,
}

/// Source Vault summary in OKF.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OkfSourceVault {
    /// Vault id.
    pub id: String,
    /// Vault kind.
    pub kind: String,
    /// Vault name.
    pub name: String,
}

/// Folder entry in `okf-vault.json`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OkfFolderManifestEntry {
    /// Folder id.
    pub folder_id: String,
    /// Readable Folder path.
    pub display_path: String,
    /// Access mode.
    pub access: FolderAccessMode,
    /// True when the Folder was omitted.
    pub omitted: bool,
}

/// Object entry in `okf-vault.json`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OkfObjectManifestEntry {
    /// Folder id.
    pub folder_id: String,
    /// Object id.
    pub object_id: String,
    /// Bundle path.
    pub path: String,
    /// MIME content type.
    pub content_type: String,
    /// SHA-256 of exported plaintext bytes.
    pub content_hash: String,
}

/// Omission entry in `okf-vault.json`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OkfOmissionManifestEntry {
    /// Folder id.
    pub folder_id: String,
    /// Readable Folder path.
    pub display_path: String,
    /// Reason, for example `inaccessible`.
    pub reason: String,
}

/// Local search/index document derived from decrypted content.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LocalSearchDocument {
    /// Folder id.
    pub folder_id: FolderId,
    /// Object id.
    pub object_id: ObjectId,
    /// Plaintext page path.
    pub page_path: SafeRelativePath,
    /// Search title.
    pub title: String,
    /// Decrypted text body.
    pub body: String,
}

/// OKF import conflict mode.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OkfConflictMode {
    /// Do not import colliding pages.
    Skip,
    /// Import colliding pages at a clear suffixed path.
    Copy,
    /// Overwrite colliding pages only when confirmed.
    Overwrite { confirmed: bool },
}

/// Imported readable page before client-side encryption/upload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OkfImportPage {
    /// Source bundle path.
    pub source_path: SafeRelativePath,
    /// Destination Folder.
    pub folder_id: FolderId,
    /// Desired destination plaintext path.
    pub target_path: SafeRelativePath,
    /// Markdown content.
    pub markdown: String,
}

/// Existing accessible destination page path.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExistingPagePath {
    /// Destination Folder.
    pub folder_id: FolderId,
    /// Plaintext path.
    pub page_path: SafeRelativePath,
    /// Existing object id.
    pub object_id: ObjectId,
}

/// OKF import action.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OkfImportAction {
    /// Create a new encrypted object.
    Create,
    /// Skip because of a conflict.
    Skip,
    /// Create a suffixed copy.
    Copy,
    /// Overwrite an existing object.
    Overwrite,
}

/// One planned OKF import write.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OkfImportPlanEntry {
    /// Source bundle path.
    pub source_path: SafeRelativePath,
    /// Destination Folder.
    pub folder_id: FolderId,
    /// Final destination plaintext path.
    pub target_path: SafeRelativePath,
    /// Import action.
    pub action: OkfImportAction,
}

/// OKF import plan.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OkfImportPlan {
    /// Planned entries in input order.
    pub entries: Vec<OkfImportPlanEntry>,
}

/// Input for materializing a Vault Working Tree from already-opened content.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WorkingTreeMaterializeInput {
    /// Materialization timestamp.
    pub generated_at: String,
    /// Acting npub.
    pub generated_by_npub: UserId,
    /// Source Vault metadata.
    pub vault: Vault,
    /// Decrypted pages visible to the actor.
    pub opened_pages: Vec<OpenedPage>,
    /// Folder-level omissions that must not leak Page details.
    pub locked_folders: Vec<OkfOmittedFolder>,
    /// Latest sync sequence observed by the client.
    pub latest_sequence: u64,
}

/// File-map projection of a Vault Working Tree.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WorkingTreeProjection {
    /// Files to write, keyed by safe relative path from the working-tree root.
    pub files: BTreeMap<String, String>,
    /// Parsed Vault Directory manifest.
    pub directory: VaultDirectoryManifest,
    /// Parsed working-tree state manifest.
    pub state: VaultWorkingTreeStateManifest,
}

/// `.finitebrain/vault-directory.json`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDirectoryManifest {
    /// Manifest version.
    pub version: String,
    /// Vault summary.
    pub vault: VaultDirectoryVaultSummary,
    /// Working-tree root marker.
    pub working_tree: VaultDirectoryPath,
    /// Encrypted sync mirror marker.
    pub encrypted_sync: VaultDirectoryPath,
    /// Ownership flags.
    pub portability: VaultDirectoryPortability,
    /// Creation timestamp.
    pub created_at: String,
    /// Update timestamp.
    pub updated_at: String,
}

/// Vault summary in a Vault Directory manifest.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDirectoryVaultSummary {
    /// Vault id.
    pub id: String,
    /// Vault kind.
    pub kind: String,
    /// Vault name.
    pub name: String,
    /// Owner npub for personal Vaults.
    pub owner_npub: Option<String>,
}

/// Path entry in a Vault Directory manifest.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultDirectoryPath {
    /// Safe relative path.
    pub path: String,
}

/// Ownership flags in a Vault Directory manifest.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDirectoryPortability {
    /// True when an Agent Runtime owns writes for this directory.
    pub owned_by_agent_runtime: bool,
    /// True when an app surface owns writes for this directory.
    pub owned_by_app_surface: bool,
}

/// `.finitebrain/working-tree-state.json`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultWorkingTreeStateManifest {
    /// Manifest version.
    pub version: String,
    /// Folder roots materialized in the working tree.
    pub folder_roots: Vec<WorkingTreeFolderRoot>,
    /// Materialized readable objects.
    pub objects: Vec<WorkingTreeObjectManifestEntry>,
    /// Latest sync position.
    pub sync: WorkingTreeSyncState,
}

/// Folder root in the working-tree state.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkingTreeFolderRoot {
    /// Folder id.
    pub folder_id: String,
    /// Materialized Folder path.
    pub path: String,
    /// Whether plaintext files may be read.
    pub can_read: bool,
    /// True when only safe metadata was materialized.
    pub metadata_only: bool,
}

/// Object entry in the working-tree state.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkingTreeObjectManifestEntry {
    /// Folder id.
    pub folder_id: String,
    /// Plaintext path inside the Folder root.
    pub path: String,
    /// Folder Object id.
    pub object_id: String,
    /// Current revision.
    pub revision: u64,
    /// Current Folder Key version.
    pub key_version: u32,
    /// Content type.
    pub content_type: String,
    /// SHA-256 of plaintext bytes.
    pub content_hash: String,
}

/// Sync state in the working-tree manifest.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkingTreeSyncState {
    /// Latest applied sync sequence.
    pub latest_sequence: u64,
}

/// Local file change detected in a Vault Working Tree.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum WorkingTreeChange {
    /// Create or update a plaintext file.
    Upsert {
        /// Working-tree relative path.
        path: SafeRelativePath,
        /// New Markdown contents.
        markdown: String,
    },
    /// Rename or move a plaintext file.
    Rename {
        /// Source working-tree relative path.
        from_path: SafeRelativePath,
        /// Destination working-tree relative path.
        to_path: SafeRelativePath,
    },
    /// Delete a plaintext file.
    Delete {
        /// Working-tree relative path.
        path: SafeRelativePath,
    },
}

/// Product Client route family needed to turn a working-tree intent into sync.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WorkingTreeIntentRoute {
    /// Encrypt content, sign a Folder Object revision, and PUT the secure object route.
    EncryptedObjectWrite,
    /// Sign a Folder Object move through the secure move route.
    EncryptedObjectMove,
    /// Sign a Folder Object tombstone through the secure delete route.
    EncryptedObjectDelete,
    /// No automatic secure route can be chosen.
    Unresolved,
}

/// Action for a working-tree change intent.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WorkingTreeIntentAction {
    /// Create a new Folder Object.
    Create,
    /// Update an existing Folder Object.
    Update,
    /// Move or rename an existing Folder Object.
    Move,
    /// Delete an existing Folder Object.
    Delete,
    /// Leave unresolved for app/human handling.
    Unresolved,
}

/// One Product Client intent derived from a local working-tree change.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WorkingTreeChangeIntent {
    /// Intended action.
    pub action: WorkingTreeIntentAction,
    /// Secure route family the Product Client must use.
    pub route: WorkingTreeIntentRoute,
    /// Destination/source Folder id when known.
    pub folder_id: Option<FolderId>,
    /// Existing or generated Object id when known.
    pub object_id: Option<ObjectId>,
    /// Path inside the Folder root when known.
    pub target_path: Option<SafeRelativePath>,
    /// Previous path for moves.
    pub from_path: Option<SafeRelativePath>,
    /// Base revision for update/move/delete when known.
    pub base_revision: Option<u64>,
    /// Plaintext markdown for create/update. The Product Client encrypts it before upload.
    pub markdown: Option<String>,
    /// Reason when unresolved.
    pub reason: Option<String>,
}

mod agents;
mod okf;
mod search;
mod working_tree;

pub use agents::agent_discovery_paths;
pub use okf::{export_okf_bundle, plan_okf_import};
pub use search::build_local_search_index;
pub use working_tree::{materialize_vault_working_tree, plan_working_tree_change_intents};

fn safe_locked_reason(reason: &str) -> &'static str {
    match reason {
        "missing-folder-key" => "missing-folder-key",
        "no-folder-access" => "no-folder-access",
        _ => "inaccessible",
    }
}

fn collect_tags(files: &BTreeMap<String, String>) -> Vec<String> {
    let mut tags = BTreeSet::new();
    for body in files.values() {
        for word in body.split_whitespace() {
            let tag = word
                .strip_prefix('#')
                .map(|value| value.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-'));
            if let Some(tag) = tag.filter(|value| !value.is_empty()) {
                tags.insert(format!("- #{tag}"));
            }
        }
    }
    tags.into_iter().collect()
}

fn markdown_title(markdown: &str) -> Option<String> {
    markdown
        .lines()
        .find_map(|line| line.strip_prefix("# ").map(str::trim))
        .filter(|title| !title.is_empty())
        .map(ToOwned::to_owned)
}

fn title_from_path(path: &SafeRelativePath) -> String {
    path.as_str()
        .rsplit('/')
        .next()
        .unwrap_or(path.as_str())
        .trim_end_matches(".md")
        .replace('-', " ")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DisplayName, Folder, FolderRole, VaultId, VaultKind};

    #[test]
    fn okf_export_omits_inaccessible_pages_and_rewrites_only_present_links() {
        let vault = sample_vault();
        let bundle = export_okf_bundle(OkfExportInput {
            exported_at: "2026-06-23T00:00:00.000Z".to_owned(),
            exported_by_npub: UserId::new("npub-admin").unwrap(),
            source_vault: vault,
            opened_pages: vec![
                page(
                    "concepts",
                    "obj_000000000001",
                    "Concepts",
                    "index.md",
                    "# Index\n\nSee [Allowed](allowed.md) and [Secret](../Board/secret-plan.md). #okf",
                ),
                page(
                    "concepts",
                    "obj_000000000002",
                    "Concepts",
                    "allowed.md",
                    "# Allowed\n\nReadable page.",
                ),
                page(
                    "concepts",
                    "obj_000000000003",
                    "Concepts",
                    "_wiki/index.md",
                    "# Local Wiki\n\nOrdinary accessible content.",
                ),
            ],
            omissions: vec![OkfOmittedFolder {
                folder_id: FolderId::new("board").unwrap(),
                display_path: SafeRelativePath::new("folder_path", "Board").unwrap(),
                reason: "missing key for Board/secret-plan.md".to_owned(),
            }],
        })
        .unwrap();

        let index = bundle.files.get("content/Concepts/index.md").unwrap();
        assert!(index.contains("[Allowed](allowed.md)"));
        assert!(index.contains("Secret"));
        assert!(!index.contains("secret-plan.md"));
        assert!(bundle.files.contains_key("content/Concepts/_wiki/index.md"));
        assert!(bundle.files.contains_key("_wiki/index.md"));
        let all_exported_text = bundle.files.values().cloned().collect::<String>();
        assert!(!all_exported_text.contains("secret-plan"));
        assert_eq!(bundle.manifest.omissions[0].folder_id, "board");
        assert_eq!(bundle.manifest.omissions[0].reason, "inaccessible");
        assert!(
            bundle
                .manifest
                .objects
                .iter()
                .all(|object| !object.path.contains("Board"))
        );
    }

    #[test]
    fn okf_export_rejects_duplicate_bundle_paths() {
        assert_eq!(
            export_okf_bundle(OkfExportInput {
                exported_at: "2026-06-23T00:00:00.000Z".to_owned(),
                exported_by_npub: UserId::new("npub-admin").unwrap(),
                source_vault: sample_vault(),
                opened_pages: vec![
                    page(
                        "concepts",
                        "obj_000000000001",
                        "Same",
                        "index.md",
                        "# First",
                    ),
                    page("board", "obj_000000000002", "Same", "index.md", "# Second"),
                ],
                omissions: Vec::new(),
            })
            .unwrap_err(),
            PortabilityError::DuplicateBundlePath {
                path: "content/Same/index.md".to_owned()
            }
        );
    }

    #[test]
    fn local_search_and_agent_discovery_use_accessible_plaintext_only() {
        let pages = vec![page(
            "concepts",
            "obj_000000000001",
            "Concepts",
            "compiled/deep/module.md",
            "# Deep Module\n\nOnly accessible text is indexed.",
        )];
        let index = build_local_search_index(&pages);
        assert_eq!(index.len(), 1);
        assert_eq!(index[0].title, "Deep Module");
        assert!(index[0].body.contains("accessible text"));

        let candidates = agent_discovery_paths(&pages[0].page_path).unwrap();
        assert_eq!(
            candidates
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec![
                "compiled/deep/AGENTS.md".to_owned(),
                "compiled/AGENTS.md".to_owned(),
                "AGENTS.md".to_owned()
            ]
        );
    }

    #[test]
    fn working_tree_materializes_accessible_pages_and_safe_agent_conventions() {
        let mut opened = page(
            "concepts",
            "obj_000000000001",
            "Concepts",
            "compiled/deep/module.md",
            "# Deep Module\n\nOnly accessible text is materialized. #agent",
        );
        opened.revision = 7;
        opened.key_version = 3;
        let projection = materialize_vault_working_tree(WorkingTreeMaterializeInput {
            generated_at: "2026-06-24T00:00:00.000Z".to_owned(),
            generated_by_npub: UserId::new("npub-admin").unwrap(),
            vault: sample_vault(),
            opened_pages: vec![opened],
            locked_folders: vec![OkfOmittedFolder {
                folder_id: FolderId::new("board").unwrap(),
                display_path: SafeRelativePath::new("folder_path", "Board").unwrap(),
                reason: "inaccessible secret-plan".to_owned(),
            }],
            latest_sequence: 42,
        })
        .unwrap();

        assert!(
            projection
                .files
                .contains_key(".finitebrain/vault-directory.json")
        );
        assert!(
            projection
                .files
                .contains_key(".finitebrain/working-tree-state.json")
        );
        assert!(projection.files.contains_key("AGENTS.md"));
        assert!(projection.files.contains_key("_index.md"));
        assert!(projection.files.contains_key("_wiki/index.md"));
        assert!(projection.files.contains_key("Concepts/AGENTS.md"));
        assert!(projection.files.contains_key("Concepts/_index.md"));
        assert!(projection.files.contains_key("Concepts/_wiki/index.md"));
        assert!(projection.files.contains_key("Concepts/raw/.keep"));
        assert!(projection.files.contains_key("Concepts/compiled/.keep"));
        assert!(projection.files.contains_key("Concepts/output/.keep"));
        assert_eq!(
            projection
                .files
                .get("Concepts/compiled/deep/module.md")
                .unwrap(),
            "# Deep Module\n\nOnly accessible text is materialized. #agent"
        );

        let concepts = projection
            .state
            .folder_roots
            .iter()
            .find(|root| root.folder_id == "concepts")
            .unwrap();
        assert!(concepts.can_read);
        assert!(!concepts.metadata_only);
        let board = projection
            .state
            .folder_roots
            .iter()
            .find(|root| root.folder_id == "board")
            .unwrap();
        assert!(!board.can_read);
        assert!(board.metadata_only);
        assert_eq!(projection.state.objects[0].revision, 7);
        assert_eq!(projection.state.objects[0].key_version, 3);
        assert_eq!(projection.state.objects[0].content_hash.len(), 64);
        assert_eq!(projection.state.sync.latest_sequence, 42);
        assert_eq!(
            projection.directory.encrypted_sync.path,
            ".finitebrain/encrypted-sync"
        );

        let all_materialized_text = projection.files.values().cloned().collect::<String>();
        assert!(!all_materialized_text.contains("secret-plan"));
        assert!(!all_materialized_text.contains("Secret Page"));
        assert!(!all_materialized_text.contains("Board/"));
    }

    #[test]
    fn working_tree_change_intents_use_encrypted_product_client_routes() {
        let mut opened = page(
            "concepts",
            "obj_000000000001",
            "Concepts",
            "compiled/deep/module.md",
            "# Deep Module",
        );
        opened.revision = 7;
        let projection = materialize_vault_working_tree(WorkingTreeMaterializeInput {
            generated_at: "2026-06-24T00:00:00.000Z".to_owned(),
            generated_by_npub: UserId::new("npub-admin").unwrap(),
            vault: sample_vault(),
            opened_pages: vec![opened],
            locked_folders: vec![OkfOmittedFolder {
                folder_id: FolderId::new("board").unwrap(),
                display_path: SafeRelativePath::new("folder_path", "Board").unwrap(),
                reason: "inaccessible".to_owned(),
            }],
            latest_sequence: 42,
        })
        .unwrap();

        let intents = plan_working_tree_change_intents(
            &projection.state,
            &[
                WorkingTreeChange::Upsert {
                    path: SafeRelativePath::new("change_path", "Concepts/compiled/deep/module.md")
                        .unwrap(),
                    markdown: "# Deep Module\n\nUpdated.".to_owned(),
                },
                WorkingTreeChange::Upsert {
                    path: SafeRelativePath::new("change_path", "Concepts/raw/new.md").unwrap(),
                    markdown: "# New".to_owned(),
                },
                WorkingTreeChange::Rename {
                    from_path: SafeRelativePath::new(
                        "change_path",
                        "Concepts/compiled/deep/module.md",
                    )
                    .unwrap(),
                    to_path: SafeRelativePath::new(
                        "change_path",
                        "Concepts/compiled/deep/module-renamed.md",
                    )
                    .unwrap(),
                },
                WorkingTreeChange::Delete {
                    path: SafeRelativePath::new("change_path", "Concepts/compiled/deep/module.md")
                        .unwrap(),
                },
                WorkingTreeChange::Rename {
                    from_path: SafeRelativePath::new(
                        "change_path",
                        "Concepts/compiled/deep/module.md",
                    )
                    .unwrap(),
                    to_path: SafeRelativePath::new("change_path", "Board/secret.md").unwrap(),
                },
            ],
        );

        assert_eq!(intents[0].action, WorkingTreeIntentAction::Update);
        assert_eq!(
            intents[0].route,
            WorkingTreeIntentRoute::EncryptedObjectWrite
        );
        assert_eq!(intents[0].base_revision, Some(7));
        assert_eq!(
            intents[0].object_id,
            Some(ObjectId::new("obj_000000000001").unwrap())
        );
        assert_eq!(intents[1].action, WorkingTreeIntentAction::Create);
        assert_eq!(
            intents[1].route,
            WorkingTreeIntentRoute::EncryptedObjectWrite
        );
        assert!(intents[1].object_id.is_some());
        assert_eq!(intents[1].base_revision, None);
        assert_eq!(intents[2].action, WorkingTreeIntentAction::Move);
        assert_eq!(
            intents[2].route,
            WorkingTreeIntentRoute::EncryptedObjectMove
        );
        assert_eq!(intents[2].base_revision, Some(7));
        assert_eq!(intents[3].action, WorkingTreeIntentAction::Delete);
        assert_eq!(
            intents[3].route,
            WorkingTreeIntentRoute::EncryptedObjectDelete
        );
        assert_eq!(intents[3].base_revision, Some(7));
        assert_eq!(intents[4].action, WorkingTreeIntentAction::Unresolved);
        assert_eq!(intents[4].route, WorkingTreeIntentRoute::Unresolved);
        assert!(intents[4].reason.as_ref().unwrap().contains("locked"));
    }

    #[test]
    fn okf_import_plans_skip_copy_and_explicit_overwrite_conflicts() {
        let import_page = OkfImportPage {
            source_path: SafeRelativePath::new("source", "content/Concepts/index.md").unwrap(),
            folder_id: FolderId::new("concepts").unwrap(),
            target_path: SafeRelativePath::new("target", "index.md").unwrap(),
            markdown: "# Incoming".to_owned(),
        };
        let existing = vec![ExistingPagePath {
            folder_id: FolderId::new("concepts").unwrap(),
            page_path: SafeRelativePath::new("existing", "index.md").unwrap(),
            object_id: ObjectId::new("obj_000000000001").unwrap(),
        }];

        let skip = plan_okf_import(
            std::slice::from_ref(&import_page),
            &existing,
            OkfConflictMode::Skip,
        )
        .unwrap();
        assert_eq!(skip.entries[0].action, OkfImportAction::Skip);

        let copy = plan_okf_import(
            std::slice::from_ref(&import_page),
            &existing,
            OkfConflictMode::Copy,
        )
        .unwrap();
        assert_eq!(copy.entries[0].action, OkfImportAction::Copy);
        assert_eq!(copy.entries[0].target_path.to_string(), "index imported.md");

        assert_eq!(
            plan_okf_import(
                std::slice::from_ref(&import_page),
                &existing,
                OkfConflictMode::Overwrite { confirmed: false },
            )
            .unwrap_err(),
            PortabilityError::OverwriteRequiresConfirmation
        );
        let overwrite = plan_okf_import(
            &[import_page],
            &existing,
            OkfConflictMode::Overwrite { confirmed: true },
        )
        .unwrap();
        assert_eq!(overwrite.entries[0].action, OkfImportAction::Overwrite);
    }

    fn page(
        folder_id: &str,
        object_id: &str,
        folder_display_path: &str,
        page_path: &str,
        markdown: &str,
    ) -> OpenedPage {
        OpenedPage {
            folder_id: FolderId::new(folder_id).unwrap(),
            object_id: ObjectId::new(object_id).unwrap(),
            folder_display_path: SafeRelativePath::new("folder_path", folder_display_path).unwrap(),
            page_path: SafeRelativePath::new("page_path", page_path).unwrap(),
            markdown: markdown.to_owned(),
            revision: 1,
            key_version: 1,
            content_type: "text/markdown".to_owned(),
        }
    }

    fn sample_vault() -> Vault {
        Vault {
            id: VaultId::new("acme").unwrap(),
            kind: VaultKind::Organization,
            name: DisplayName::new("vault_name", "Acme").unwrap(),
            owner_user_id: None,
            folders: vec![
                Folder {
                    id: FolderId::new("concepts").unwrap(),
                    name: DisplayName::new("folder_name", "Concepts").unwrap(),
                    role: FolderRole::Folder,
                    access: FolderAccessMode::AllMembers,
                    parent_folder_id: None,
                    path: SafeRelativePath::new("folder_path", "Concepts").unwrap(),
                    current_key_version: 1,
                    shared_folder_source: false,
                },
                Folder {
                    id: FolderId::new("board").unwrap(),
                    name: DisplayName::new("folder_name", "Board").unwrap(),
                    role: FolderRole::Folder,
                    access: FolderAccessMode::Restricted,
                    parent_folder_id: None,
                    path: SafeRelativePath::new("folder_path", "Board").unwrap(),
                    current_key_version: 1,
                    shared_folder_source: false,
                },
            ],
            members: Vec::new(),
            admins: vec![UserId::new("npub-admin").unwrap()],
        }
    }
}
