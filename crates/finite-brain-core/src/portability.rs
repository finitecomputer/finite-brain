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

struct LinkEdge {
    from: String,
    to: String,
}

/// Export accessible decrypted pages into a readable OKF bundle.
pub fn export_okf_bundle(input: OkfExportInput) -> Result<OkfBundle, PortabilityError> {
    let mut files = BTreeMap::new();
    let mut manifest_objects = Vec::new();
    let mut manifest_folders = Vec::new();
    let mut page_bundle_paths = BTreeMap::new();
    let mut opened_page_paths = BTreeSet::new();
    let mut bundle_paths = BTreeSet::new();

    for page in &input.opened_pages {
        let page_key = (page.folder_id.clone(), page.page_path.as_str().to_owned());
        if !opened_page_paths.insert(page_key.clone()) {
            return Err(PortabilityError::DuplicatePagePath {
                folder_id: page.folder_id.to_string(),
                path: page.page_path.to_string(),
            });
        }
        let bundle_path = content_bundle_path(page)?;
        if !bundle_paths.insert(bundle_path.clone()) {
            return Err(PortabilityError::DuplicateBundlePath { path: bundle_path });
        }
        page_bundle_paths.insert(page_key, bundle_path);
    }

    let mut link_edges = Vec::new();
    for page in &input.opened_pages {
        let bundle_path = page_bundle_paths
            .get(&(page.folder_id.clone(), page.page_path.as_str().to_owned()))
            .expect("page path indexed")
            .clone();
        let (rewritten, links) = rewrite_markdown_links(page, &bundle_path, &page_bundle_paths);
        link_edges.extend(links);
        manifest_objects.push(OkfObjectManifestEntry {
            folder_id: page.folder_id.to_string(),
            object_id: page.object_id.as_str().to_owned(),
            path: bundle_path.clone(),
            content_type: page.content_type.clone(),
            content_hash: sha256_hex(rewritten.as_bytes()),
        });
        files.insert(bundle_path, rewritten);
    }

    let source_folders = input
        .source_vault
        .folders
        .iter()
        .map(|folder| (folder.id.clone(), folder))
        .collect::<BTreeMap<_, _>>();
    let accessible_folder_paths = input
        .opened_pages
        .iter()
        .map(|page| (page.folder_id.clone(), page.folder_display_path.to_string()))
        .collect::<BTreeMap<_, _>>();
    for (folder_id, display_path) in accessible_folder_paths {
        if let Some(folder) = source_folders.get(&folder_id) {
            manifest_folders.push(OkfFolderManifestEntry {
                folder_id: folder_id.to_string(),
                display_path,
                access: folder.access,
                omitted: false,
            });
        }
    }
    for omission in &input.omissions {
        if let Some(folder) = source_folders.get(&omission.folder_id) {
            manifest_folders.push(OkfFolderManifestEntry {
                folder_id: omission.folder_id.to_string(),
                display_path: omission.display_path.to_string(),
                access: folder.access,
                omitted: true,
            });
        }
    }

    let omissions = input
        .omissions
        .into_iter()
        .map(|omission| OkfOmissionManifestEntry {
            folder_id: omission.folder_id.to_string(),
            display_path: omission.display_path.to_string(),
            reason: omission.reason,
        })
        .collect::<Vec<_>>();

    let wiki_files = generated_wiki_files(
        &input.exported_at,
        &input.exported_by_npub,
        &files,
        &link_edges,
    )?;
    for (path, body) in wiki_files {
        if files.insert(path.clone(), body).is_some() {
            return Err(PortabilityError::DuplicateBundlePath { path });
        }
    }

    let manifest = OkfManifest {
        version: "finite-okf-vault-export-v1".to_owned(),
        exported_at: input.exported_at,
        exported_by_npub: input.exported_by_npub.to_string(),
        source_vault: OkfSourceVault {
            id: input.source_vault.id.to_string(),
            kind: format!("{:?}", input.source_vault.kind).to_lowercase(),
            name: input.source_vault.name.to_string(),
        },
        folders: manifest_folders,
        objects: manifest_objects,
        omissions,
    };
    let manifest_json = serde_json::to_string_pretty(&manifest).expect("manifest serializes");
    files.insert("okf-vault.json".to_owned(), manifest_json);

    Ok(OkfBundle { manifest, files })
}

/// Build a local plaintext search index from already-opened pages.
pub fn build_local_search_index(opened_pages: &[OpenedPage]) -> Vec<LocalSearchDocument> {
    opened_pages
        .iter()
        .map(|page| LocalSearchDocument {
            folder_id: page.folder_id.clone(),
            object_id: page.object_id.clone(),
            page_path: page.page_path.clone(),
            title: markdown_title(&page.markdown)
                .unwrap_or_else(|| title_from_path(&page.page_path)),
            body: page.markdown.clone(),
        })
        .collect()
}

/// Candidate `AGENTS.md` files from nearest page directory to Vault root.
pub fn agent_discovery_paths(
    page_path: &SafeRelativePath,
) -> Result<Vec<SafeRelativePath>, CoreError> {
    let mut dirs = page_path.as_str().split('/').collect::<Vec<_>>();
    dirs.pop();

    let mut candidates = Vec::new();
    for depth in (0..=dirs.len()).rev() {
        let candidate = if depth == 0 {
            "AGENTS.md".to_owned()
        } else {
            format!("{}/AGENTS.md", dirs[..depth].join("/"))
        };
        candidates.push(SafeRelativePath::new("agent_path", candidate)?);
    }
    Ok(candidates)
}

/// Plan readable OKF import conflict handling before client-side encryption/upload.
pub fn plan_okf_import(
    pages: &[OkfImportPage],
    existing_pages: &[ExistingPagePath],
    mode: OkfConflictMode,
) -> Result<OkfImportPlan, PortabilityError> {
    let mut occupied = existing_pages
        .iter()
        .map(|page| (page.folder_id.clone(), page.page_path.to_string()))
        .collect::<BTreeSet<_>>();
    let mut entries = Vec::new();

    for page in pages {
        let key = (page.folder_id.clone(), page.target_path.to_string());
        let collides = occupied.contains(&key);
        match (mode, collides) {
            (_, false) => {
                occupied.insert(key);
                entries.push(OkfImportPlanEntry {
                    source_path: page.source_path.clone(),
                    folder_id: page.folder_id.clone(),
                    target_path: page.target_path.clone(),
                    action: OkfImportAction::Create,
                });
            }
            (OkfConflictMode::Skip, true) => entries.push(OkfImportPlanEntry {
                source_path: page.source_path.clone(),
                folder_id: page.folder_id.clone(),
                target_path: page.target_path.clone(),
                action: OkfImportAction::Skip,
            }),
            (OkfConflictMode::Copy, true) => {
                let copy_path = unique_copy_path(&page.folder_id, &page.target_path, &occupied)?;
                occupied.insert((page.folder_id.clone(), copy_path.to_string()));
                entries.push(OkfImportPlanEntry {
                    source_path: page.source_path.clone(),
                    folder_id: page.folder_id.clone(),
                    target_path: copy_path,
                    action: OkfImportAction::Copy,
                });
            }
            (OkfConflictMode::Overwrite { confirmed: false }, true) => {
                return Err(PortabilityError::OverwriteRequiresConfirmation);
            }
            (OkfConflictMode::Overwrite { confirmed: true }, true) => {
                entries.push(OkfImportPlanEntry {
                    source_path: page.source_path.clone(),
                    folder_id: page.folder_id.clone(),
                    target_path: page.target_path.clone(),
                    action: OkfImportAction::Overwrite,
                });
            }
        }
    }

    Ok(OkfImportPlan { entries })
}

/// Materialize already-opened content into a Vault Working Tree file map.
pub fn materialize_vault_working_tree(
    input: WorkingTreeMaterializeInput,
) -> Result<WorkingTreeProjection, PortabilityError> {
    let mut files = BTreeMap::new();
    let mut folder_roots = BTreeMap::<FolderId, WorkingTreeFolderRoot>::new();
    let mut objects = Vec::new();
    let folders_by_id = input
        .vault
        .folders
        .iter()
        .map(|folder| (folder.id.clone(), folder))
        .collect::<BTreeMap<_, _>>();
    let folder_paths = input
        .vault
        .folders
        .iter()
        .map(|folder| folder.path.to_string())
        .collect::<BTreeSet<_>>();

    for page in &input.opened_pages {
        let folder = folders_by_id
            .get(&page.folder_id)
            .ok_or_else(|| CoreError::InvalidId {
                field: "folder_id",
                value: page.folder_id.to_string(),
            })?;
        folder_roots
            .entry(page.folder_id.clone())
            .or_insert_with(|| WorkingTreeFolderRoot {
                folder_id: page.folder_id.to_string(),
                path: folder.path.to_string(),
                can_read: true,
                metadata_only: false,
            });

        let full_path = working_tree_page_path(&folder.path, &page.page_path)?;
        if folder_paths.contains(&full_path) {
            return Err(PortabilityError::WorkingTreePathCollision { path: full_path });
        }
        insert_working_tree_file(&mut files, &full_path, page.markdown.clone())?;
        objects.push(WorkingTreeObjectManifestEntry {
            folder_id: page.folder_id.to_string(),
            path: page.page_path.to_string(),
            object_id: page.object_id.as_str().to_owned(),
            revision: page.revision,
            key_version: page.key_version,
            content_type: page.content_type.clone(),
            content_hash: sha256_hex(page.markdown.as_bytes()),
        });
    }

    for locked in &input.locked_folders {
        folder_roots
            .entry(locked.folder_id.clone())
            .or_insert_with(|| WorkingTreeFolderRoot {
                folder_id: locked.folder_id.to_string(),
                path: locked.display_path.to_string(),
                can_read: false,
                metadata_only: true,
            });
        let locked_marker = serde_json::to_string_pretty(&serde_json::json!({
            "folderId": locked.folder_id.to_string(),
            "reason": safe_locked_reason(&locked.reason),
            "metadataOnly": true
        }))
        .expect("locked marker serializes");
        insert_working_tree_file(
            &mut files,
            &format!(
                ".finitebrain/encrypted-sync/folders/{}/locked.json",
                locked.folder_id
            ),
            locked_marker,
        )?;
    }

    let mut roots = folder_roots.into_values().collect::<Vec<_>>();
    roots.sort_by(|left, right| left.path.cmp(&right.path));
    objects.sort_by(|left, right| {
        left.folder_id
            .cmp(&right.folder_id)
            .then(left.path.cmp(&right.path))
    });

    let directory = VaultDirectoryManifest {
        version: "finite-vault-directory-v1".to_owned(),
        vault: VaultDirectoryVaultSummary {
            id: input.vault.id.to_string(),
            kind: format!("{:?}", input.vault.kind).to_lowercase(),
            name: input.vault.name.to_string(),
            owner_npub: input.vault.owner_user_id.as_ref().map(ToString::to_string),
        },
        working_tree: VaultDirectoryPath {
            path: ".".to_owned(),
        },
        encrypted_sync: VaultDirectoryPath {
            path: ".finitebrain/encrypted-sync".to_owned(),
        },
        portability: VaultDirectoryPortability {
            owned_by_agent_runtime: false,
            owned_by_app_surface: false,
        },
        created_at: input.generated_at.clone(),
        updated_at: input.generated_at.clone(),
    };
    let state = VaultWorkingTreeStateManifest {
        version: "finite-vault-working-tree-state-v1".to_owned(),
        folder_roots: roots,
        objects,
        sync: WorkingTreeSyncState {
            latest_sequence: input.latest_sequence,
        },
    };

    insert_working_tree_file(
        &mut files,
        ".finitebrain/vault-directory.json",
        serde_json::to_string_pretty(&directory).expect("directory manifest serializes"),
    )?;
    insert_working_tree_file(
        &mut files,
        ".finitebrain/working-tree-state.json",
        serde_json::to_string_pretty(&state).expect("working-tree manifest serializes"),
    )?;
    insert_working_tree_file(
        &mut files,
        "AGENTS.md",
        root_agents_file(&input.generated_by_npub),
    )?;
    insert_working_tree_file(&mut files, "_index.md", root_working_tree_index(&state))?;
    insert_working_tree_file(
        &mut files,
        "_wiki/index.md",
        root_wiki_index(&input.generated_at, &input.generated_by_npub, &state),
    )?;
    insert_working_tree_file(
        &mut files,
        "_wiki/backlinks.md",
        "# Backlinks\n\n".to_owned(),
    )?;
    insert_working_tree_file(&mut files, "_wiki/orphans.md", root_orphans_report(&state))?;
    insert_working_tree_file(
        &mut files,
        "_wiki/stale.md",
        root_stale_report(&input.generated_at),
    )?;
    let tags_report = root_tags_report(&files);
    insert_working_tree_file(&mut files, "_wiki/tags.md", tags_report)?;

    for root in &state.folder_roots {
        if !root.can_read {
            continue;
        }
        insert_working_tree_file(
            &mut files,
            &format!("{}/AGENTS.md", root.path),
            folder_agents_file(&root.folder_id),
        )?;
        insert_working_tree_file(
            &mut files,
            &format!("{}/_index.md", root.path),
            folder_index_file(root, &state),
        )?;
        insert_working_tree_file(
            &mut files,
            &format!("{}/_wiki/index.md", root.path),
            folder_wiki_index(root, &input.generated_at, &input.generated_by_npub, &state),
        )?;
        for convention in ["raw", "compiled", "output"] {
            insert_working_tree_file(
                &mut files,
                &format!("{}/{convention}/.keep", root.path),
                format!(
                    "# {convention}\n\nAgent convention directory for Folder `{}`.\n",
                    root.folder_id
                ),
            )?;
        }
    }

    Ok(WorkingTreeProjection {
        files,
        directory,
        state,
    })
}

/// Translate local working-tree changes into Product Client encrypted-sync intents.
pub fn plan_working_tree_change_intents(
    state: &VaultWorkingTreeStateManifest,
    changes: &[WorkingTreeChange],
) -> Vec<WorkingTreeChangeIntent> {
    changes
        .iter()
        .map(|change| match change {
            WorkingTreeChange::Upsert { path, markdown } => {
                plan_working_tree_upsert(state, path, markdown)
            }
            WorkingTreeChange::Rename { from_path, to_path } => {
                plan_working_tree_rename(state, from_path, to_path)
            }
            WorkingTreeChange::Delete { path } => plan_working_tree_delete(state, path),
        })
        .collect()
}

fn working_tree_page_path(
    folder_path: &SafeRelativePath,
    page_path: &SafeRelativePath,
) -> Result<String, CoreError> {
    let path = format!("{}/{}", folder_path.as_str(), page_path.as_str());
    SafeRelativePath::new("working_tree_path", &path)?;
    Ok(path)
}

fn insert_working_tree_file(
    files: &mut BTreeMap<String, String>,
    path: &str,
    content: String,
) -> Result<(), PortabilityError> {
    validate_working_tree_file_path(path)?;
    let path = path.to_owned();
    if files.insert(path.clone(), content).is_some() {
        return Err(PortabilityError::WorkingTreePathCollision { path });
    }
    Ok(())
}

fn validate_working_tree_file_path(path: &str) -> Result<(), CoreError> {
    if path.starts_with(".finitebrain/") {
        if path.contains('\\')
            || path.chars().any(|c| c == '\0' || c.is_control())
            || path
                .split('/')
                .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return Err(CoreError::InvalidPath {
                field: "working_tree_file",
                value: path.to_owned(),
            });
        }
        return Ok(());
    }
    SafeRelativePath::new("working_tree_file", path).map(|_| ())
}

fn safe_locked_reason(reason: &str) -> &'static str {
    match reason {
        "missing-folder-key" => "missing-folder-key",
        "no-folder-access" => "no-folder-access",
        _ => "inaccessible",
    }
}

fn root_agents_file(actor: &UserId) -> String {
    format!(
        "# FiniteBrain Agent Workspace\n\nActing user: {actor}\n\n- Read and write only materialized accessible Folders.\n- Do not write decrypted content into `.finitebrain/encrypted-sync`.\n- Changes must be returned through the Product Client encrypted sync path.\n"
    )
}

fn folder_agents_file(folder_id: &str) -> String {
    format!(
        "# Folder Agent Instructions\n\nFolder id: `{folder_id}`\n\nUse `raw/` for source captures, `compiled/` for curated wiki pages, and `output/` for generated artifacts.\n"
    )
}

fn root_working_tree_index(state: &VaultWorkingTreeStateManifest) -> String {
    let folders = state
        .folder_roots
        .iter()
        .map(|root| {
            if root.can_read {
                format!("- [{}]({}/_index.md)", root.path, root.path)
            } else {
                format!("- {} (locked metadata only)", root.path)
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("# Vault Working Tree\n\n## Folders\n\n{folders}\n")
}

fn root_wiki_index(
    generated_at: &str,
    generated_by: &UserId,
    state: &VaultWorkingTreeStateManifest,
) -> String {
    let readable_count = state
        .folder_roots
        .iter()
        .filter(|root| root.can_read)
        .count();
    format!(
        "# Working Tree Wiki\n\nGenerated at: {generated_at}\nGenerated by: {generated_by}\nReadable Folders: {readable_count}\nReadable Pages: {}\n",
        state.objects.len()
    )
}

fn root_orphans_report(state: &VaultWorkingTreeStateManifest) -> String {
    let pages = state
        .objects
        .iter()
        .map(|object| format!("- {}/{}", object.folder_id, object.path))
        .collect::<Vec<_>>()
        .join("\n");
    format!("# Orphans\n\n{pages}\n")
}

fn root_stale_report(generated_at: &str) -> String {
    format!("# Stale\n\nGenerated at: {generated_at}\nNo stale-page policy was applied.\n")
}

fn root_tags_report(files: &BTreeMap<String, String>) -> String {
    format!("# Tags\n\n{}\n", collect_tags(files).join("\n"))
}

fn folder_index_file(
    root: &WorkingTreeFolderRoot,
    state: &VaultWorkingTreeStateManifest,
) -> String {
    let pages = state
        .objects
        .iter()
        .filter(|object| object.folder_id == root.folder_id)
        .map(|object| format!("- [{}]({})", object.path, object.path))
        .collect::<Vec<_>>()
        .join("\n");
    format!("# {}\n\n{pages}\n", root.path)
}

fn folder_wiki_index(
    root: &WorkingTreeFolderRoot,
    generated_at: &str,
    generated_by: &UserId,
    state: &VaultWorkingTreeStateManifest,
) -> String {
    let count = state
        .objects
        .iter()
        .filter(|object| object.folder_id == root.folder_id)
        .count();
    format!(
        "# Folder Wiki\n\nGenerated at: {generated_at}\nGenerated by: {generated_by}\nFolder: {}\nReadable Pages: {count}\n",
        root.path
    )
}

fn plan_working_tree_upsert(
    state: &VaultWorkingTreeStateManifest,
    path: &SafeRelativePath,
    markdown: &str,
) -> WorkingTreeChangeIntent {
    let Some((root, local_path)) = resolve_working_tree_folder(state, path) else {
        return unresolved_intent("path is outside materialized readable Folders");
    };
    if !root.can_read {
        return unresolved_intent("Folder is locked in this working tree");
    }
    let existing = object_for_local_path(state, &root.folder_id, &local_path);
    let object_id = existing
        .and_then(|object| ObjectId::new(object.object_id.clone()).ok())
        .unwrap_or_else(|| generated_working_tree_object_id(&root.folder_id, &local_path));
    WorkingTreeChangeIntent {
        action: if existing.is_some() {
            WorkingTreeIntentAction::Update
        } else {
            WorkingTreeIntentAction::Create
        },
        route: WorkingTreeIntentRoute::EncryptedObjectWrite,
        folder_id: FolderId::new(root.folder_id.clone()).ok(),
        object_id: Some(object_id),
        target_path: Some(local_path),
        from_path: None,
        base_revision: existing.map(|object| object.revision),
        markdown: Some(markdown.to_owned()),
        reason: None,
    }
}

fn plan_working_tree_rename(
    state: &VaultWorkingTreeStateManifest,
    from_path: &SafeRelativePath,
    to_path: &SafeRelativePath,
) -> WorkingTreeChangeIntent {
    let Some((from_root, from_local_path)) = resolve_working_tree_folder(state, from_path) else {
        return unresolved_intent("source path is outside materialized readable Folders");
    };
    let Some((to_root, to_local_path)) = resolve_working_tree_folder(state, to_path) else {
        return unresolved_intent("destination path is outside materialized readable Folders");
    };
    if !from_root.can_read || !to_root.can_read {
        return unresolved_intent("Folder is locked in this working tree");
    }
    if from_root.folder_id != to_root.folder_id {
        return unresolved_intent("cross-Folder moves require Vault Admin handling");
    }
    let Some(existing) = object_for_local_path(state, &from_root.folder_id, &from_local_path)
    else {
        return unresolved_intent("source object is not in working-tree state");
    };
    WorkingTreeChangeIntent {
        action: WorkingTreeIntentAction::Move,
        route: WorkingTreeIntentRoute::EncryptedObjectMove,
        folder_id: FolderId::new(from_root.folder_id.clone()).ok(),
        object_id: ObjectId::new(existing.object_id.clone()).ok(),
        target_path: Some(to_local_path),
        from_path: Some(from_local_path),
        base_revision: Some(existing.revision),
        markdown: None,
        reason: None,
    }
}

fn plan_working_tree_delete(
    state: &VaultWorkingTreeStateManifest,
    path: &SafeRelativePath,
) -> WorkingTreeChangeIntent {
    let Some((root, local_path)) = resolve_working_tree_folder(state, path) else {
        return unresolved_intent("path is outside materialized readable Folders");
    };
    if !root.can_read {
        return unresolved_intent("Folder is locked in this working tree");
    }
    let Some(existing) = object_for_local_path(state, &root.folder_id, &local_path) else {
        return unresolved_intent("object is not in working-tree state");
    };
    WorkingTreeChangeIntent {
        action: WorkingTreeIntentAction::Delete,
        route: WorkingTreeIntentRoute::EncryptedObjectDelete,
        folder_id: FolderId::new(root.folder_id.clone()).ok(),
        object_id: ObjectId::new(existing.object_id.clone()).ok(),
        target_path: Some(local_path),
        from_path: None,
        base_revision: Some(existing.revision),
        markdown: None,
        reason: None,
    }
}

fn resolve_working_tree_folder<'a>(
    state: &'a VaultWorkingTreeStateManifest,
    path: &SafeRelativePath,
) -> Option<(&'a WorkingTreeFolderRoot, SafeRelativePath)> {
    state
        .folder_roots
        .iter()
        .filter_map(|root| {
            let root_path = root.path.as_str();
            let relative = path
                .as_str()
                .strip_prefix(root_path)
                .and_then(|rest| rest.strip_prefix('/'))?;
            SafeRelativePath::new("working_tree_local_path", relative)
                .ok()
                .map(|local_path| (root, local_path))
        })
        .max_by_key(|(root, _)| root.path.len())
}

fn object_for_local_path<'a>(
    state: &'a VaultWorkingTreeStateManifest,
    folder_id: &str,
    local_path: &SafeRelativePath,
) -> Option<&'a WorkingTreeObjectManifestEntry> {
    state
        .objects
        .iter()
        .find(|object| object.folder_id == folder_id && object.path == local_path.to_string())
}

fn generated_working_tree_object_id(folder_id: &str, local_path: &SafeRelativePath) -> ObjectId {
    let digest = Sha256::digest(format!("{folder_id}/{}", local_path.as_str()).as_bytes());
    let hex = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    ObjectId::new(format!("obj_{hex}")).expect("generated object id is valid")
}

fn unresolved_intent(reason: &str) -> WorkingTreeChangeIntent {
    WorkingTreeChangeIntent {
        action: WorkingTreeIntentAction::Unresolved,
        route: WorkingTreeIntentRoute::Unresolved,
        folder_id: None,
        object_id: None,
        target_path: None,
        from_path: None,
        base_revision: None,
        markdown: None,
        reason: Some(reason.to_owned()),
    }
}

fn content_bundle_path(page: &OpenedPage) -> Result<String, CoreError> {
    let path = format!(
        "content/{}/{}",
        page.folder_display_path.as_str(),
        page.page_path.as_str()
    );
    SafeRelativePath::new("okf_path", &path)?;
    Ok(path)
}

fn rewrite_markdown_links(
    page: &OpenedPage,
    current_bundle_path: &str,
    page_bundle_paths: &BTreeMap<(FolderId, String), String>,
) -> (String, Vec<LinkEdge>) {
    let mut output = String::new();
    let mut links = Vec::new();
    let mut rest = page.markdown.as_str();

    while let Some(open) = rest.find('[') {
        output.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find("](") else {
            output.push_str(&rest[open..]);
            return (output, links);
        };
        let label = &after_open[..close];
        let after_marker = &after_open[close + 2..];
        let Some(end) = after_marker.find(')') else {
            output.push_str(&rest[open..]);
            return (output, links);
        };
        let target = &after_marker[..end];
        let original = &rest[open..open + 1 + close + 2 + end + 1];
        if is_external_or_anchor(target) {
            output.push_str(original);
        } else if let Some(resolved) = resolve_relative_path(page.page_path.as_str(), target) {
            let key = (page.folder_id.clone(), resolved);
            if let Some(target_bundle_path) = page_bundle_paths.get(&key) {
                let relative = relative_path_between(current_bundle_path, target_bundle_path);
                output.push_str(&format!("[{label}]({relative})"));
                links.push(LinkEdge {
                    from: current_bundle_path.to_owned(),
                    to: target_bundle_path.clone(),
                });
            } else {
                output.push_str(label);
            }
        } else {
            output.push_str(label);
        }
        rest = &after_marker[end + 1..];
    }

    output.push_str(rest);
    (output, links)
}

fn is_external_or_anchor(target: &str) -> bool {
    target.starts_with('#')
        || target.starts_with("http://")
        || target.starts_with("https://")
        || target.starts_with("mailto:")
}

fn resolve_relative_path(base_page_path: &str, target: &str) -> Option<String> {
    if target.starts_with('/') || target.contains('\\') {
        return None;
    }
    let target = target.split('#').next().unwrap_or(target);
    let mut segments = base_page_path.split('/').collect::<Vec<_>>();
    segments.pop();
    for segment in target.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            value => segments.push(value),
        }
    }
    let path = segments.join("/");
    SafeRelativePath::new("markdown_link", &path).ok()?;
    Some(path)
}

fn relative_path_between(from_file: &str, to_file: &str) -> String {
    let mut from = from_file.split('/').collect::<Vec<_>>();
    from.pop();
    let to = to_file.split('/').collect::<Vec<_>>();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut parts = Vec::new();
    parts.extend(std::iter::repeat_n("..", from.len().saturating_sub(common)));
    parts.extend(to[common..].iter().copied());
    parts.join("/")
}

fn generated_wiki_files(
    exported_at: &str,
    exported_by: &UserId,
    files: &BTreeMap<String, String>,
    links: &[LinkEdge],
) -> Result<BTreeMap<String, String>, CoreError> {
    let content_paths = files
        .keys()
        .filter(|path| path.starts_with("content/"))
        .cloned()
        .collect::<Vec<_>>();
    let incoming = links
        .iter()
        .map(|link| link.to.clone())
        .collect::<BTreeSet<_>>();

    let mut wiki = BTreeMap::new();
    wiki.insert(
        "_wiki/index.md".to_owned(),
        format!(
            "# OKF Index\n\nGenerated at: {exported_at}\nGenerated by: {exported_by}\n\n{}",
            content_paths
                .iter()
                .map(|path| format!(
                    "- [{}]({})",
                    path,
                    relative_path_between("_wiki/index.md", path)
                ))
                .collect::<Vec<_>>()
                .join("\n")
        ),
    );
    wiki.insert(
        "_wiki/backlinks.md".to_owned(),
        format!(
            "# Backlinks\n\n{}",
            links
                .iter()
                .map(|link| format!("- {} -> {}", link.from, link.to))
                .collect::<Vec<_>>()
                .join("\n")
        ),
    );
    wiki.insert(
        "_wiki/orphans.md".to_owned(),
        format!(
            "# Orphans\n\n{}",
            content_paths
                .iter()
                .filter(|path| !incoming.contains(*path))
                .map(|path| format!("- {path}"))
                .collect::<Vec<_>>()
                .join("\n")
        ),
    );
    wiki.insert(
        "_wiki/tags.md".to_owned(),
        format!("# Tags\n\n{}", collect_tags(files).join("\n")),
    );
    wiki.insert(
        "_wiki/stale.md".to_owned(),
        format!("# Stale\n\nGenerated at: {exported_at}\nNo stale-page policy was applied."),
    );

    for path in wiki.keys() {
        SafeRelativePath::new("wiki_path", path)?;
    }
    Ok(wiki)
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

fn unique_copy_path(
    folder_id: &FolderId,
    path: &SafeRelativePath,
    occupied: &BTreeSet<(FolderId, String)>,
) -> Result<SafeRelativePath, CoreError> {
    let value = path.as_str();
    let (stem, extension) = value
        .strip_suffix(".md")
        .map_or((value, ""), |stem| (stem, ".md"));
    for index in 1..=1_000 {
        let suffix = if index == 1 {
            " imported".to_owned()
        } else {
            format!(" imported {index}")
        };
        let candidate = format!("{stem}{suffix}{extension}");
        if !occupied.contains(&(folder_id.clone(), candidate.clone())) {
            return SafeRelativePath::new("copy_path", candidate);
        }
    }
    SafeRelativePath::new("copy_path", format!("{stem} imported overflow{extension}"))
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
                reason: "inaccessible".to_owned(),
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
