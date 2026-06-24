//! FiniteBrain HTTP server and API surface.

use std::collections::BTreeSet;
use std::path::Path;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, OriginalUri, Path as AxumPath, Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use finite_brain_core::{
    AdminAccessAction, AdminAccessChangePayload, AdminAccessChangeValidation,
    BootstrapSmokeSummary, CoreError, CryptoRecordError, DisplayName, Folder, FolderAccessMode,
    FolderId, FolderObjectOperation, FolderObjectRevisionPayload, FolderObjectTombstonePayload,
    FolderRole, ObjectId, RequiredFolderKeyGrant, RevisionValidation, SafeRelativePath,
    TombstoneValidation, UserId, VaultId, VaultKind, bootstrap_organization_vault,
    bootstrap_personal_vault, validate_admin_access_change_event, validate_revision_event,
    validate_tombstone_event,
};
use finite_brain_store::{
    BrainStore, ControlSyncRecord, EncryptedVaultExport, FolderKeyGrantMetadata,
    FolderObjectRevisionSyncRecord, FolderObjectTombstoneSyncRecord, LinkStatus,
    MountedFolderProjection, MountedFolderState, SharedFolderConnectionStatus, StoreError,
    StoredShareLink, StoredSharedFolderConnection, StoredSharedFolderInvitation, StoredSyncRecord,
    StoredVault, StoredVaultInvitation, SyncRecordInput, SyncRecordType,
};
use finite_nostr::{HttpAuthValidation, NostrPrimitiveError, NostrPublicKey};
use nostr::Event;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const DEFAULT_PUBLIC_BASE_URL: &str = "http://127.0.0.1:3015";
const DEFAULT_MAX_AUTH_SKEW_SECONDS: u64 = 60;
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_SYNC_RECORDS_LIMIT: u64 = 1_000;
const NOSTR_AUTHORIZATION_HEADER: &str = "x-nostr-authorization";
const FINITEBRAIN_NOSTR_HEADER: &str = "x-finitebrain-nostr";
const APP_SPECIFIC_KIND: u16 = 30_078;

/// Development status returned by the first smoke path.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct HealthStatus {
    pub service: String,
    pub status: String,
    pub core_crate: String,
    pub store_crate: String,
}

/// Shared server state.
#[derive(Clone)]
pub struct ServerState {
    store: Arc<Mutex<BrainStore>>,
    public_base_url: Arc<str>,
    auth_now_unix_seconds: Option<u64>,
    max_auth_skew_seconds: u64,
}

impl ServerState {
    /// Build state around an existing store.
    pub fn new(store: BrainStore, public_base_url: impl Into<String>) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            public_base_url: Arc::<str>::from(public_base_url.into()),
            auth_now_unix_seconds: None,
            max_auth_skew_seconds: DEFAULT_MAX_AUTH_SKEW_SECONDS,
        }
    }

    /// Override the auth validation clock for deterministic tests.
    pub fn with_auth_clock(mut self, now_unix_seconds: u64, max_skew_seconds: u64) -> Self {
        self.auth_now_unix_seconds = Some(now_unix_seconds);
        self.max_auth_skew_seconds = max_skew_seconds;
        self
    }

    fn auth_now_unix_seconds(&self) -> u64 {
        self.auth_now_unix_seconds
            .unwrap_or_else(current_unix_seconds)
    }
}

/// API error body.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct ApiErrorBody {
    pub error: String,
}

#[derive(Debug, Clone)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(value: StoreError) -> Self {
        match value {
            StoreError::Core(error) => Self::new(StatusCode::BAD_REQUEST, error.to_string()),
            StoreError::MissingVault { .. } | StoreError::MissingFolder { .. } => {
                Self::new(StatusCode::NOT_FOUND, value.to_string())
            }
            StoreError::DuplicateId { .. } | StoreError::Conflict { .. } => {
                Self::new(StatusCode::CONFLICT, value.to_string())
            }
            StoreError::MissingRequiredGrant { .. }
            | StoreError::BrokenInvariant { .. }
            | StoreError::InvalidRecord { .. } => {
                Self::new(StatusCode::BAD_REQUEST, value.to_string())
            }
            StoreError::RebootstrapRequired { .. } => {
                Self::new(StatusCode::GONE, value.to_string())
            }
            StoreError::UnavailableLink { .. } => {
                Self::new(StatusCode::NOT_FOUND, value.to_string())
            }
            StoreError::Database { .. } => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            }
        }
    }
}

impl From<CoreError> for ApiError {
    fn from(value: CoreError) -> Self {
        Self::new(StatusCode::BAD_REQUEST, value.to_string())
    }
}

impl From<CryptoRecordError> for ApiError {
    fn from(value: CryptoRecordError) -> Self {
        Self::new(StatusCode::BAD_REQUEST, value.to_string())
    }
}

/// Create Vault request.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVaultRequest {
    pub vault_id: String,
    pub kind: CreateVaultKind,
    pub name: String,
}

/// Supported Vault creation kinds.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreateVaultKind {
    Personal,
    Organization,
}

/// Vault metadata response without plaintext Page content.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMetadataResponse {
    pub vault_id: String,
    pub kind: VaultKind,
    pub name: String,
    pub owner_user_id: Option<String>,
    pub members: Vec<String>,
    pub admins: Vec<String>,
    pub folders: Vec<FolderMetadataResponse>,
    pub mounted_folders: Vec<MountedFolderResponse>,
    pub grant_count: usize,
}

/// Server-visible Folder metadata response.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderMetadataResponse {
    pub id: String,
    pub name: String,
    pub role: FolderRole,
    pub access: FolderAccessMode,
    pub parent_folder_id: Option<String>,
    pub path: String,
    pub shared_folder_source: bool,
    pub access_user_ids: Vec<String>,
    pub current_key_version: u32,
    pub setup_incomplete: bool,
}

/// Client-visible mounted Folder metadata response.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MountedFolderResponse {
    pub mount_id: String,
    pub organization_vault_id: String,
    pub source_vault_id: String,
    pub source_folder_id: String,
    pub connection_id: String,
    pub display_name: String,
    pub display_parent_folder_id: Option<String>,
    pub state: String,
}

/// Encrypted object write request.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectWriteRequest {
    pub base_revision: Option<u64>,
    pub key_version: u32,
    pub cipher: String,
    pub ciphertext: String,
    pub revision_event: serde_json::Value,
}

/// Encrypted object tombstone request.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectDeleteRequest {
    pub base_revision: u64,
    pub tombstone_event: serde_json::Value,
}

/// Object write response.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectWriteResponse {
    pub sequence: u64,
    pub duplicate: bool,
    pub revision: u64,
}

/// Current encrypted object response.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectResponse {
    pub vault_id: String,
    pub folder_id: String,
    pub object_id: String,
    pub revision: u64,
    pub ciphertext: String,
    pub deleted: bool,
}

/// Encrypted Vault Export response.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedVaultExportResponse {
    pub version: String,
    pub vault: ExportVaultSummaryResponse,
    pub folders: Vec<EncryptedExportFolderResponse>,
    pub objects: Vec<EncryptedExportObjectResponse>,
    pub key_grants: Vec<FolderKeyGrantResponse>,
    pub access_state: EncryptedExportAccessStateResponse,
}

/// Vault summary in an encrypted export.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportVaultSummaryResponse {
    pub id: String,
    pub kind: VaultKind,
    pub name: String,
    pub owner_user_id: Option<String>,
}

/// Folder entry in an encrypted export.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedExportFolderResponse {
    pub id: String,
    pub path: String,
    pub access: FolderAccessMode,
    pub current_key_version: u32,
    pub shared_folder_source: bool,
    pub accessible: bool,
}

/// Object entry in an encrypted export.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedExportObjectResponse {
    pub folder_id: String,
    pub object_id: String,
    pub payload_json: Option<String>,
    pub revision: u64,
    pub updated_at: String,
    pub deleted: bool,
    pub opaque: bool,
}

/// Folder Key Grant metadata in an encrypted export.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderKeyGrantResponse {
    pub id: String,
    pub folder_id: String,
    pub key_version: u32,
    pub issuer_npub: String,
    pub recipient_npub: String,
    pub format: String,
    pub wrapped_event_json: String,
    pub access_change_event_json: Option<String>,
    pub created_at: String,
}

/// Access state in an encrypted export.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedExportAccessStateResponse {
    pub members: Vec<String>,
    pub admins: Vec<String>,
    pub folders: Vec<EncryptedExportFolderAccessResponse>,
}

/// Restricted Folder access state in an encrypted export.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedExportFolderAccessResponse {
    pub folder_id: String,
    pub user_ids: Vec<String>,
}

/// Sync bootstrap response.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncBootstrapResponse {
    pub vault_id: String,
    pub latest_sequence: u64,
    pub objects: Vec<ObjectResponse>,
    pub object_count: usize,
    pub current_state_kind: String,
}

/// Incremental sync record response.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncRecordResponse {
    pub sequence: u64,
    pub record_event_id: String,
    pub record_type: String,
    pub folder_id: Option<String>,
    pub object_id: Option<String>,
    pub revision: Option<u64>,
    pub actor_npub: String,
    pub client_created_at: String,
    pub payload_json: String,
    pub record_event_kind: u16,
}

/// Incremental sync pull response.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncPullResponse {
    pub vault_id: String,
    pub after_sequence: u64,
    pub latest_sequence: u64,
    pub records: Vec<SyncRecordResponse>,
    pub count: usize,
    pub has_more: bool,
    pub next_sequence: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncRecordsQuery {
    after: Option<u64>,
    limit: Option<u64>,
}

/// Opaque Folder Key Grant metadata accepted by the server.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderKeyGrantRequest {
    pub id: String,
    pub key_version: u32,
    pub recipient_npub: String,
    pub wrapped_event_json: String,
    pub created_at: Option<String>,
}

/// Add/remove member/admin request.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminTargetRequest {
    pub target_npub: String,
    pub access_change_event: serde_json::Value,
}

/// Body for path-targeted admin mutations.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminEventRequest {
    pub access_change_event: serde_json::Value,
}

/// Create Folder request.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateFolderRequest {
    pub folder_id: String,
    pub name: String,
    pub role: FolderRole,
    pub access: FolderAccessMode,
    pub parent_folder_id: Option<String>,
    pub path: String,
    pub shared_folder_source: Option<bool>,
    pub access_user_ids: Vec<String>,
    pub grants: Vec<FolderKeyGrantRequest>,
    pub access_change_event: serde_json::Value,
}

/// Finish setup request for setup-incomplete Folders.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishFolderSetupRequest {
    pub grants: Vec<FolderKeyGrantRequest>,
    pub access_change_event: serde_json::Value,
}

/// Grant access to one restricted Folder recipient.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantFolderAccessRequest {
    pub target_npub: String,
    pub grant: FolderKeyGrantRequest,
    pub access_change_event: serde_json::Value,
}

/// Re-encrypted object supplied during Folder Key rotation.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationObjectRequest {
    pub object_id: String,
    pub base_revision: Option<u64>,
    pub key_version: u32,
    pub cipher: String,
    pub ciphertext: String,
    pub revision_event: serde_json::Value,
}

/// Remove Folder access with required Folder Key rotation material.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveFolderAccessRequest {
    pub new_key_version: u32,
    pub grants: Vec<FolderKeyGrantRequest>,
    pub reencrypted_records: Vec<RotationObjectRequest>,
    pub access_change_event: serde_json::Value,
}

/// Create Vault Invitation request.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVaultInvitationRequest {
    pub target_npub: String,
    pub initial_folder_access: Vec<String>,
    pub expires_at: String,
}

/// Vault Invitation response.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInvitationResponse {
    pub id: String,
    pub vault_id: String,
    pub user_id: String,
    pub status: String,
    pub invite_code: String,
    pub accept_path: String,
    pub initial_folder_access: Vec<String>,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
    pub accepted_at: Option<String>,
    pub duplicate_accept: bool,
}

/// Create Share Link request.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateShareLinkRequest {
    pub recipient_npub: String,
    pub grant: FolderKeyGrantRequest,
    pub access_change_event: serde_json::Value,
    pub expires_at: String,
    pub create_personal_mount: Option<bool>,
}

/// Share Link response.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareLinkResponse {
    pub id: String,
    pub vault_id: String,
    pub folder_id: String,
    pub recipient_npub: String,
    pub created_by_npub: String,
    pub status: String,
    pub accept_path: String,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
    pub accepted_at: Option<String>,
    pub grant_id: String,
    pub create_personal_mount: bool,
    pub personal_mount_id: Option<String>,
    pub duplicate_accept: bool,
}

/// Mark Shared Folder Source request.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkSharedFolderSourceRequest {
    pub access_change_event: serde_json::Value,
}

/// Create Shared Folder Invitation request.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSharedFolderInvitationRequest {
    pub destination_vault_id: String,
    pub destination_admin_npub: String,
    pub grant: FolderKeyGrantRequest,
    pub access_change_event: serde_json::Value,
}

/// Shared Folder Invitation response.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedFolderInvitationResponse {
    pub id: String,
    pub source_vault_id: String,
    pub source_folder_id: String,
    pub destination_vault_id: String,
    pub destination_admin_npub: String,
    pub created_by_npub: String,
    pub status: String,
    pub current_key_version: u32,
    pub accept_path: String,
    pub created_at: String,
    pub updated_at: String,
    pub accepted_at: Option<String>,
    pub grant_id: String,
    pub duplicate_accept: bool,
}

/// Shared Folder Connection response.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedFolderConnectionResponse {
    pub id: String,
    pub source_vault_id: String,
    pub source_folder_id: String,
    pub destination_vault_id: String,
    pub destination_admin_npub: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub member_npubs: Vec<String>,
}

/// Update Shared Folder Connection members request.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSharedFolderConnectionMembersRequest {
    pub action: String,
    pub target_npub: String,
    pub grant: Option<FolderKeyGrantRequest>,
    pub new_key_version: Option<u32>,
    pub grants: Vec<FolderKeyGrantRequest>,
    pub reencrypted_records: Vec<RotationObjectRequest>,
}

/// Revoke Shared Folder Connection request.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeSharedFolderConnectionRequest {
    pub new_key_version: u32,
    pub grants: Vec<FolderKeyGrantRequest>,
    pub reencrypted_records: Vec<RotationObjectRequest>,
}

/// Returns the current process health status.
pub fn health_status() -> HealthStatus {
    HealthStatus {
        service: "finite-brain".to_owned(),
        status: "ok".to_owned(),
        core_crate: finite_brain_core::crate_name().to_owned(),
        store_crate: finite_brain_store::crate_name().to_owned(),
    }
}

/// Builds the development server router with an in-memory SQLite store.
pub fn router() -> Router {
    let store = BrainStore::open_in_memory().expect("in-memory store migration succeeds");
    router_with_state(ServerState::new(store, DEFAULT_PUBLIC_BASE_URL))
}

/// Build a router backed by an on-disk SQLite store.
pub fn router_with_sqlite_path(
    path: impl AsRef<Path>,
    public_base_url: impl Into<String>,
) -> Result<Router, StoreError> {
    Ok(router_with_state(ServerState::new(
        BrainStore::open(path)?,
        public_base_url,
    )))
}

/// Build a router with explicit state.
pub fn router_with_state(state: ServerState) -> Router {
    Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .route("/smoke/bootstrap", get(bootstrap_smoke_handler))
        .route("/smoke/ui", get(smoke_ui_handler))
        .route("/smoke/ui.css", get(smoke_ui_css_handler))
        .route("/smoke/ui.js", get(smoke_ui_js_handler))
        .route("/_admin/vaults", post(create_vault_handler))
        .route(
            "/_admin/vaults/{vault_id}/metadata",
            get(vault_metadata_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/export",
            get(encrypted_vault_export_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/search",
            get(vault_search_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/members",
            post(add_member_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/members/{target_npub}",
            axum::routing::delete(remove_member_handler),
        )
        .route("/_admin/vaults/{vault_id}/admins", post(add_admin_handler))
        .route(
            "/_admin/vaults/{vault_id}/admins/{target_npub}",
            axum::routing::delete(remove_admin_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/invitations",
            post(create_vault_invitation_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/invitations/{invitation_id}",
            axum::routing::delete(revoke_vault_invitation_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/invitations/{invitation_id}/accept",
            post(accept_vault_invitation_handler),
        )
        .route(
            "/_admin/vault-invitation-links/{invite_code}",
            get(get_vault_invitation_link_handler),
        )
        .route(
            "/_admin/vault-invitation-links/{invite_code}/accept",
            post(accept_vault_invitation_link_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/folders",
            post(create_folder_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/folders/{folder_id}/finish-setup",
            post(finish_folder_setup_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/folders/{folder_id}/access",
            post(grant_folder_access_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/folders/{folder_id}/access/{target_npub}",
            axum::routing::delete(remove_folder_access_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/folders/{folder_id}/share-links",
            post(create_share_link_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/folders/{folder_id}/share-source",
            post(mark_shared_folder_source_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/folders/{folder_id}/shared-folder-invitations",
            post(create_shared_folder_invitation_handler),
        )
        .route(
            "/_admin/share-links/{share_link_id}",
            get(get_share_link_handler).delete(revoke_share_link_handler),
        )
        .route(
            "/_admin/share-links/{share_link_id}/accept",
            post(accept_share_link_handler),
        )
        .route(
            "/_admin/shared-folder-invitations/{invitation_id}",
            get(get_shared_folder_invitation_handler)
                .delete(revoke_shared_folder_invitation_handler),
        )
        .route(
            "/_admin/shared-folder-invitations/{invitation_id}/accept",
            post(accept_shared_folder_invitation_handler),
        )
        .route(
            "/_admin/shared-folder-connections/{connection_id}/members",
            axum::routing::patch(update_shared_folder_connection_members_handler),
        )
        .route(
            "/_admin/shared-folder-connections/{connection_id}",
            axum::routing::delete(revoke_shared_folder_connection_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/organization-folder-mounts",
            get(organization_folder_mounts_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/folders/{folder_id}/objects/{object_id}",
            get(get_object_handler)
                .put(put_object_handler)
                .delete(delete_object_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/folders/{folder_id}/objects/{object_id}/move",
            post(move_object_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/sync/bootstrap",
            get(sync_bootstrap_handler),
        )
        .route(
            "/_admin/vaults/{vault_id}/sync/records",
            get(sync_records_handler).post(submit_sync_record_handler),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state)
}

async fn root_handler() -> &'static str {
    "FiniteBrain Rust smoke server"
}

async fn health_handler() -> Json<HealthStatus> {
    Json(health_status())
}

async fn bootstrap_smoke_handler() -> Result<Json<BootstrapSmokeSummary>, ApiError> {
    finite_brain_core::smoke_bootstrap_summary()
        .map(Json)
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))
}

async fn smoke_ui_handler() -> Html<&'static str> {
    Html(include_str!("smoke-ui.html"))
}

async fn smoke_ui_css_handler() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("smoke-ui.css"),
    )
}

async fn smoke_ui_js_handler() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("smoke-ui.js"),
    )
}

async fn create_vault_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Json<VaultMetadataResponse>, ApiError> {
    let signer = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?;
    let actor_npub = signer.to_npub().map_err(auth_error)?;
    let request: CreateVaultRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;

    let output = match request.kind {
        CreateVaultKind::Personal => {
            bootstrap_personal_vault(request.vault_id, request.name, actor_npub.clone())?
        }
        CreateVaultKind::Organization => {
            bootstrap_organization_vault(request.vault_id, request.name, actor_npub.clone())?
        }
    };
    let grants = grants_for_required(&output.required_key_grants, &actor_npub);
    let vault_id = output.vault.id.clone();

    let stored = {
        let mut store = state.store.lock().map_err(lock_error)?;
        store.create_vault_bootstrap(&output, &grants)?;
        store.load_vault(&vault_id)?
    };

    Ok(Json(metadata_response(stored)))
}

async fn vault_metadata_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(vault_id): AxumPath<String>,
) -> Result<Json<VaultMetadataResponse>, ApiError> {
    let signer = validate_request_auth(&state, &headers, &method, &uri, None)?;
    let actor_npub = signer.to_npub().map_err(auth_error)?;
    let vault_id = VaultId::new(vault_id)?;

    let stored = {
        let store = state.store.lock().map_err(lock_error)?;
        store.load_vault(&vault_id)?
    };
    ensure_metadata_visible(&stored, &actor_npub)?;
    let mounted_folders = {
        let store = state.store.lock().map_err(lock_error)?;
        store.mounted_folder_projection(&vault_id, &UserId::new(actor_npub.clone())?)?
    };

    Ok(Json(metadata_response_with_mounts(stored, mounted_folders)))
}

async fn encrypted_vault_export_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(vault_id): AxumPath<String>,
) -> Result<Json<EncryptedVaultExportResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let actor_id = UserId::new(actor.clone())?;
    let vault_id = VaultId::new(vault_id)?;
    let export = {
        let store = state.store.lock().map_err(lock_error)?;
        let stored = store.load_vault(&vault_id)?;
        ensure_metadata_visible(&stored, &actor)?;
        store.encrypted_vault_export(&vault_id, &actor_id)?
    };
    Ok(Json(encrypted_vault_export_response(export)))
}

async fn vault_search_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(vault_id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let vault_id = VaultId::new(vault_id)?;
    {
        let store = state.store.lock().map_err(lock_error)?;
        let stored = store.load_vault(&vault_id)?;
        ensure_metadata_visible(&stored, &actor)?;
    }
    Err(ApiError::new(
        StatusCode::BAD_REQUEST,
        "plaintext search is client-side only over decrypted accessible content",
    ))
}

async fn add_member_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(vault_id): AxumPath<String>,
    body: Bytes,
) -> Result<Json<VaultMetadataResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: AdminTargetRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let vault_id = VaultId::new(vault_id)?;
    let target = UserId::new(request.target_npub.clone())?;
    let (event, payload) = validate_admin_access_change_value(
        request.access_change_event,
        &vault_id,
        &actor,
        AdminAccessAction::AddMember,
        None,
        Some(request.target_npub.as_str()),
        None,
    )?;
    mutate_as_admin(state, vault_id, actor, event, payload, |store, vault_id| {
        store.add_member(vault_id, &target)
    })
    .map(Json)
}

async fn remove_member_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath((vault_id, target_npub)): AxumPath<(String, String)>,
    body: Bytes,
) -> Result<Json<VaultMetadataResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: AdminEventRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let vault_id = VaultId::new(vault_id)?;
    let target = UserId::new(target_npub.clone())?;
    let (event, payload) = validate_admin_access_change_value(
        request.access_change_event,
        &vault_id,
        &actor,
        AdminAccessAction::RemoveMember,
        None,
        Some(target_npub.as_str()),
        None,
    )?;
    mutate_as_admin(state, vault_id, actor, event, payload, |store, vault_id| {
        store.remove_member(vault_id, &target)
    })
    .map(Json)
}

async fn add_admin_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(vault_id): AxumPath<String>,
    body: Bytes,
) -> Result<Json<VaultMetadataResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: AdminTargetRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let vault_id = VaultId::new(vault_id)?;
    let target = UserId::new(request.target_npub.clone())?;
    let (event, payload) = validate_admin_access_change_value(
        request.access_change_event,
        &vault_id,
        &actor,
        AdminAccessAction::AddAdmin,
        None,
        Some(request.target_npub.as_str()),
        None,
    )?;
    mutate_as_admin(state, vault_id, actor, event, payload, |store, vault_id| {
        store.add_admin(vault_id, &target)
    })
    .map(Json)
}

async fn remove_admin_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath((vault_id, target_npub)): AxumPath<(String, String)>,
    body: Bytes,
) -> Result<Json<VaultMetadataResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: AdminEventRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let vault_id = VaultId::new(vault_id)?;
    let target = UserId::new(target_npub.clone())?;
    let (event, payload) = validate_admin_access_change_value(
        request.access_change_event,
        &vault_id,
        &actor,
        AdminAccessAction::RemoveAdmin,
        None,
        Some(target_npub.as_str()),
        None,
    )?;
    mutate_as_admin(state, vault_id, actor, event, payload, |store, vault_id| {
        store.remove_admin(vault_id, &target)
    })
    .map(Json)
}

async fn create_vault_invitation_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(vault_id): AxumPath<String>,
    body: Bytes,
) -> Result<Json<VaultInvitationResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: CreateVaultInvitationRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let vault_id = VaultId::new(vault_id)?;
    let target = UserId::new(request.target_npub.clone())?;
    let initial_folder_access = request
        .initial_folder_access
        .into_iter()
        .map(FolderId::new)
        .collect::<Result<Vec<_>, _>>()?;
    let actor_user_id = UserId::new(actor.clone())?;
    let created_at = server_timestamp(&state);
    let id = generated_link_id(
        "invitation",
        &[
            vault_id.as_str(),
            target.as_str(),
            actor_user_id.as_str(),
            request.expires_at.as_str(),
            created_at.as_str(),
        ],
        16,
    );
    let invite_code = generated_link_id(
        "invite",
        &[
            vault_id.as_str(),
            target.as_str(),
            actor_user_id.as_str(),
            request.expires_at.as_str(),
            created_at.as_str(),
            "code",
        ],
        16,
    );
    let accept_path = format!("/_admin/vault-invitation-links/{invite_code}/accept");

    let invitation = {
        let mut store = state.store.lock().map_err(lock_error)?;
        let stored = store.load_vault(&vault_id)?;
        ensure_vault_admin(&stored, &actor)?;
        store.create_vault_invitation(
            &vault_id,
            &id,
            &target,
            &invite_code,
            &accept_path,
            &initial_folder_access,
            &actor_user_id,
            &request.expires_at,
            &created_at,
        )?
    };

    Ok(Json(vault_invitation_response(invitation)))
}

async fn revoke_vault_invitation_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath((vault_id, invitation_id)): AxumPath<(String, String)>,
) -> Result<Json<VaultInvitationResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let vault_id = VaultId::new(vault_id)?;
    let actor_user_id = UserId::new(actor)?;
    let updated_at = server_timestamp(&state);
    let invitation = {
        let mut store = state.store.lock().map_err(lock_error)?;
        store.revoke_vault_invitation(&vault_id, &invitation_id, &actor_user_id, &updated_at)?
    };
    Ok(Json(vault_invitation_response(invitation)))
}

async fn accept_vault_invitation_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath((vault_id, invitation_id)): AxumPath<(String, String)>,
) -> Result<Json<VaultInvitationResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let actor = UserId::new(actor)?;
    let vault_id = VaultId::new(vault_id)?;
    let now = server_timestamp(&state);
    let invitation = {
        let mut store = state.store.lock().map_err(lock_error)?;
        let invitation = store.load_vault_invitation(&invitation_id)?;
        if invitation.vault_id != vault_id {
            return Err(StoreError::UnavailableLink {
                kind: "vault invitation",
            }
            .into());
        }
        store.accept_vault_invitation_by_code(&invitation.invite_code, &actor, &now)?
    };
    Ok(Json(vault_invitation_response(invitation)))
}

async fn get_vault_invitation_link_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(invite_code): AxumPath<String>,
) -> Result<Json<VaultInvitationResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let actor = UserId::new(actor)?;
    let now = server_timestamp(&state);
    let invitation = {
        let store = state.store.lock().map_err(lock_error)?;
        store.load_available_vault_invitation_by_code(&invite_code, &actor, &now)?
    };
    Ok(Json(vault_invitation_response(invitation)))
}

async fn accept_vault_invitation_link_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(invite_code): AxumPath<String>,
) -> Result<Json<VaultInvitationResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let actor = UserId::new(actor)?;
    let now = server_timestamp(&state);
    let invitation = {
        let mut store = state.store.lock().map_err(lock_error)?;
        store.accept_vault_invitation_by_code(&invite_code, &actor, &now)?
    };
    Ok(Json(vault_invitation_response(invitation)))
}

async fn create_folder_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(vault_id): AxumPath<String>,
    body: Bytes,
) -> Result<Json<VaultMetadataResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: CreateFolderRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let vault_id = VaultId::new(vault_id)?;
    let folder = Folder {
        id: FolderId::new(request.folder_id)?,
        name: DisplayName::new("folder_name", request.name)?,
        role: request.role,
        access: request.access,
        parent_folder_id: request.parent_folder_id.map(FolderId::new).transpose()?,
        path: SafeRelativePath::new("folder_path", request.path)?,
        current_key_version: 1,
        shared_folder_source: request.shared_folder_source.unwrap_or(false),
    };
    let access_user_ids = user_id_set(request.access_user_ids)?;
    let (event, payload) = validate_admin_access_change_value(
        request.access_change_event,
        &vault_id,
        &actor,
        AdminAccessAction::SetFolderAccessMode,
        Some(&folder.id),
        None,
        Some(1),
    )?;
    let event_json = event.as_json();
    let grant_created_at = server_timestamp(&state);
    let grants = grant_requests_to_metadata(
        &request.grants,
        &folder.id,
        &actor,
        Some(event_json),
        &grant_created_at,
    )?;

    mutate_as_admin(state, vault_id, actor, event, payload, |store, vault_id| {
        store.create_folder(vault_id, &folder, &access_user_ids, &grants)
    })
    .map(Json)
}

async fn finish_folder_setup_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath((vault_id, folder_id)): AxumPath<(String, String)>,
    body: Bytes,
) -> Result<Json<VaultMetadataResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: FinishFolderSetupRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let vault_id = VaultId::new(vault_id)?;
    let folder_id = FolderId::new(folder_id)?;
    let current_key_version = {
        let store = state.store.lock().map_err(lock_error)?;
        let stored = store.load_vault(&vault_id)?;
        ensure_vault_admin(&stored, &actor)?;
        folder_current_key_version(&stored, &folder_id)?
    };
    let (event, payload) = validate_admin_access_change_value(
        request.access_change_event,
        &vault_id,
        &actor,
        AdminAccessAction::SetFolderAccessMode,
        Some(&folder_id),
        None,
        Some(current_key_version),
    )?;
    let event_json = event.as_json();
    let grant_created_at = server_timestamp(&state);
    let grants = grant_requests_to_metadata(
        &request.grants,
        &folder_id,
        &actor,
        Some(event_json),
        &grant_created_at,
    )?;

    mutate_as_admin(state, vault_id, actor, event, payload, |store, vault_id| {
        store.finish_folder_setup(vault_id, &folder_id, &grants)
    })
    .map(Json)
}

async fn grant_folder_access_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath((vault_id, folder_id)): AxumPath<(String, String)>,
    body: Bytes,
) -> Result<Json<VaultMetadataResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: GrantFolderAccessRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let vault_id = VaultId::new(vault_id)?;
    let folder_id = FolderId::new(folder_id)?;
    let target = UserId::new(request.target_npub.clone())?;
    let current_key_version = {
        let store = state.store.lock().map_err(lock_error)?;
        let stored = store.load_vault(&vault_id)?;
        ensure_vault_admin(&stored, &actor)?;
        folder_current_key_version(&stored, &folder_id)?
    };
    let (event, payload) = validate_admin_access_change_value(
        request.access_change_event,
        &vault_id,
        &actor,
        AdminAccessAction::GrantFolderAccess,
        Some(&folder_id),
        Some(request.target_npub.as_str()),
        Some(current_key_version),
    )?;
    let grant_created_at = server_timestamp(&state);
    let grant = grant_request_to_metadata(
        &request.grant,
        &folder_id,
        &actor,
        Some(event.as_json()),
        &grant_created_at,
    )?;

    mutate_as_admin(state, vault_id, actor, event, payload, |store, vault_id| {
        store.grant_folder_access(vault_id, &folder_id, &target, &grant)
    })
    .map(Json)
}

async fn remove_folder_access_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath((vault_id, folder_id, target_npub)): AxumPath<(String, String, String)>,
    body: Bytes,
) -> Result<Json<VaultMetadataResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: RemoveFolderAccessRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let vault_id = VaultId::new(vault_id)?;
    let folder_id = FolderId::new(folder_id)?;
    let target = UserId::new(target_npub.clone())?;
    {
        let store = state.store.lock().map_err(lock_error)?;
        let stored = store.load_vault(&vault_id)?;
        ensure_vault_admin(&stored, &actor)?;
    }
    let (event, payload) = validate_admin_access_change_value(
        request.access_change_event,
        &vault_id,
        &actor,
        AdminAccessAction::RemoveFolderAccess,
        Some(&folder_id),
        Some(target_npub.as_str()),
        Some(request.new_key_version),
    )?;
    let event_json = event.as_json();
    let grant_created_at = server_timestamp(&state);
    let grants = grant_requests_to_metadata(
        &request.grants,
        &folder_id,
        &actor,
        Some(event_json),
        &grant_created_at,
    )?;
    let mut reencrypted_records = Vec::new();
    for record in request.reencrypted_records {
        if record.key_version != request.new_key_version {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "rotation record keyVersion must match newKeyVersion",
            ));
        }
        let object_id = ObjectId::new(record.object_id)?;
        let write_request = ObjectWriteRequest {
            base_revision: record.base_revision,
            key_version: record.key_version,
            cipher: record.cipher,
            ciphertext: record.ciphertext,
            revision_event: record.revision_event,
        };
        let (record, _) = validate_object_revision_record(
            &vault_id,
            &folder_id,
            &object_id,
            &actor,
            write_request,
            FolderObjectOperation::Update,
        )?;
        reencrypted_records.push(record);
    }

    mutate_as_admin(state, vault_id, actor, event, payload, |store, vault_id| {
        store.rotate_folder_key_for_access_removal(
            vault_id,
            &folder_id,
            &target,
            request.new_key_version,
            &grants,
            &reencrypted_records,
        )
    })
    .map(Json)
}

async fn create_share_link_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath((vault_id, folder_id)): AxumPath<(String, String)>,
    body: Bytes,
) -> Result<Json<ShareLinkResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: CreateShareLinkRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let vault_id = VaultId::new(vault_id)?;
    let folder_id = FolderId::new(folder_id)?;
    let recipient = UserId::new(request.recipient_npub.clone())?;
    let current_key_version = {
        let store = state.store.lock().map_err(lock_error)?;
        let stored = store.load_vault(&vault_id)?;
        ensure_vault_admin(&stored, &actor)?;
        folder_current_key_version(&stored, &folder_id)?
    };
    let (event, _) = validate_admin_access_change_value(
        request.access_change_event,
        &vault_id,
        &actor,
        AdminAccessAction::GrantFolderAccess,
        Some(&folder_id),
        Some(request.recipient_npub.as_str()),
        Some(current_key_version),
    )?;
    let created_at = server_timestamp(&state);
    let grant = grant_request_to_metadata(
        &request.grant,
        &folder_id,
        &actor,
        Some(event.as_json()),
        &created_at,
    )?;
    let actor_user_id = UserId::new(actor.clone())?;
    let id = generated_link_id(
        "share-link",
        &[
            vault_id.as_str(),
            folder_id.as_str(),
            recipient.as_str(),
            actor_user_id.as_str(),
            request.expires_at.as_str(),
            created_at.as_str(),
        ],
        16,
    );
    let accept_path = format!("/_admin/share-links/{id}/accept");

    let share_link = {
        let mut store = state.store.lock().map_err(lock_error)?;
        store.create_share_link(
            &vault_id,
            &folder_id,
            &id,
            &recipient,
            &actor_user_id,
            &request.expires_at,
            &accept_path,
            &grant,
            request.create_personal_mount.unwrap_or(false),
            &created_at,
        )?
    };
    Ok(Json(share_link_response(share_link)))
}

async fn get_share_link_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(share_link_id): AxumPath<String>,
) -> Result<Json<ShareLinkResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let actor = UserId::new(actor)?;
    let now = server_timestamp(&state);
    let share_link = {
        let store = state.store.lock().map_err(lock_error)?;
        store.load_available_share_link(&share_link_id, &actor, &now)?
    };
    Ok(Json(share_link_response(share_link)))
}

async fn accept_share_link_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(share_link_id): AxumPath<String>,
) -> Result<Json<ShareLinkResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let actor = UserId::new(actor)?;
    let now = server_timestamp(&state);
    let share_link = {
        let mut store = state.store.lock().map_err(lock_error)?;
        store.accept_share_link(&share_link_id, &actor, &now)?
    };
    Ok(Json(share_link_response(share_link)))
}

async fn revoke_share_link_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(share_link_id): AxumPath<String>,
) -> Result<Json<ShareLinkResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let actor = UserId::new(actor)?;
    let now = server_timestamp(&state);
    let share_link = {
        let mut store = state.store.lock().map_err(lock_error)?;
        store.revoke_share_link(&share_link_id, &actor, &now)?
    };
    Ok(Json(share_link_response(share_link)))
}

async fn mark_shared_folder_source_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath((vault_id, folder_id)): AxumPath<(String, String)>,
    body: Bytes,
) -> Result<Json<VaultMetadataResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: MarkSharedFolderSourceRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let vault_id = VaultId::new(vault_id)?;
    let folder_id = FolderId::new(folder_id)?;
    let current_key_version = {
        let store = state.store.lock().map_err(lock_error)?;
        let stored = store.load_vault(&vault_id)?;
        ensure_vault_admin(&stored, &actor)?;
        folder_current_key_version(&stored, &folder_id)?
    };
    let (event, payload) = validate_admin_access_change_value(
        request.access_change_event,
        &vault_id,
        &actor,
        AdminAccessAction::SetFolderAccessMode,
        Some(&folder_id),
        None,
        Some(current_key_version),
    )?;
    mutate_as_admin(state, vault_id, actor, event, payload, |store, vault_id| {
        store.mark_shared_folder_source(vault_id, &folder_id)
    })
    .map(Json)
}

async fn create_shared_folder_invitation_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath((source_vault_id, source_folder_id)): AxumPath<(String, String)>,
    body: Bytes,
) -> Result<Json<SharedFolderInvitationResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: CreateSharedFolderInvitationRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let source_vault_id = VaultId::new(source_vault_id)?;
    let source_folder_id = FolderId::new(source_folder_id)?;
    let destination_vault_id = VaultId::new(request.destination_vault_id)?;
    let destination_admin = UserId::new(request.destination_admin_npub.clone())?;
    let current_key_version = {
        let store = state.store.lock().map_err(lock_error)?;
        let stored = store.load_vault(&source_vault_id)?;
        ensure_vault_admin(&stored, &actor)?;
        folder_current_key_version(&stored, &source_folder_id)?
    };
    let (event, _) = validate_admin_access_change_value(
        request.access_change_event,
        &source_vault_id,
        &actor,
        AdminAccessAction::GrantFolderAccess,
        Some(&source_folder_id),
        Some(destination_admin.as_str()),
        Some(current_key_version),
    )?;
    let created_at = server_timestamp(&state);
    let grant = grant_request_to_metadata(
        &request.grant,
        &source_folder_id,
        &actor,
        Some(event.as_json()),
        &created_at,
    )?;
    let actor_user_id = UserId::new(actor)?;
    let id = generated_link_id(
        "shared-folder-invitation",
        &[
            source_vault_id.as_str(),
            source_folder_id.as_str(),
            destination_vault_id.as_str(),
            destination_admin.as_str(),
            created_at.as_str(),
        ],
        16,
    );
    let accept_path = format!("/_admin/shared-folder-invitations/{id}/accept");
    let invitation = {
        let mut store = state.store.lock().map_err(lock_error)?;
        store.create_shared_folder_invitation(
            &source_vault_id,
            &source_folder_id,
            &destination_vault_id,
            &id,
            &destination_admin,
            &actor_user_id,
            &accept_path,
            &grant,
            &created_at,
        )?
    };
    Ok(Json(shared_folder_invitation_response(invitation)))
}

async fn get_shared_folder_invitation_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(invitation_id): AxumPath<String>,
) -> Result<Json<SharedFolderInvitationResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let invitation = {
        let store = state.store.lock().map_err(lock_error)?;
        let invitation = store.load_shared_folder_invitation(&invitation_id)?;
        if invitation.destination_admin_npub.as_str() != actor {
            return Err(StoreError::UnavailableLink {
                kind: "shared folder invitation",
            }
            .into());
        }
        invitation
    };
    Ok(Json(shared_folder_invitation_response(invitation)))
}

async fn accept_shared_folder_invitation_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(invitation_id): AxumPath<String>,
) -> Result<Json<SharedFolderInvitationResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let actor = UserId::new(actor)?;
    let now = server_timestamp(&state);
    let invitation = {
        let mut store = state.store.lock().map_err(lock_error)?;
        let invitation = store.load_shared_folder_invitation(&invitation_id)?;
        let connection_id = shared_folder_connection_id(
            &invitation.source_vault_id,
            &invitation.source_folder_id,
            &invitation.destination_vault_id,
        );
        let mount_id = organization_mount_id(
            &invitation.destination_vault_id,
            &invitation.source_vault_id,
            &invitation.source_folder_id,
        );
        store.accept_shared_folder_invitation(
            &invitation_id,
            &actor,
            &connection_id,
            &mount_id,
            &now,
        )?
    };
    Ok(Json(shared_folder_invitation_response(invitation)))
}

async fn revoke_shared_folder_invitation_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(invitation_id): AxumPath<String>,
) -> Result<Json<SharedFolderInvitationResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let actor = UserId::new(actor)?;
    let now = server_timestamp(&state);
    let invitation = {
        let mut store = state.store.lock().map_err(lock_error)?;
        store.revoke_shared_folder_invitation(&invitation_id, &actor, &now)?
    };
    Ok(Json(shared_folder_invitation_response(invitation)))
}

async fn update_shared_folder_connection_members_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(connection_id): AxumPath<String>,
    body: Bytes,
) -> Result<Json<SharedFolderConnectionResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let actor = UserId::new(actor)?;
    let request: UpdateSharedFolderConnectionMembersRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let target = UserId::new(request.target_npub.clone())?;
    let now = server_timestamp(&state);
    let connection = {
        let mut store = state.store.lock().map_err(lock_error)?;
        let connection = store.load_shared_folder_connection(&connection_id)?;
        match request.action.as_str() {
            "add" => {
                let grant = request.grant.as_ref().ok_or_else(|| {
                    ApiError::new(StatusCode::BAD_REQUEST, "grant is required for add")
                })?;
                let grant = grant_request_to_metadata(
                    grant,
                    &connection.source_folder_id,
                    actor.as_str(),
                    None,
                    &now,
                )?;
                store.add_shared_folder_connection_member(
                    &connection_id,
                    &actor,
                    &target,
                    &grant,
                    &now,
                )?
            }
            "remove" => {
                let new_key_version = request.new_key_version.ok_or_else(|| {
                    ApiError::new(
                        StatusCode::BAD_REQUEST,
                        "newKeyVersion is required for remove",
                    )
                })?;
                let grants = grant_requests_to_metadata(
                    &request.grants,
                    &connection.source_folder_id,
                    actor.as_str(),
                    None,
                    &now,
                )?;
                let reencrypted_records = rotation_records_from_requests(
                    &connection.source_vault_id,
                    &connection.source_folder_id,
                    actor.as_str(),
                    new_key_version,
                    request.reencrypted_records,
                )?;
                store.remove_shared_folder_connection_member(
                    &connection_id,
                    &actor,
                    &target,
                    new_key_version,
                    &grants,
                    &reencrypted_records,
                )?
            }
            _ => {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "action must be add or remove",
                ));
            }
        }
    };
    Ok(Json(shared_folder_connection_response(connection)))
}

async fn revoke_shared_folder_connection_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(connection_id): AxumPath<String>,
    body: Bytes,
) -> Result<Json<SharedFolderConnectionResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let actor = UserId::new(actor)?;
    let request: RevokeSharedFolderConnectionRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let now = server_timestamp(&state);
    let connection = {
        let mut store = state.store.lock().map_err(lock_error)?;
        let connection = store.load_shared_folder_connection(&connection_id)?;
        let grants = grant_requests_to_metadata(
            &request.grants,
            &connection.source_folder_id,
            actor.as_str(),
            None,
            &now,
        )?;
        let reencrypted_records = rotation_records_from_requests(
            &connection.source_vault_id,
            &connection.source_folder_id,
            actor.as_str(),
            request.new_key_version,
            request.reencrypted_records,
        )?;
        store.revoke_shared_folder_connection(
            &connection_id,
            &actor,
            request.new_key_version,
            &grants,
            &reencrypted_records,
            &now,
        )?
    };
    Ok(Json(shared_folder_connection_response(connection)))
}

async fn organization_folder_mounts_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(vault_id): AxumPath<String>,
) -> Result<Json<Vec<MountedFolderResponse>>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let actor = UserId::new(actor)?;
    let vault_id = VaultId::new(vault_id)?;
    let projections = {
        let store = state.store.lock().map_err(lock_error)?;
        let stored = store.load_vault(&vault_id)?;
        ensure_metadata_visible(&stored, actor.as_str())?;
        store.mounted_folder_projection(&vault_id, &actor)?
    };
    Ok(Json(mounted_folder_responses(projections)))
}

async fn put_object_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath((vault_id, folder_id, object_id)): AxumPath<(String, String, String)>,
    body: Bytes,
) -> Result<Json<ObjectWriteResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: ObjectWriteRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let operation = if request.base_revision.is_some() {
        FolderObjectOperation::Update
    } else {
        FolderObjectOperation::Create
    };
    accept_object_revision(
        state, vault_id, folder_id, object_id, actor, request, operation,
    )
    .map(Json)
}

async fn move_object_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath((vault_id, folder_id, object_id)): AxumPath<(String, String, String)>,
    body: Bytes,
) -> Result<Json<ObjectWriteResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: ObjectWriteRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    accept_object_revision(
        state,
        vault_id,
        folder_id,
        object_id,
        actor,
        request,
        FolderObjectOperation::Move,
    )
    .map(Json)
}

async fn delete_object_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath((vault_id, folder_id, object_id)): AxumPath<(String, String, String)>,
    body: Bytes,
) -> Result<Json<ObjectWriteResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let request: ObjectDeleteRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    accept_object_tombstone(state, vault_id, folder_id, object_id, actor, request).map(Json)
}

async fn get_object_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath((vault_id, folder_id, object_id)): AxumPath<(String, String, String)>,
) -> Result<Json<ObjectResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let vault_id = VaultId::new(vault_id)?;
    let folder_id = FolderId::new(folder_id)?;
    let object_id = ObjectId::new(object_id)?;
    let stored = {
        let store = state.store.lock().map_err(lock_error)?;
        store.load_vault(&vault_id)?
    };
    ensure_folder_visible(&stored, &folder_id, &actor)?;
    let bootstrap = {
        let store = state.store.lock().map_err(lock_error)?;
        store.sync_bootstrap(&vault_id)?
    };
    let object = bootstrap
        .objects
        .into_iter()
        .find(|object| object.folder_id == folder_id && object.object_id == object_id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "object not found"))?;
    if object.deleted {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "object not found"));
    }

    Ok(Json(ObjectResponse {
        vault_id: vault_id.to_string(),
        folder_id: object.folder_id.to_string(),
        object_id: object.object_id.as_str().to_owned(),
        revision: object.revision,
        ciphertext: object.payload_json,
        deleted: object.deleted,
    }))
}

async fn sync_bootstrap_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(vault_id): AxumPath<String>,
) -> Result<Json<SyncBootstrapResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let vault_id = VaultId::new(vault_id)?;
    let stored = {
        let store = state.store.lock().map_err(lock_error)?;
        store.load_vault(&vault_id)?
    };
    ensure_metadata_visible(&stored, &actor)?;
    let bootstrap = {
        let store = state.store.lock().map_err(lock_error)?;
        store.sync_bootstrap(&vault_id)?
    };
    let objects = bootstrap
        .objects
        .into_iter()
        .filter(|object| folder_visible(&stored, &object.folder_id, &actor))
        .map(|object| ObjectResponse {
            vault_id: vault_id.to_string(),
            folder_id: object.folder_id.to_string(),
            object_id: object.object_id.as_str().to_owned(),
            revision: object.revision,
            ciphertext: object.payload_json,
            deleted: object.deleted,
        })
        .collect::<Vec<_>>();

    Ok(Json(SyncBootstrapResponse {
        vault_id: vault_id.to_string(),
        latest_sequence: bootstrap.latest_sequence,
        object_count: objects.len(),
        objects,
        current_state_kind: bootstrap.current_state_kind.to_owned(),
    }))
}

async fn sync_records_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(vault_id): AxumPath<String>,
    Query(query): Query<SyncRecordsQuery>,
) -> Result<Json<SyncPullResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, None)?
        .to_npub()
        .map_err(auth_error)?;
    let vault_id = VaultId::new(vault_id)?;
    let stored = {
        let store = state.store.lock().map_err(lock_error)?;
        store.load_vault(&vault_id)?
    };
    ensure_metadata_visible(&stored, &actor)?;
    let pull = {
        let store = state.store.lock().map_err(lock_error)?;
        let limit = query.limit.unwrap_or(100).clamp(1, MAX_SYNC_RECORDS_LIMIT);
        store.pull_sync_records(&vault_id, query.after.unwrap_or(0), limit)?
    };
    let records = pull
        .records
        .into_iter()
        .filter(|record| record_visible(&stored, record, &actor))
        .map(sync_record_response)
        .collect::<Vec<_>>();
    Ok(Json(SyncPullResponse {
        vault_id: vault_id.to_string(),
        after_sequence: pull.after_sequence,
        latest_sequence: pull.latest_sequence,
        count: records.len(),
        records,
        has_more: pull.has_more,
        next_sequence: pull.next_sequence,
    }))
}

async fn submit_sync_record_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    AxumPath(vault_id): AxumPath<String>,
    body: Bytes,
) -> Result<Json<ObjectWriteResponse>, ApiError> {
    let actor = validate_request_auth(&state, &headers, &method, &uri, Some(&body))?
        .to_npub()
        .map_err(auth_error)?;
    let value: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let record_type = value
        .get("recordType")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "recordType is required"))?;
    match record_type {
        "folder_object_revision" => {
            let request: ObjectWriteRequest = serde_json::from_value(value)
                .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid revision record"))?;
            let folder_id = request_field(&body, "folderId")?;
            let object_id = request_field(&body, "objectId")?;
            let operation = if request.base_revision.is_some() {
                FolderObjectOperation::Update
            } else {
                FolderObjectOperation::Create
            };
            accept_object_revision(
                state, vault_id, folder_id, object_id, actor, request, operation,
            )
            .map(Json)
        }
        "folder_object_tombstone" => {
            let request: ObjectDeleteRequest = serde_json::from_value(value)
                .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid tombstone record"))?;
            let folder_id = request_field(&body, "folderId")?;
            let object_id = request_field(&body, "objectId")?;
            accept_object_tombstone(state, vault_id, folder_id, object_id, actor, request).map(Json)
        }
        _ => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "unsupported recordType",
        )),
    }
}

fn validate_request_auth(
    state: &ServerState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: Option<&[u8]>,
) -> Result<NostrPublicKey, ApiError> {
    let authorization = headers
        .get(AUTHORIZATION)
        .or_else(|| headers.get(NOSTR_AUTHORIZATION_HEADER))
        .or_else(|| headers.get(FINITEBRAIN_NOSTR_HEADER))
        .ok_or_else(|| auth_error_message("valid Nostr authorization is required"))?
        .to_str()
        .map_err(|_| auth_error_message("valid Nostr authorization is required"))?;
    let encoded = authorization
        .strip_prefix("Nostr ")
        .ok_or_else(|| auth_error_message("valid Nostr authorization is required"))?;
    let event_json = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| auth_error_message("valid Nostr authorization is required"))?;
    let event_json = str::from_utf8(&event_json)
        .map_err(|_| auth_error_message("valid Nostr authorization is required"))?;
    let event = Event::from_json(event_json)
        .map_err(|_| auth_error_message("valid Nostr authorization is required"))?;

    let expected_url = absolute_url(&state.public_base_url, uri);
    let mut expected = HttpAuthValidation::new(
        method.as_str(),
        expected_url,
        state.auth_now_unix_seconds(),
        state.max_auth_skew_seconds,
    );
    if let Some(body) = body {
        expected = expected.with_body(body.to_vec());
    }

    finite_nostr::validate_http_auth_event(&event, &expected).map_err(auth_error)
}

fn accept_object_revision(
    state: ServerState,
    vault_id: String,
    folder_id: String,
    object_id: String,
    actor_npub: String,
    request: ObjectWriteRequest,
    operation: FolderObjectOperation,
) -> Result<ObjectWriteResponse, ApiError> {
    let vault_id = VaultId::new(vault_id)?;
    let folder_id = FolderId::new(folder_id)?;
    let object_id = ObjectId::new(object_id)?;

    let stored = {
        let store = state.store.lock().map_err(lock_error)?;
        store.load_vault(&vault_id)?
    };
    ensure_folder_visible(&stored, &folder_id, &actor_npub)?;
    ensure_folder_key_version(&stored, &folder_id, request.key_version)?;
    let request_key_version = request.key_version;

    let (record, revision) = validate_object_revision_record(
        &vault_id,
        &folder_id,
        &object_id,
        &actor_npub,
        request,
        operation,
    )?;
    let outcome = {
        let mut store = state.store.lock().map_err(lock_error)?;
        let stored = store.load_vault(&vault_id)?;
        ensure_folder_visible(&stored, &folder_id, &actor_npub)?;
        ensure_folder_key_version(&stored, &folder_id, request_key_version)?;
        store.submit_sync_record(&vault_id, &SyncRecordInput::FolderObjectRevision(record))?
    };

    Ok(ObjectWriteResponse {
        sequence: outcome.sequence,
        duplicate: outcome.duplicate,
        revision,
    })
}

fn validate_object_revision_record(
    vault_id: &VaultId,
    folder_id: &FolderId,
    object_id: &ObjectId,
    actor_npub: &str,
    request: ObjectWriteRequest,
    operation: FolderObjectOperation,
) -> Result<(FolderObjectRevisionSyncRecord, u64), ApiError> {
    if request.cipher != "AES-256-GCM" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "cipher must be AES-256-GCM",
        ));
    }
    let revision = request.base_revision.map_or(1, |base| base + 1);
    let event = event_from_value(request.revision_event)?;
    let expected = RevisionValidation {
        vault_id: vault_id.clone(),
        folder_id: folder_id.clone(),
        object_id: object_id.clone(),
        operation,
        revision,
        base_revision: request.base_revision,
        key_version: request.key_version,
        envelope_json: request.ciphertext.clone(),
        author_npub: actor_npub.to_owned(),
        created_at: expected_created_at(&event),
    };
    let payload: FolderObjectRevisionPayload = validate_revision_event(&event, &expected)?;
    Ok((
        FolderObjectRevisionSyncRecord {
            record_event_id: event.id.to_hex(),
            folder_id: folder_id.clone(),
            object_id: object_id.clone(),
            revision,
            base_revision: request.base_revision,
            actor_npub: UserId::new(actor_npub.to_owned())?,
            client_created_at: payload.created_at,
            payload_json: request.ciphertext,
            record_event_kind: event.kind.as_u16(),
        },
        revision,
    ))
}

fn rotation_records_from_requests(
    vault_id: &VaultId,
    folder_id: &FolderId,
    actor_npub: &str,
    new_key_version: u32,
    requests: Vec<RotationObjectRequest>,
) -> Result<Vec<FolderObjectRevisionSyncRecord>, ApiError> {
    let mut records = Vec::new();
    for request in requests {
        if request.key_version != new_key_version {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "rotation record keyVersion must match newKeyVersion",
            ));
        }
        let object_id = ObjectId::new(request.object_id)?;
        let write_request = ObjectWriteRequest {
            base_revision: request.base_revision,
            key_version: request.key_version,
            cipher: request.cipher,
            ciphertext: request.ciphertext,
            revision_event: request.revision_event,
        };
        let (record, _) = validate_object_revision_record(
            vault_id,
            folder_id,
            &object_id,
            actor_npub,
            write_request,
            FolderObjectOperation::Update,
        )?;
        records.push(record);
    }
    Ok(records)
}

fn accept_object_tombstone(
    state: ServerState,
    vault_id: String,
    folder_id: String,
    object_id: String,
    actor_npub: String,
    request: ObjectDeleteRequest,
) -> Result<ObjectWriteResponse, ApiError> {
    let vault_id = VaultId::new(vault_id)?;
    let folder_id = FolderId::new(folder_id)?;
    let object_id = ObjectId::new(object_id)?;
    let revision = request.base_revision + 1;
    let event = event_from_value(request.tombstone_event)?;

    let stored = {
        let store = state.store.lock().map_err(lock_error)?;
        store.load_vault(&vault_id)?
    };
    ensure_folder_visible(&stored, &folder_id, &actor_npub)?;

    let expected = TombstoneValidation {
        vault_id: vault_id.clone(),
        folder_id: folder_id.clone(),
        object_id: object_id.clone(),
        revision,
        base_revision: request.base_revision,
        author_npub: actor_npub.clone(),
        deleted_at: expected_created_at(&event),
    };
    let payload: FolderObjectTombstonePayload = validate_tombstone_event(&event, &expected)?;
    let outcome = {
        let mut store = state.store.lock().map_err(lock_error)?;
        let stored = store.load_vault(&vault_id)?;
        ensure_folder_visible(&stored, &folder_id, &actor_npub)?;
        store.submit_sync_record(
            &vault_id,
            &SyncRecordInput::FolderObjectTombstone(FolderObjectTombstoneSyncRecord {
                record_event_id: event.id.to_hex(),
                folder_id,
                object_id,
                revision,
                base_revision: request.base_revision,
                actor_npub: UserId::new(actor_npub)?,
                client_created_at: payload.deleted_at,
                payload_json: serde_json::to_string(&serde_json::json!({"deleted": true}))
                    .expect("static JSON serializes"),
                record_event_kind: event.kind.as_u16(),
            }),
        )?
    };

    Ok(ObjectWriteResponse {
        sequence: outcome.sequence,
        duplicate: outcome.duplicate,
        revision,
    })
}

fn event_from_value(value: serde_json::Value) -> Result<Event, ApiError> {
    Event::from_json(value.to_string()).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "signed Nostr event JSON did not parse",
        )
    })
}

fn validate_admin_access_change_value(
    value: serde_json::Value,
    vault_id: &VaultId,
    admin_npub: &str,
    action: AdminAccessAction,
    folder_id: Option<&FolderId>,
    target_npub: Option<&str>,
    key_version: Option<u32>,
) -> Result<(Event, AdminAccessChangePayload), ApiError> {
    let event = event_from_value(value)?;
    if event.kind.as_u16() != APP_SPECIFIC_KIND {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("admin access-change event must be kind {APP_SPECIFIC_KIND}"),
        ));
    }
    let hint: AdminAccessChangePayload = serde_json::from_str(&event.content).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "admin access-change event content did not parse",
        )
    })?;
    let expected = AdminAccessChangeValidation {
        vault_id: vault_id.clone(),
        change_id: hint.change_id,
        action,
        admin_npub: admin_npub.to_owned(),
        folder_id: folder_id.cloned(),
        target_npub: target_npub.map(ToOwned::to_owned),
        key_version,
        note: hint.note,
        created_at: expected_created_at(&event),
    };
    let payload = validate_admin_access_change_event(&event, &expected)?;
    Ok((event, payload))
}

fn mutate_as_admin<F>(
    state: ServerState,
    vault_id: VaultId,
    actor_npub: String,
    event: Event,
    payload: AdminAccessChangePayload,
    mutation: F,
) -> Result<VaultMetadataResponse, ApiError>
where
    F: FnOnce(&mut BrainStore, &VaultId) -> Result<(), StoreError>,
{
    let stored = {
        let mut store = state.store.lock().map_err(lock_error)?;
        let stored = store.load_vault(&vault_id)?;
        ensure_vault_admin(&stored, &actor_npub)?;
        mutation(&mut store, &vault_id)?;
        append_admin_access_change_record(&mut store, &vault_id, &actor_npub, &event, &payload)?;
        store.load_vault(&vault_id)?
    };
    Ok(metadata_response(stored))
}

fn append_admin_access_change_record(
    store: &mut BrainStore,
    vault_id: &VaultId,
    actor_npub: &str,
    event: &Event,
    payload: &AdminAccessChangePayload,
) -> Result<(), ApiError> {
    let folder_id = payload.folder_id.as_ref().map(FolderId::new).transpose()?;
    store.submit_sync_record(
        vault_id,
        &SyncRecordInput::Control(ControlSyncRecord {
            record_event_id: event.id.to_hex(),
            record_type: SyncRecordType::VaultAdminAccessChange,
            folder_id,
            actor_npub: UserId::new(actor_npub.to_owned())?,
            client_created_at: payload.created_at.clone(),
            payload_json: event.content.clone(),
            record_event_kind: event.kind.as_u16(),
        }),
    )?;
    Ok(())
}

fn user_id_set(values: Vec<String>) -> Result<BTreeSet<UserId>, ApiError> {
    values
        .into_iter()
        .map(UserId::new)
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(ApiError::from)
}

fn grant_requests_to_metadata(
    requests: &[FolderKeyGrantRequest],
    folder_id: &FolderId,
    issuer_npub: &str,
    access_change_event_json: Option<String>,
    default_created_at: &str,
) -> Result<Vec<FolderKeyGrantMetadata>, ApiError> {
    requests
        .iter()
        .map(|request| {
            grant_request_to_metadata(
                request,
                folder_id,
                issuer_npub,
                access_change_event_json.clone(),
                default_created_at,
            )
        })
        .collect()
}

fn grant_request_to_metadata(
    request: &FolderKeyGrantRequest,
    folder_id: &FolderId,
    issuer_npub: &str,
    access_change_event_json: Option<String>,
    default_created_at: &str,
) -> Result<FolderKeyGrantMetadata, ApiError> {
    Ok(FolderKeyGrantMetadata {
        id: request.id.clone(),
        folder_id: folder_id.clone(),
        key_version: request.key_version,
        issuer_npub: UserId::new(issuer_npub.to_owned())?,
        recipient_npub: UserId::new(request.recipient_npub.clone())?,
        format: "NIP-59".to_owned(),
        wrapped_event_json: request.wrapped_event_json.clone(),
        access_change_event_json,
        created_at: request
            .created_at
            .clone()
            .unwrap_or_else(|| default_created_at.to_owned()),
    })
}

fn expected_created_at(event: &Event) -> String {
    event.created_at.as_secs().to_string()
}

fn ensure_vault_admin(stored: &StoredVault, actor_npub: &str) -> Result<(), ApiError> {
    let is_admin = stored
        .vault
        .admins
        .iter()
        .any(|admin| admin.as_str() == actor_npub);
    if is_admin {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "vault admin access required",
        ))
    }
}

fn folder_current_key_version(stored: &StoredVault, folder_id: &FolderId) -> Result<u32, ApiError> {
    stored
        .vault
        .folders
        .iter()
        .find(|folder| folder.id == *folder_id)
        .map(|folder| folder.current_key_version)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "folder not found"))
}

fn ensure_folder_key_version(
    stored: &StoredVault,
    folder_id: &FolderId,
    key_version: u32,
) -> Result<(), ApiError> {
    let folder = stored
        .vault
        .folders
        .iter()
        .find(|folder| folder.id == *folder_id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "folder not found"))?;
    if folder.current_key_version == key_version {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "keyVersion does not match current Folder Key version",
        ))
    }
}

fn ensure_folder_visible(
    stored: &StoredVault,
    folder_id: &FolderId,
    actor_npub: &str,
) -> Result<(), ApiError> {
    if folder_visible(stored, folder_id, actor_npub) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "folder access required",
        ))
    }
}

fn folder_visible(stored: &StoredVault, folder_id: &FolderId, actor_npub: &str) -> bool {
    let Some(folder) = stored
        .vault
        .folders
        .iter()
        .find(|folder| folder.id == *folder_id)
    else {
        return false;
    };
    let is_owner = stored
        .vault
        .owner_user_id
        .as_ref()
        .is_some_and(|owner| owner.as_str() == actor_npub);
    let is_admin = stored
        .vault
        .admins
        .iter()
        .any(|admin| admin.as_str() == actor_npub);
    let is_member = stored
        .vault
        .members
        .iter()
        .any(|member| member.user_id.as_str() == actor_npub);

    match folder.access {
        FolderAccessMode::Owner => is_owner,
        FolderAccessMode::AdminOnly => is_admin,
        FolderAccessMode::AllMembers => is_admin || is_member,
        FolderAccessMode::Restricted => {
            is_admin
                || stored
                    .folder_access
                    .get(folder_id)
                    .is_some_and(|users| users.iter().any(|user| user.as_str() == actor_npub))
        }
    }
}

fn record_visible(stored: &StoredVault, record: &StoredSyncRecord, actor_npub: &str) -> bool {
    record
        .folder_id
        .as_ref()
        .is_none_or(|folder_id| folder_visible(stored, folder_id, actor_npub))
}

fn sync_record_response(record: StoredSyncRecord) -> SyncRecordResponse {
    SyncRecordResponse {
        sequence: record.sequence,
        record_event_id: record.record_event_id,
        record_type: match record.record_type {
            SyncRecordType::FolderObjectRevision => "folder_object_revision",
            SyncRecordType::FolderObjectTombstone => "folder_object_tombstone",
            SyncRecordType::FolderKeyGrant => "folder_key_grant",
            SyncRecordType::VaultAdminAccessChange => "vault_admin_access_change",
        }
        .to_owned(),
        folder_id: record.folder_id.map(|folder_id| folder_id.to_string()),
        object_id: record
            .object_id
            .map(|object_id| object_id.as_str().to_owned()),
        revision: record.revision,
        actor_npub: record.actor_npub.to_string(),
        client_created_at: record.client_created_at,
        payload_json: record.payload_json,
        record_event_kind: record.record_event_kind,
    }
}

fn request_field(body: &[u8], field: &'static str) -> Result<String, ApiError> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get(field)
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
        })
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, format!("{field} is required")))
}

fn auth_error(error: NostrPrimitiveError) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, error.to_string())
}

fn auth_error_message(message: &'static str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, message)
}

fn lock_error<T>(_error: T) -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned")
}

fn absolute_url(public_base_url: &str, uri: &Uri) -> String {
    let path_and_query = uri
        .path_and_query()
        .map_or(uri.path(), |path_and_query| path_and_query.as_str());
    format!(
        "{}{}",
        public_base_url.trim_end_matches('/'),
        path_and_query
    )
}

fn grants_for_required(
    required: &[RequiredFolderKeyGrant],
    issuer_npub: &str,
) -> Vec<FolderKeyGrantMetadata> {
    required
        .iter()
        .map(|required| FolderKeyGrantMetadata {
            id: format!(
                "bootstrap-{}-{}-{}",
                required.folder_id, required.key_version, required.recipient_user_id
            ),
            folder_id: required.folder_id.clone(),
            key_version: required.key_version,
            issuer_npub: UserId::new(issuer_npub).expect("issuer npub was already validated"),
            recipient_npub: required.recipient_user_id.clone(),
            format: "NIP-59".to_owned(),
            wrapped_event_json: "{\"kind\":1059}".to_owned(),
            access_change_event_json: None,
            created_at: "2026-06-23T00:00:00.000Z".to_owned(),
        })
        .collect()
}

fn metadata_response(stored: StoredVault) -> VaultMetadataResponse {
    metadata_response_with_mounts(stored, Vec::new())
}

fn metadata_response_with_mounts(
    stored: StoredVault,
    mounted_folders: Vec<MountedFolderProjection>,
) -> VaultMetadataResponse {
    let folder_access = stored.folder_access;
    let setup_incomplete = stored.setup_incomplete_folder_ids;
    VaultMetadataResponse {
        vault_id: stored.vault.id.to_string(),
        kind: stored.vault.kind,
        name: stored.vault.name.to_string(),
        owner_user_id: stored.vault.owner_user_id.map(|owner| owner.to_string()),
        members: stored
            .vault
            .members
            .iter()
            .map(|member| member.user_id.to_string())
            .collect(),
        admins: stored
            .vault
            .admins
            .iter()
            .map(ToString::to_string)
            .collect(),
        folders: stored
            .vault
            .folders
            .iter()
            .map(|folder| FolderMetadataResponse {
                id: folder.id.to_string(),
                name: folder.name.to_string(),
                role: folder.role,
                access: folder.access,
                parent_folder_id: folder.parent_folder_id.as_ref().map(ToString::to_string),
                path: folder.path.to_string(),
                shared_folder_source: folder.shared_folder_source,
                access_user_ids: folder_access
                    .get(&folder.id)
                    .map(|users| users.iter().map(ToString::to_string).collect())
                    .unwrap_or_default(),
                current_key_version: folder.current_key_version,
                setup_incomplete: setup_incomplete.contains(&folder.id),
            })
            .collect(),
        mounted_folders: mounted_folder_responses(mounted_folders),
        grant_count: stored.grants.len(),
    }
}

fn vault_invitation_response(invitation: StoredVaultInvitation) -> VaultInvitationResponse {
    VaultInvitationResponse {
        id: invitation.id,
        vault_id: invitation.vault_id.to_string(),
        user_id: invitation.user_id.to_string(),
        status: link_status_str(invitation.status).to_owned(),
        invite_code: invitation.invite_code,
        accept_path: invitation.accept_path,
        initial_folder_access: invitation
            .initial_folder_access
            .into_iter()
            .map(|folder_id| folder_id.to_string())
            .collect(),
        expires_at: invitation.expires_at,
        created_at: invitation.created_at,
        updated_at: invitation.updated_at,
        accepted_at: invitation.accepted_at,
        duplicate_accept: invitation.duplicate_accept,
    }
}

fn share_link_response(share_link: StoredShareLink) -> ShareLinkResponse {
    ShareLinkResponse {
        id: share_link.id,
        vault_id: share_link.vault_id.to_string(),
        folder_id: share_link.folder_id.to_string(),
        recipient_npub: share_link.recipient_npub.to_string(),
        created_by_npub: share_link.created_by_npub.to_string(),
        status: link_status_str(share_link.status).to_owned(),
        accept_path: share_link.accept_path,
        expires_at: share_link.expires_at,
        created_at: share_link.created_at,
        updated_at: share_link.updated_at,
        accepted_at: share_link.accepted_at,
        grant_id: share_link.folder_key_grant.id,
        create_personal_mount: share_link.create_personal_mount,
        personal_mount_id: share_link.personal_mount_id,
        duplicate_accept: share_link.duplicate_accept,
    }
}

fn shared_folder_invitation_response(
    invitation: StoredSharedFolderInvitation,
) -> SharedFolderInvitationResponse {
    SharedFolderInvitationResponse {
        id: invitation.id,
        source_vault_id: invitation.source_vault_id.to_string(),
        source_folder_id: invitation.source_folder_id.to_string(),
        destination_vault_id: invitation.destination_vault_id.to_string(),
        destination_admin_npub: invitation.destination_admin_npub.to_string(),
        created_by_npub: invitation.created_by_npub.to_string(),
        status: link_status_str(invitation.status).to_owned(),
        current_key_version: invitation.current_key_version,
        accept_path: invitation.accept_path,
        created_at: invitation.created_at,
        updated_at: invitation.updated_at,
        accepted_at: invitation.accepted_at,
        grant_id: invitation.folder_key_grant.id,
        duplicate_accept: invitation.duplicate_accept,
    }
}

fn shared_folder_connection_response(
    connection: StoredSharedFolderConnection,
) -> SharedFolderConnectionResponse {
    SharedFolderConnectionResponse {
        id: connection.id,
        source_vault_id: connection.source_vault_id.to_string(),
        source_folder_id: connection.source_folder_id.to_string(),
        destination_vault_id: connection.destination_vault_id.to_string(),
        destination_admin_npub: connection.destination_admin_npub.to_string(),
        status: match connection.status {
            SharedFolderConnectionStatus::Active => "active",
            SharedFolderConnectionStatus::Revoked => "revoked",
        }
        .to_owned(),
        created_at: connection.created_at,
        updated_at: connection.updated_at,
        member_npubs: connection
            .member_npubs
            .iter()
            .map(ToString::to_string)
            .collect(),
    }
}

fn mounted_folder_responses(
    mounted_folders: Vec<MountedFolderProjection>,
) -> Vec<MountedFolderResponse> {
    mounted_folders
        .into_iter()
        .map(|mount| MountedFolderResponse {
            mount_id: mount.mount_id,
            organization_vault_id: mount.organization_vault_id.to_string(),
            source_vault_id: mount.source_vault_id.to_string(),
            source_folder_id: mount.source_folder_id.to_string(),
            connection_id: mount.connection_id,
            display_name: mount.display_name,
            display_parent_folder_id: mount.display_parent_folder_id.map(|id| id.to_string()),
            state: match mount.state {
                MountedFolderState::Available => "available",
                MountedFolderState::Locked => "locked",
                MountedFolderState::Revoked => "revoked",
            }
            .to_owned(),
        })
        .collect()
}

fn encrypted_vault_export_response(export: EncryptedVaultExport) -> EncryptedVaultExportResponse {
    EncryptedVaultExportResponse {
        version: export.version,
        vault: ExportVaultSummaryResponse {
            id: export.vault.id.to_string(),
            kind: export.vault.kind,
            name: export.vault.name.to_string(),
            owner_user_id: export.vault.owner_user_id.map(|owner| owner.to_string()),
        },
        folders: export
            .folders
            .into_iter()
            .map(|folder| EncryptedExportFolderResponse {
                id: folder.id.to_string(),
                path: folder.path.to_string(),
                access: folder.access,
                current_key_version: folder.current_key_version,
                shared_folder_source: folder.shared_folder_source,
                accessible: folder.accessible,
            })
            .collect(),
        objects: export
            .objects
            .into_iter()
            .map(|object| EncryptedExportObjectResponse {
                folder_id: object.folder_id.to_string(),
                object_id: object.object_id.as_str().to_owned(),
                payload_json: object.payload_json,
                revision: object.revision,
                updated_at: object.updated_at,
                deleted: object.deleted,
                opaque: object.opaque,
            })
            .collect(),
        key_grants: export
            .key_grants
            .into_iter()
            .map(folder_key_grant_response)
            .collect(),
        access_state: EncryptedExportAccessStateResponse {
            members: export
                .access_state
                .members
                .into_iter()
                .map(|member| member.to_string())
                .collect(),
            admins: export
                .access_state
                .admins
                .into_iter()
                .map(|admin| admin.to_string())
                .collect(),
            folders: export
                .access_state
                .folders
                .into_iter()
                .map(|folder| EncryptedExportFolderAccessResponse {
                    folder_id: folder.folder_id.to_string(),
                    user_ids: folder
                        .user_ids
                        .into_iter()
                        .map(|user_id| user_id.to_string())
                        .collect(),
                })
                .collect(),
        },
    }
}

fn folder_key_grant_response(grant: FolderKeyGrantMetadata) -> FolderKeyGrantResponse {
    FolderKeyGrantResponse {
        id: grant.id,
        folder_id: grant.folder_id.to_string(),
        key_version: grant.key_version,
        issuer_npub: grant.issuer_npub.to_string(),
        recipient_npub: grant.recipient_npub.to_string(),
        format: grant.format,
        wrapped_event_json: grant.wrapped_event_json,
        access_change_event_json: grant.access_change_event_json,
        created_at: grant.created_at,
    }
}

fn link_status_str(status: LinkStatus) -> &'static str {
    match status {
        LinkStatus::Pending => "pending",
        LinkStatus::Accepted => "accepted",
        LinkStatus::Revoked => "revoked",
    }
}

fn shared_folder_connection_id(
    source_vault_id: &VaultId,
    source_folder_id: &FolderId,
    destination_vault_id: &VaultId,
) -> String {
    generated_link_id(
        "shared-folder-connection",
        &[
            source_vault_id.as_str(),
            source_folder_id.as_str(),
            destination_vault_id.as_str(),
        ],
        8,
    )
}

fn organization_mount_id(
    organization_vault_id: &VaultId,
    source_vault_id: &VaultId,
    source_folder_id: &FolderId,
) -> String {
    generated_link_id(
        "organization-mount",
        &[
            organization_vault_id.as_str(),
            source_vault_id.as_str(),
            source_folder_id.as_str(),
        ],
        8,
    )
}

fn ensure_metadata_visible(stored: &StoredVault, actor_npub: &str) -> Result<(), ApiError> {
    match stored.vault.kind {
        VaultKind::Personal => {
            if stored
                .vault
                .owner_user_id
                .as_ref()
                .is_some_and(|owner| owner.as_str() == actor_npub)
            {
                Ok(())
            } else {
                Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "vault access required",
                ))
            }
        }
        VaultKind::Organization => {
            let is_member = stored
                .vault
                .members
                .iter()
                .any(|member| member.user_id.as_str() == actor_npub);
            if is_member {
                Ok(())
            } else {
                Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "vault access required",
                ))
            }
        }
    }
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn server_timestamp(state: &ServerState) -> String {
    OffsetDateTime::from_unix_timestamp(state.auth_now_unix_seconds() as i64)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn generated_link_id(prefix: &str, parts: &[&str], hash_bytes: usize) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(b"\n");
    }
    let hash = hasher.finalize();
    format!("{prefix}-{}", hex_prefix(&hash, hash_bytes))
}

fn hex_prefix(bytes: &[u8], len: usize) -> String {
    bytes
        .iter()
        .take(len)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use finite_brain_core::{FolderKey, FolderObjectAad, encrypt_folder_object_with_nonce};
    use nostr::event::FinalizeEvent;
    use nostr::hashes::Hash;
    use nostr::hashes::sha256::Hash as Sha256Hash;
    use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
    use tower::ServiceExt;

    const TEST_NOW: u64 = 1_780_000_000;
    const TEST_BASE_URL: &str = "http://finite.test";

    #[test]
    fn health_status_identifies_workspace_layers() {
        assert_eq!(
            health_status(),
            HealthStatus {
                service: "finite-brain".to_owned(),
                status: "ok".to_owned(),
                core_crate: "finite-brain-core".to_owned(),
                store_crate: "finite-brain-store".to_owned(),
            }
        );
    }

    #[test]
    fn server_state_defaults_to_portable_v1_auth_skew() {
        let state = ServerState::new(BrainStore::open_in_memory().unwrap(), TEST_BASE_URL);
        assert_eq!(state.max_auth_skew_seconds, 60);
        assert_eq!(state.auth_now_unix_seconds, None);
    }

    #[tokio::test]
    async fn health_route_returns_workspace_status_without_auth() {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("health route response");

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("health body");
        let status: HealthStatus = serde_json::from_slice(&body).expect("health json");

        assert_eq!(status, health_status());
    }

    #[tokio::test]
    async fn smoke_bootstrap_route_returns_core_summary() {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .uri("/smoke/bootstrap")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("bootstrap route response");

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 4096)
            .await
            .expect("bootstrap body");
        let summary: BootstrapSmokeSummary = serde_json::from_slice(&body).expect("bootstrap json");

        assert_eq!(
            summary,
            finite_brain_core::smoke_bootstrap_summary().expect("smoke bootstrap summary")
        );
    }

    #[tokio::test]
    async fn smoke_ui_serves_static_assets_and_sqlite_flow_works() {
        let temp_dir = tempfile::TempDir::new().expect("temp sqlite dir");
        let db_path = temp_dir.path().join("smoke-ui.sqlite3");
        let router = sqlite_test_router(&db_path);

        let ui_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/smoke/ui")
                    .body(Body::empty())
                    .expect("valid ui request"),
            )
            .await
            .expect("ui response");
        assert_eq!(ui_response.status(), StatusCode::OK);
        let ui_body = to_bytes(ui_response.into_body(), 16 * 1024)
            .await
            .expect("ui body");
        let ui_body = std::str::from_utf8(&ui_body).expect("ui utf8");
        assert!(ui_body.contains("Development only"));
        assert!(ui_body.contains("FiniteBrain Smoke UI"));
        assert!(ui_body.contains("Invitations and Share Links"));
        assert!(ui_body.contains("Connections and mounts"));

        let css_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/smoke/ui.css")
                    .body(Body::empty())
                    .expect("valid css request"),
            )
            .await
            .expect("css response");
        assert_eq!(css_response.status(), StatusCode::OK);
        let css_body = to_bytes(css_response.into_body(), 16 * 1024)
            .await
            .expect("css body");
        let css_body = std::str::from_utf8(&css_body).expect("css utf8");
        assert!(css_body.contains(".topbar"));

        let js_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/smoke/ui.js")
                    .body(Body::empty())
                    .expect("valid js request"),
            )
            .await
            .expect("js response");
        assert_eq!(js_response.status(), StatusCode::OK);
        let js_body = to_bytes(js_response.into_body(), 16 * 1024)
            .await
            .expect("js body");
        let js_body = std::str::from_utf8(&js_body).expect("js utf8");
        assert!(js_body.contains("bootstrapButton"));
        assert!(js_body.contains("createShareLinkButton"));
        assert!(js_body.contains("mountsButton"));

        let keys = Keys::generate();
        let create = post_vault(
            router,
            &keys,
            &create_vault_body("smoke", "organization"),
            TEST_NOW,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(create.status(), StatusCode::OK);

        let reopened = sqlite_test_router(&db_path);
        let metadata = get_metadata(reopened.clone(), &keys, "smoke", TEST_NOW).await;
        assert_eq!(metadata.status(), StatusCode::OK);
        let metadata: VaultMetadataResponse = read_json(metadata).await;
        assert_eq!(metadata.vault_id, "smoke");
        assert_eq!(metadata.folders.len(), 2);
        assert!(metadata.folders.iter().any(|folder| folder.id == "general"));

        let sync_bootstrap = authed_request(
            reopened,
            &keys,
            "GET",
            "/_admin/vaults/smoke/sync/bootstrap",
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(sync_bootstrap.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn valid_auth_creates_vault_and_metadata_contains_no_pages() {
        let keys = Keys::generate();
        let body = create_vault_body("acme", "organization");
        let router = test_router();
        let response = post_vault(router.clone(), &keys, &body, TEST_NOW, None, None, None).await;

        assert_eq!(response.status(), StatusCode::OK);
        let metadata: VaultMetadataResponse = read_json(response).await;
        assert_eq!(metadata.vault_id, "acme");
        assert_eq!(metadata.kind, VaultKind::Organization);
        assert_eq!(metadata.folders.len(), 2);
        assert_eq!(metadata.grant_count, 2);
        assert!(
            metadata
                .folders
                .iter()
                .all(|folder| !folder.setup_incomplete)
        );

        let response = get_metadata(router, &keys, "acme", TEST_NOW).await;
        assert_eq!(response.status(), StatusCode::OK);
        let metadata: VaultMetadataResponse = read_json(response).await;
        assert_eq!(metadata.vault_id, "acme");
        assert_eq!(metadata.members.len(), 1);
    }

    #[tokio::test]
    async fn protected_create_rejects_missing_auth() {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_admin/vaults")
                    .header("content-type", "application/json")
                    .body(Body::from(create_vault_body("acme", "organization")))
                    .expect("valid request"),
            )
            .await
            .expect("create response");

        assert_error(
            response,
            StatusCode::FORBIDDEN,
            "valid Nostr authorization is required",
        )
        .await;
    }

    #[tokio::test]
    async fn protected_create_accepts_compatible_nostr_auth_header_aliases() {
        for header_name in [NOSTR_AUTHORIZATION_HEADER, FINITEBRAIN_NOSTR_HEADER] {
            let keys = Keys::generate();
            let body = create_vault_body(header_name.replace('-', "_").as_str(), "organization");
            let response =
                post_vault_with_header(test_router(), &keys, &body, TEST_NOW, header_name).await;

            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn protected_create_rejects_oversized_request_body() {
        let body = "x".repeat(MAX_REQUEST_BODY_BYTES + 1);
        let response = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_admin/vaults")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .expect("valid request"),
            )
            .await
            .expect("oversized response");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn protected_create_rejects_stale_wrong_method_wrong_url_and_wrong_payload_auth() {
        let keys = Keys::generate();
        let body = create_vault_body("acme", "organization");

        let stale = post_vault(
            test_router(),
            &keys,
            &body,
            TEST_NOW - 1_000,
            None,
            None,
            None,
        )
        .await;
        assert_error(stale, StatusCode::FORBIDDEN, "stale Nostr event timestamp").await;

        let wrong_method = post_vault(
            test_router(),
            &keys,
            &body,
            TEST_NOW,
            Some("GET"),
            None,
            None,
        )
        .await;
        assert_error(
            wrong_method,
            StatusCode::FORBIDDEN,
            "Nostr auth method mismatch",
        )
        .await;

        let wrong_url = post_vault(
            test_router(),
            &keys,
            &body,
            TEST_NOW,
            None,
            Some("/_admin/vaults/acme/metadata"),
            None,
        )
        .await;
        assert_error(wrong_url, StatusCode::FORBIDDEN, "Nostr auth URL mismatch").await;

        let wrong_payload = post_vault(
            test_router(),
            &keys,
            &body,
            TEST_NOW,
            None,
            None,
            Some(br#"{"wrong":true}"#),
        )
        .await;
        assert_error(
            wrong_payload,
            StatusCode::FORBIDDEN,
            "Nostr auth payload mismatch",
        )
        .await;
    }

    #[tokio::test]
    async fn invalid_bootstrap_maps_to_bad_request_after_valid_auth() {
        let keys = Keys::generate();
        let body = create_vault_body("", "organization");
        let response = post_vault(test_router(), &keys, &body, TEST_NOW, None, None, None).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn metadata_requires_vault_membership() {
        let admin_keys = Keys::generate();
        let outsider_keys = Keys::generate();
        let router = test_router();
        let body = create_vault_body("acme", "organization");
        let create = post_vault(
            router.clone(),
            &admin_keys,
            &body,
            TEST_NOW,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(create.status(), StatusCode::OK);

        let response = get_metadata(router, &outsider_keys, "acme", TEST_NOW).await;
        assert_error(response, StatusCode::FORBIDDEN, "vault access required").await;
    }

    #[tokio::test]
    async fn secure_object_routes_create_update_delete_and_pull_sync() {
        let keys = Keys::generate();
        let router = test_router();
        let create_vault = post_vault(
            router.clone(),
            &keys,
            &create_vault_body("acme", "organization"),
            TEST_NOW,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(create_vault.status(), StatusCode::OK);

        let object_path = "/_admin/vaults/acme/folders/general/objects/obj_000000000001";
        let create_body = object_write_body(
            &keys,
            RevisionFixture {
                vault_id: "acme",
                folder_id: "general",
                object_id: "obj_000000000001",
                operation: FolderObjectOperation::Create,
                revision: 1,
                base_revision: None,
                key_version: 1,
                content: "created page",
                nonce: 1,
                record_type: false,
            },
        );
        let create = authed_request(
            router.clone(),
            &keys,
            "PUT",
            object_path,
            Some(create_body.clone()),
            TEST_NOW,
        )
        .await;
        assert_eq!(create.status(), StatusCode::OK);
        let create: ObjectWriteResponse = read_json(create).await;
        assert_eq!(create.sequence, 1);
        assert!(!create.duplicate);
        assert_eq!(create.revision, 1);

        let get = authed_request(router.clone(), &keys, "GET", object_path, None, TEST_NOW).await;
        assert_eq!(get.status(), StatusCode::OK);
        let current: ObjectResponse = read_json(get).await;
        assert_eq!(current.revision, 1);
        assert!(!current.deleted);
        assert!(current.ciphertext.contains("\"cipher\":\"AES-256-GCM\""));

        let update_body = object_write_body(
            &keys,
            RevisionFixture {
                vault_id: "acme",
                folder_id: "general",
                object_id: "obj_000000000001",
                operation: FolderObjectOperation::Update,
                revision: 2,
                base_revision: Some(1),
                key_version: 1,
                content: "updated page",
                nonce: 2,
                record_type: true,
            },
        );
        let update = authed_request(
            router.clone(),
            &keys,
            "POST",
            "/_admin/vaults/acme/sync/records",
            Some(update_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(update.status(), StatusCode::OK);
        let update: ObjectWriteResponse = read_json(update).await;
        assert_eq!(update.sequence, 2);
        assert_eq!(update.revision, 2);

        let bootstrap = authed_request(
            router.clone(),
            &keys,
            "GET",
            "/_admin/vaults/acme/sync/bootstrap",
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(bootstrap.status(), StatusCode::OK);
        let bootstrap: SyncBootstrapResponse = read_json(bootstrap).await;
        assert_eq!(bootstrap.latest_sequence, 2);
        assert_eq!(bootstrap.object_count, 1);
        assert_eq!(bootstrap.objects[0].revision, 2);

        let first_pull = authed_request(
            router.clone(),
            &keys,
            "GET",
            "/_admin/vaults/acme/sync/records?after=0&limit=1",
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(first_pull.status(), StatusCode::OK);
        let first_pull: SyncPullResponse = read_json(first_pull).await;
        assert_eq!(first_pull.count, 1);
        assert!(first_pull.has_more);
        assert_eq!(first_pull.next_sequence, 1);
        assert_eq!(first_pull.records[0].record_type, "folder_object_revision");

        let second_pull = authed_request(
            router.clone(),
            &keys,
            "GET",
            "/_admin/vaults/acme/sync/records?after=1&limit=10",
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(second_pull.status(), StatusCode::OK);
        let second_pull: SyncPullResponse = read_json(second_pull).await;
        assert_eq!(second_pull.count, 1);
        assert!(!second_pull.has_more);
        assert_eq!(second_pull.records[0].revision, Some(2));

        let move_body = object_write_body(
            &keys,
            RevisionFixture {
                vault_id: "acme",
                folder_id: "general",
                object_id: "obj_000000000001",
                operation: FolderObjectOperation::Move,
                revision: 3,
                base_revision: Some(2),
                key_version: 1,
                content: "moved page",
                nonce: 11,
                record_type: false,
            },
        );
        let move_object = authed_request(
            router.clone(),
            &keys,
            "POST",
            "/_admin/vaults/acme/folders/general/objects/obj_000000000001/move",
            Some(move_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(move_object.status(), StatusCode::OK);
        let move_object: ObjectWriteResponse = read_json(move_object).await;
        assert_eq!(move_object.sequence, 3);
        assert_eq!(move_object.revision, 3);

        let delete_body = object_delete_body(
            &keys,
            TombstoneFixture {
                vault_id: "acme",
                folder_id: "general",
                object_id: "obj_000000000001",
                revision: 4,
                base_revision: 3,
                record_type: false,
            },
        );
        let delete = authed_request(
            router.clone(),
            &keys,
            "DELETE",
            object_path,
            Some(delete_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(delete.status(), StatusCode::OK);
        let delete: ObjectWriteResponse = read_json(delete).await;
        assert_eq!(delete.sequence, 4);
        assert_eq!(delete.revision, 4);

        let get_deleted =
            authed_request(router.clone(), &keys, "GET", object_path, None, TEST_NOW).await;
        assert_error(get_deleted, StatusCode::NOT_FOUND, "object not found").await;

        let bootstrap = authed_request(
            router,
            &keys,
            "GET",
            "/_admin/vaults/acme/sync/bootstrap",
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(bootstrap.status(), StatusCode::OK);
        let bootstrap: SyncBootstrapResponse = read_json(bootstrap).await;
        assert_eq!(bootstrap.latest_sequence, 4);
        assert!(bootstrap.objects[0].deleted);
    }

    #[tokio::test]
    async fn encrypted_export_route_filters_opaque_objects_and_search_stays_client_side() {
        let admin_keys = Keys::generate();
        let member_keys = Keys::generate();
        let admin_npub = npub(&admin_keys);
        let member_npub = npub(&member_keys);
        let vault_id = VaultId::new("acme").unwrap();
        let mut store = BrainStore::open_in_memory().unwrap();
        let output = bootstrap_organization_vault("acme", "Acme", &admin_npub).unwrap();
        let grants = grants_for_required(&output.required_key_grants, &admin_npub);
        store.create_vault_bootstrap(&output, &grants).unwrap();
        store
            .add_member(&vault_id, &UserId::new(member_npub.clone()).unwrap())
            .unwrap();
        store
            .create_folder(
                &vault_id,
                &Folder {
                    id: FolderId::new("strategy").unwrap(),
                    name: DisplayName::new("folder_name", "Strategy").unwrap(),
                    role: FolderRole::Folder,
                    access: FolderAccessMode::Restricted,
                    parent_folder_id: Some(FolderId::new("general").unwrap()),
                    path: SafeRelativePath::new("folder_path", "general/Strategy").unwrap(),
                    current_key_version: 1,
                    shared_folder_source: false,
                },
                &BTreeSet::new(),
                &[FolderKeyGrantMetadata {
                    id: "grant-strategy-admin".to_owned(),
                    folder_id: FolderId::new("strategy").unwrap(),
                    key_version: 1,
                    issuer_npub: UserId::new(admin_npub.clone()).unwrap(),
                    recipient_npub: UserId::new(admin_npub.clone()).unwrap(),
                    format: "NIP-59".to_owned(),
                    wrapped_event_json: "{\"kind\":1059}".to_owned(),
                    access_change_event_json: Some("{\"kind\":30078}".to_owned()),
                    created_at: "2026-06-23T00:00:00.000Z".to_owned(),
                }],
            )
            .unwrap();
        for (folder_id, object_id, body) in [
            ("general", "obj_000000000201", "general encrypted payload"),
            ("strategy", "obj_000000000202", "secret encrypted payload"),
        ] {
            store
                .submit_sync_record(
                    &vault_id,
                    &SyncRecordInput::FolderObjectRevision(FolderObjectRevisionSyncRecord {
                        record_event_id: format!("event-{folder_id}"),
                        folder_id: FolderId::new(folder_id).unwrap(),
                        object_id: ObjectId::new(object_id).unwrap(),
                        revision: 1,
                        base_revision: None,
                        actor_npub: UserId::new(admin_npub.clone()).unwrap(),
                        client_created_at: "2026-06-23T00:00:00.000Z".to_owned(),
                        payload_json: format!("{{\"body\":\"{body}\"}}"),
                        record_event_kind: APP_SPECIFIC_KIND,
                    }),
                )
                .unwrap();
        }

        let router =
            router_with_state(ServerState::new(store, TEST_BASE_URL).with_auth_clock(TEST_NOW, 60));
        let export = authed_request(
            router.clone(),
            &member_keys,
            "GET",
            "/_admin/vaults/acme/export",
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(export.status(), StatusCode::OK);
        let export: EncryptedVaultExportResponse = read_json(export).await;
        assert_eq!(export.version, "finite-vault-export-v1");
        let general = export
            .objects
            .iter()
            .find(|object| object.folder_id == "general")
            .unwrap();
        assert!(!general.opaque);
        assert!(general.payload_json.as_ref().unwrap().contains("general"));
        let strategy = export
            .objects
            .iter()
            .find(|object| object.folder_id == "strategy")
            .unwrap();
        assert!(strategy.opaque);
        assert!(strategy.payload_json.is_none());

        let search = authed_request(
            router,
            &member_keys,
            "GET",
            "/_admin/vaults/acme/search?q=secret",
            None,
            TEST_NOW,
        )
        .await;
        assert_error(
            search,
            StatusCode::BAD_REQUEST,
            "plaintext search is client-side only",
        )
        .await;
    }

    #[tokio::test]
    async fn object_write_duplicate_retry_returns_original_sequence() {
        let keys = Keys::generate();
        let router = router_with_bootstrapped_org(&keys).await;
        let path = "/_admin/vaults/acme/folders/general/objects/obj_000000000001";
        let body = object_write_body(
            &keys,
            RevisionFixture {
                vault_id: "acme",
                folder_id: "general",
                object_id: "obj_000000000001",
                operation: FolderObjectOperation::Create,
                revision: 1,
                base_revision: None,
                key_version: 1,
                content: "created page",
                nonce: 3,
                record_type: false,
            },
        );

        let first = authed_request(
            router.clone(),
            &keys,
            "PUT",
            path,
            Some(body.clone()),
            TEST_NOW,
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);
        let first: ObjectWriteResponse = read_json(first).await;
        assert_eq!(first.sequence, 1);
        assert!(!first.duplicate);

        let retry = authed_request(router, &keys, "PUT", path, Some(body), TEST_NOW).await;
        assert_eq!(retry.status(), StatusCode::OK);
        let retry: ObjectWriteResponse = read_json(retry).await;
        assert_eq!(retry.sequence, 1);
        assert!(retry.duplicate);
    }

    #[tokio::test]
    async fn object_write_rejects_stale_base_bad_ciphertext_hash_and_signer_mismatch() {
        let keys = Keys::generate();
        let router = router_with_bootstrapped_org(&keys).await;
        let path = "/_admin/vaults/acme/folders/general/objects/obj_000000000001";
        let create_body = object_write_body(
            &keys,
            RevisionFixture {
                vault_id: "acme",
                folder_id: "general",
                object_id: "obj_000000000001",
                operation: FolderObjectOperation::Create,
                revision: 1,
                base_revision: None,
                key_version: 1,
                content: "created page",
                nonce: 4,
                record_type: false,
            },
        );
        let create = authed_request(
            router.clone(),
            &keys,
            "PUT",
            path,
            Some(create_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(create.status(), StatusCode::OK);

        let update_body = object_write_body(
            &keys,
            RevisionFixture {
                vault_id: "acme",
                folder_id: "general",
                object_id: "obj_000000000001",
                operation: FolderObjectOperation::Update,
                revision: 2,
                base_revision: Some(1),
                key_version: 1,
                content: "updated page",
                nonce: 5,
                record_type: false,
            },
        );
        let update = authed_request(
            router.clone(),
            &keys,
            "PUT",
            path,
            Some(update_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(update.status(), StatusCode::OK);

        let stale_body = object_write_body(
            &keys,
            RevisionFixture {
                vault_id: "acme",
                folder_id: "general",
                object_id: "obj_000000000001",
                operation: FolderObjectOperation::Update,
                revision: 2,
                base_revision: Some(1),
                key_version: 1,
                content: "stale update",
                nonce: 6,
                record_type: false,
            },
        );
        let stale = authed_request(
            router.clone(),
            &keys,
            "PUT",
            path,
            Some(stale_body),
            TEST_NOW,
        )
        .await;
        assert_error(stale, StatusCode::CONFLICT, "baseRevision does not match").await;

        let good_envelope =
            object_envelope_json("acme", "general", "obj_000000000002", 1, "good content", 7);
        let bad_envelope =
            object_envelope_json("acme", "general", "obj_000000000002", 1, "bad content", 8);
        let event = revision_event_for_author(
            &keys,
            npub(&keys),
            RevisionEventFixture {
                vault_id: "acme",
                folder_id: "general",
                object_id: "obj_000000000002",
                operation: FolderObjectOperation::Create,
                revision: 1,
                base_revision: None,
                key_version: 1,
                envelope_json: good_envelope,
            },
        );
        let bad_hash_body = serde_json::json!({
            "baseRevision": null,
            "keyVersion": 1,
            "cipher": "AES-256-GCM",
            "ciphertext": bad_envelope,
            "revisionEvent": event,
        })
        .to_string();
        let bad_hash = authed_request(
            router.clone(),
            &keys,
            "PUT",
            "/_admin/vaults/acme/folders/general/objects/obj_000000000002",
            Some(bad_hash_body),
            TEST_NOW,
        )
        .await;
        assert_error(
            bad_hash,
            StatusCode::BAD_REQUEST,
            "ciphertext hash mismatch",
        )
        .await;

        let signer_keys = Keys::generate();
        let envelope = object_envelope_json(
            "acme",
            "general",
            "obj_000000000003",
            1,
            "signer mismatch",
            9,
        );
        let event = revision_event_for_author(
            &signer_keys,
            npub(&keys),
            RevisionEventFixture {
                vault_id: "acme",
                folder_id: "general",
                object_id: "obj_000000000003",
                operation: FolderObjectOperation::Create,
                revision: 1,
                base_revision: None,
                key_version: 1,
                envelope_json: envelope.clone(),
            },
        );
        let signer_mismatch_body = serde_json::json!({
            "baseRevision": null,
            "keyVersion": 1,
            "cipher": "AES-256-GCM",
            "ciphertext": envelope,
            "revisionEvent": event,
        })
        .to_string();
        let signer_mismatch = authed_request(
            router,
            &keys,
            "PUT",
            "/_admin/vaults/acme/folders/general/objects/obj_000000000003",
            Some(signer_mismatch_body),
            TEST_NOW,
        )
        .await;
        assert_error(signer_mismatch, StatusCode::BAD_REQUEST, "signer mismatch").await;
    }

    #[tokio::test]
    async fn sync_pull_expired_cursor_requires_rebootstrap() {
        let keys = Keys::generate();
        let state = test_state();
        let router = router_with_state(state.clone());
        let create_vault = post_vault(
            router.clone(),
            &keys,
            &create_vault_body("acme", "organization"),
            TEST_NOW,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(create_vault.status(), StatusCode::OK);
        let path = "/_admin/vaults/acme/folders/general/objects/obj_000000000001";
        let body = object_write_body(
            &keys,
            RevisionFixture {
                vault_id: "acme",
                folder_id: "general",
                object_id: "obj_000000000001",
                operation: FolderObjectOperation::Create,
                revision: 1,
                base_revision: None,
                key_version: 1,
                content: "created page",
                nonce: 10,
                record_type: false,
            },
        );
        let create = authed_request(router.clone(), &keys, "PUT", path, Some(body), TEST_NOW).await;
        assert_eq!(create.status(), StatusCode::OK);

        {
            let mut store = state.store.lock().unwrap();
            store
                .set_retention_floor(&VaultId::new("acme").unwrap(), 1)
                .unwrap();
        }

        let expired = authed_request(
            router,
            &keys,
            "GET",
            "/_admin/vaults/acme/sync/records?after=0&limit=10",
            None,
            TEST_NOW,
        )
        .await;
        assert_error(expired, StatusCode::GONE, "rebootstrap required").await;
    }

    #[tokio::test]
    async fn admin_routes_create_restricted_folder_and_rotate_access_removal() {
        let admin_keys = Keys::generate();
        let member_keys = Keys::generate();
        let member_npub = npub(&member_keys);
        let router = router_with_bootstrapped_org(&admin_keys).await;

        let add_member_body = serde_json::json!({
            "targetNpub": member_npub,
            "accessChangeEvent": admin_event(
                &admin_keys,
                "acme",
                "change_add_member",
                AdminAccessAction::AddMember,
                None,
                Some(member_npub.as_str()),
                None,
            ),
        })
        .to_string();
        let add_member = authed_request(
            router.clone(),
            &admin_keys,
            "POST",
            "/_admin/vaults/acme/members",
            Some(add_member_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(add_member.status(), StatusCode::OK);
        let metadata: VaultMetadataResponse = read_json(add_member).await;
        assert!(metadata.members.contains(&member_npub));

        let create_folder_body = serde_json::json!({
            "folderId": "strategy",
            "name": "Strategy",
            "role": "folder",
            "access": "restricted",
            "parentFolderId": "general",
            "path": "general/Strategy",
            "accessUserIds": [member_npub],
            "grants": [
                folder_key_grant_value("grant-strategy-admin-v1", 1, npub(&admin_keys).as_str()),
                folder_key_grant_value("grant-strategy-member-v1", 1, member_npub.as_str())
            ],
            "accessChangeEvent": admin_event(
                &admin_keys,
                "acme",
                "change_create_strategy",
                AdminAccessAction::SetFolderAccessMode,
                Some("strategy"),
                None,
                Some(1),
            ),
        })
        .to_string();
        let create_folder = authed_request(
            router.clone(),
            &admin_keys,
            "POST",
            "/_admin/vaults/acme/folders",
            Some(create_folder_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(create_folder.status(), StatusCode::OK);
        let metadata: VaultMetadataResponse = read_json(create_folder).await;
        let strategy = metadata
            .folders
            .iter()
            .find(|folder| folder.id == "strategy")
            .expect("strategy folder metadata");
        assert_eq!(strategy.current_key_version, 1);
        assert_eq!(strategy.access_user_ids, vec![member_npub.clone()]);

        let object_path = "/_admin/vaults/acme/folders/strategy/objects/obj_000000000001";
        let create_object_body = object_write_body(
            &admin_keys,
            RevisionFixture {
                vault_id: "acme",
                folder_id: "strategy",
                object_id: "obj_000000000001",
                operation: FolderObjectOperation::Create,
                revision: 1,
                base_revision: None,
                key_version: 1,
                content: "restricted page",
                nonce: 12,
                record_type: false,
            },
        );
        let create_object = authed_request(
            router.clone(),
            &admin_keys,
            "PUT",
            object_path,
            Some(create_object_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(create_object.status(), StatusCode::OK);

        let remove_access_body = serde_json::json!({
            "newKeyVersion": 2,
            "grants": [
                folder_key_grant_value("grant-strategy-admin-v2", 2, npub(&admin_keys).as_str())
            ],
            "reencryptedRecords": [
                rotation_object_value(
                    &admin_keys,
                    "acme",
                    "strategy",
                    "obj_000000000001",
                    2,
                    Some(1),
                    2,
                    "reencrypted restricted page",
                    13,
                )
            ],
            "accessChangeEvent": admin_event(
                &admin_keys,
                "acme",
                "change_remove_strategy_access",
                AdminAccessAction::RemoveFolderAccess,
                Some("strategy"),
                Some(member_npub.as_str()),
                Some(2),
            ),
        })
        .to_string();
        let remove_access = authed_request(
            router.clone(),
            &admin_keys,
            "DELETE",
            &format!("/_admin/vaults/acme/folders/strategy/access/{member_npub}"),
            Some(remove_access_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(remove_access.status(), StatusCode::OK);
        let metadata: VaultMetadataResponse = read_json(remove_access).await;
        let strategy = metadata
            .folders
            .iter()
            .find(|folder| folder.id == "strategy")
            .expect("strategy folder metadata");
        assert_eq!(strategy.current_key_version, 2);
        assert!(strategy.access_user_ids.is_empty());

        let bootstrap = authed_request(
            router,
            &admin_keys,
            "GET",
            "/_admin/vaults/acme/sync/bootstrap",
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(bootstrap.status(), StatusCode::OK);
        let bootstrap: SyncBootstrapResponse = read_json(bootstrap).await;
        let object = bootstrap
            .objects
            .iter()
            .find(|object| object.object_id == "obj_000000000001")
            .expect("current object");
        assert_eq!(object.revision, 2);
    }

    #[tokio::test]
    async fn finish_setup_route_repairs_empty_setup_incomplete_folder() {
        let admin_keys = Keys::generate();
        let state = test_state();
        let router = router_with_state(state.clone());
        let create_vault = post_vault(
            router.clone(),
            &admin_keys,
            &create_vault_body("acme", "organization"),
            TEST_NOW,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(create_vault.status(), StatusCode::OK);

        {
            let mut store = state.store.lock().unwrap();
            store
                .insert_setup_incomplete_folder_for_repair(
                    &VaultId::new("acme").unwrap(),
                    &test_strategy_folder(),
                    &BTreeSet::new(),
                )
                .unwrap();
        }

        let body = serde_json::json!({
            "grants": [
                folder_key_grant_value("grant-strategy-admin-v1", 1, npub(&admin_keys).as_str())
            ],
            "accessChangeEvent": admin_event(
                &admin_keys,
                "acme",
                "change_finish_strategy",
                AdminAccessAction::SetFolderAccessMode,
                Some("strategy"),
                None,
                Some(1),
            ),
        })
        .to_string();
        let finish = authed_request(
            router,
            &admin_keys,
            "POST",
            "/_admin/vaults/acme/folders/strategy/finish-setup",
            Some(body),
            TEST_NOW,
        )
        .await;
        assert_eq!(finish.status(), StatusCode::OK);
        let metadata: VaultMetadataResponse = read_json(finish).await;
        let strategy = metadata
            .folders
            .iter()
            .find(|folder| folder.id == "strategy")
            .expect("strategy folder metadata");
        assert!(!strategy.setup_incomplete);
    }

    #[tokio::test]
    async fn vault_invitation_routes_are_npub_bound_single_use_and_retry_safe() {
        let admin_keys = Keys::generate();
        let target_keys = Keys::generate();
        let wrong_keys = Keys::generate();
        let target_npub = npub(&target_keys);
        let router = router_with_bootstrapped_org(&admin_keys).await;

        let create_body = serde_json::json!({
            "targetNpub": target_npub,
            "initialFolderAccess": ["general"],
            "expiresAt": "2026-06-30T00:00:00.000Z",
        })
        .to_string();
        let create = authed_request(
            router.clone(),
            &admin_keys,
            "POST",
            "/_admin/vaults/acme/invitations",
            Some(create_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(create.status(), StatusCode::OK);
        let invitation: VaultInvitationResponse = read_json(create).await;
        assert_eq!(invitation.status, "pending");
        assert_eq!(invitation.user_id, target_npub);
        assert_eq!(invitation.initial_folder_access, vec!["general".to_owned()]);

        let link_path = format!("/_admin/vault-invitation-links/{}", invitation.invite_code);
        let wrong_view = authed_request(
            router.clone(),
            &wrong_keys,
            "GET",
            &link_path,
            None,
            TEST_NOW,
        )
        .await;
        assert_error(
            wrong_view,
            StatusCode::NOT_FOUND,
            "vault invitation unavailable",
        )
        .await;

        let view = authed_request(
            router.clone(),
            &target_keys,
            "GET",
            &link_path,
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(view.status(), StatusCode::OK);
        let viewed: VaultInvitationResponse = read_json(view).await;
        assert_eq!(viewed.id, invitation.id);

        let accept_path = format!("{link_path}/accept");
        let accept = authed_request(
            router.clone(),
            &target_keys,
            "POST",
            &accept_path,
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(accept.status(), StatusCode::OK);
        let accepted: VaultInvitationResponse = read_json(accept).await;
        assert_eq!(accepted.status, "accepted");
        assert!(!accepted.duplicate_accept);

        let retry = authed_request(
            router.clone(),
            &target_keys,
            "POST",
            &accept_path,
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(retry.status(), StatusCode::OK);
        let retry: VaultInvitationResponse = read_json(retry).await;
        assert!(retry.duplicate_accept);

        let id_accept_path = format!("/_admin/vaults/acme/invitations/{}/accept", invitation.id);
        let id_retry = authed_request(
            router.clone(),
            &target_keys,
            "POST",
            &id_accept_path,
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(id_retry.status(), StatusCode::OK);
        let id_retry: VaultInvitationResponse = read_json(id_retry).await;
        assert!(id_retry.duplicate_accept);

        let metadata = get_metadata(router.clone(), &target_keys, "acme", TEST_NOW).await;
        assert_eq!(metadata.status(), StatusCode::OK);
        let metadata: VaultMetadataResponse = read_json(metadata).await;
        assert!(metadata.members.contains(&target_npub));

        let revoke_path = format!("/_admin/vaults/acme/invitations/{}", invitation.id);
        let revoke =
            authed_request(router, &admin_keys, "DELETE", &revoke_path, None, TEST_NOW).await;
        assert_eq!(revoke.status(), StatusCode::OK);
        let revoked: VaultInvitationResponse = read_json(revoke).await;
        assert_eq!(revoked.status, "revoked");
    }

    #[tokio::test]
    async fn share_link_routes_create_access_and_optional_mount_on_accept() {
        let admin_keys = Keys::generate();
        let recipient_keys = Keys::generate();
        let wrong_keys = Keys::generate();
        let recipient_npub = npub(&recipient_keys);
        let router = router_with_bootstrapped_org(&admin_keys).await;

        let create_folder_body = serde_json::json!({
            "folderId": "strategy",
            "name": "Strategy",
            "role": "folder",
            "access": "restricted",
            "parentFolderId": "general",
            "path": "general/Strategy",
            "accessUserIds": [],
            "grants": [
                folder_key_grant_value("grant-strategy-admin-v1", 1, npub(&admin_keys).as_str())
            ],
            "accessChangeEvent": admin_event(
                &admin_keys,
                "acme",
                "change_create_strategy_share",
                AdminAccessAction::SetFolderAccessMode,
                Some("strategy"),
                None,
                Some(1),
            ),
        })
        .to_string();
        let create_folder = authed_request(
            router.clone(),
            &admin_keys,
            "POST",
            "/_admin/vaults/acme/folders",
            Some(create_folder_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(create_folder.status(), StatusCode::OK);

        let create_share_body = serde_json::json!({
            "recipientNpub": recipient_npub,
            "grant": folder_key_grant_value("grant-strategy-recipient-v1", 1, recipient_npub.as_str()),
            "accessChangeEvent": admin_event(
                &admin_keys,
                "acme",
                "change_share_strategy",
                AdminAccessAction::GrantFolderAccess,
                Some("strategy"),
                Some(recipient_npub.as_str()),
                Some(1),
            ),
            "expiresAt": "2026-06-30T00:00:00.000Z",
            "createPersonalMount": true,
        })
        .to_string();
        let create_share = authed_request(
            router.clone(),
            &admin_keys,
            "POST",
            "/_admin/vaults/acme/folders/strategy/share-links",
            Some(create_share_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(create_share.status(), StatusCode::OK);
        let share_link: ShareLinkResponse = read_json(create_share).await;
        assert_eq!(share_link.status, "pending");
        assert_eq!(share_link.recipient_npub, recipient_npub);

        let share_path = format!("/_admin/share-links/{}", share_link.id);
        let wrong_view = authed_request(
            router.clone(),
            &wrong_keys,
            "GET",
            &share_path,
            None,
            TEST_NOW,
        )
        .await;
        assert_error(wrong_view, StatusCode::NOT_FOUND, "share link unavailable").await;

        let view = authed_request(
            router.clone(),
            &recipient_keys,
            "GET",
            &share_path,
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(view.status(), StatusCode::OK);

        let accept_path = format!("{share_path}/accept");
        let accept = authed_request(
            router.clone(),
            &recipient_keys,
            "POST",
            &accept_path,
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(accept.status(), StatusCode::OK);
        let accepted: ShareLinkResponse = read_json(accept).await;
        assert_eq!(accepted.status, "accepted");
        assert!(accepted.personal_mount_id.is_some());
        assert!(!accepted.duplicate_accept);

        let retry = authed_request(
            router.clone(),
            &recipient_keys,
            "POST",
            &accept_path,
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(retry.status(), StatusCode::OK);
        let retry: ShareLinkResponse = read_json(retry).await;
        assert!(retry.duplicate_accept);

        let metadata = get_metadata(router.clone(), &recipient_keys, "acme", TEST_NOW).await;
        assert_eq!(metadata.status(), StatusCode::OK);
        let metadata: VaultMetadataResponse = read_json(metadata).await;
        assert!(metadata.members.contains(&recipient_npub));
        let strategy = metadata
            .folders
            .iter()
            .find(|folder| folder.id == "strategy")
            .expect("strategy folder metadata");
        assert_eq!(strategy.access_user_ids, vec![recipient_npub]);
        assert_eq!(metadata.grant_count, 4);

        let revoke =
            authed_request(router, &admin_keys, "DELETE", &share_path, None, TEST_NOW).await;
        assert_eq!(revoke.status(), StatusCode::OK);
        let revoked: ShareLinkResponse = read_json(revoke).await;
        assert_eq!(revoked.status, "revoked");
    }

    #[tokio::test]
    async fn shared_folder_routes_project_mounts_and_route_writes_to_source() {
        let source_admin_keys = Keys::generate();
        let destination_admin_keys = Keys::generate();
        let destination_member_keys = Keys::generate();
        let source_admin_npub = npub(&source_admin_keys);
        let destination_admin_npub = npub(&destination_admin_keys);
        let destination_member_npub = npub(&destination_member_keys);
        let router = test_router();

        let create_source = post_vault(
            router.clone(),
            &source_admin_keys,
            &create_vault_body("acme", "organization"),
            TEST_NOW,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(create_source.status(), StatusCode::OK);
        let create_destination = post_vault(
            router.clone(),
            &destination_admin_keys,
            &create_vault_body("dest", "organization"),
            TEST_NOW,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(create_destination.status(), StatusCode::OK);

        let create_folder_body = serde_json::json!({
            "folderId": "strategy",
            "name": "Strategy",
            "role": "folder",
            "access": "restricted",
            "parentFolderId": "general",
            "path": "general/Strategy",
            "accessUserIds": [],
            "grants": [
                folder_key_grant_value("grant-strategy-source-admin-v1", 1, source_admin_npub.as_str())
            ],
            "accessChangeEvent": admin_event(
                &source_admin_keys,
                "acme",
                "change_create_shared_strategy",
                AdminAccessAction::SetFolderAccessMode,
                Some("strategy"),
                None,
                Some(1),
            ),
        })
        .to_string();
        let create_folder = authed_request(
            router.clone(),
            &source_admin_keys,
            "POST",
            "/_admin/vaults/acme/folders",
            Some(create_folder_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(create_folder.status(), StatusCode::OK);

        let mark_source_body = serde_json::json!({
            "accessChangeEvent": admin_event(
                &source_admin_keys,
                "acme",
                "change_mark_shared_strategy",
                AdminAccessAction::SetFolderAccessMode,
                Some("strategy"),
                None,
                Some(1),
            ),
        })
        .to_string();
        let mark_source = authed_request(
            router.clone(),
            &source_admin_keys,
            "POST",
            "/_admin/vaults/acme/folders/strategy/share-source",
            Some(mark_source_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(mark_source.status(), StatusCode::OK);
        let source_metadata: VaultMetadataResponse = read_json(mark_source).await;
        assert!(
            source_metadata
                .folders
                .iter()
                .find(|folder| folder.id == "strategy")
                .unwrap()
                .shared_folder_source
        );

        let create_invitation_body = serde_json::json!({
            "destinationVaultId": "dest",
            "destinationAdminNpub": destination_admin_npub,
            "grant": folder_key_grant_value("grant-strategy-dest-admin-v1", 1, destination_admin_npub.as_str()),
            "accessChangeEvent": admin_event(
                &source_admin_keys,
                "acme",
                "change_invite_dest_strategy",
                AdminAccessAction::GrantFolderAccess,
                Some("strategy"),
                Some(destination_admin_npub.as_str()),
                Some(1),
            ),
        })
        .to_string();
        let create_invitation = authed_request(
            router.clone(),
            &source_admin_keys,
            "POST",
            "/_admin/vaults/acme/folders/strategy/shared-folder-invitations",
            Some(create_invitation_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(create_invitation.status(), StatusCode::OK);
        let invitation: SharedFolderInvitationResponse = read_json(create_invitation).await;
        assert_eq!(invitation.status, "pending");

        let wrong_view = authed_request(
            router.clone(),
            &source_admin_keys,
            "GET",
            &format!("/_admin/shared-folder-invitations/{}", invitation.id),
            None,
            TEST_NOW,
        )
        .await;
        assert_error(
            wrong_view,
            StatusCode::NOT_FOUND,
            "shared folder invitation unavailable",
        )
        .await;

        let accept = authed_request(
            router.clone(),
            &destination_admin_keys,
            "POST",
            &format!("/_admin/shared-folder-invitations/{}/accept", invitation.id),
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(accept.status(), StatusCode::OK);
        let accepted: SharedFolderInvitationResponse = read_json(accept).await;
        assert_eq!(accepted.status, "accepted");
        assert!(!accepted.duplicate_accept);

        let accept_retry = authed_request(
            router.clone(),
            &destination_admin_keys,
            "POST",
            &format!("/_admin/shared-folder-invitations/{}/accept", invitation.id),
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(accept_retry.status(), StatusCode::OK);
        let accept_retry: SharedFolderInvitationResponse = read_json(accept_retry).await;
        assert_eq!(accept_retry.status, "accepted");
        assert!(accept_retry.duplicate_accept);

        let destination_metadata =
            get_metadata(router.clone(), &destination_admin_keys, "dest", TEST_NOW).await;
        assert_eq!(destination_metadata.status(), StatusCode::OK);
        let destination_metadata: VaultMetadataResponse = read_json(destination_metadata).await;
        assert_eq!(destination_metadata.mounted_folders.len(), 1);
        let mount = &destination_metadata.mounted_folders[0];
        assert_eq!(mount.state, "available");
        assert_eq!(mount.source_vault_id, "acme");
        assert_eq!(mount.source_folder_id, "strategy");
        let connection_id = mount.connection_id.clone();

        let add_destination_member_body = serde_json::json!({
            "targetNpub": destination_member_npub,
            "accessChangeEvent": admin_event(
                &destination_admin_keys,
                "dest",
                "change_add_dest_member",
                AdminAccessAction::AddMember,
                None,
                Some(destination_member_npub.as_str()),
                None,
            ),
        })
        .to_string();
        let add_destination_member = authed_request(
            router.clone(),
            &destination_admin_keys,
            "POST",
            "/_admin/vaults/dest/members",
            Some(add_destination_member_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(add_destination_member.status(), StatusCode::OK);

        let add_connection_member_body = serde_json::json!({
            "action": "add",
            "targetNpub": destination_member_npub,
            "grant": folder_key_grant_value("grant-strategy-dest-member-v1", 1, destination_member_npub.as_str()),
            "newKeyVersion": null,
            "grants": [],
            "reencryptedRecords": [],
        })
        .to_string();
        let add_connection_member = authed_request(
            router.clone(),
            &destination_admin_keys,
            "PATCH",
            &format!("/_admin/shared-folder-connections/{connection_id}/members"),
            Some(add_connection_member_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(add_connection_member.status(), StatusCode::OK);
        let connection: SharedFolderConnectionResponse = read_json(add_connection_member).await;
        assert!(connection.member_npubs.contains(&destination_member_npub));

        let destination_member_metadata =
            get_metadata(router.clone(), &destination_member_keys, "dest", TEST_NOW).await;
        assert_eq!(destination_member_metadata.status(), StatusCode::OK);
        let destination_member_metadata: VaultMetadataResponse =
            read_json(destination_member_metadata).await;
        assert_eq!(
            destination_member_metadata.mounted_folders[0].state,
            "available"
        );

        let object_path = "/_admin/vaults/acme/folders/strategy/objects/obj_000000000101";
        let create_source_object_body = object_write_body(
            &destination_member_keys,
            RevisionFixture {
                vault_id: "acme",
                folder_id: "strategy",
                object_id: "obj_000000000101",
                operation: FolderObjectOperation::Create,
                revision: 1,
                base_revision: None,
                key_version: 1,
                content: "mounted write goes to source",
                nonce: 21,
                record_type: false,
            },
        );
        let create_source_object = authed_request(
            router.clone(),
            &destination_member_keys,
            "PUT",
            object_path,
            Some(create_source_object_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(create_source_object.status(), StatusCode::OK);

        let source_bootstrap = authed_request(
            router.clone(),
            &destination_member_keys,
            "GET",
            "/_admin/vaults/acme/sync/bootstrap",
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(source_bootstrap.status(), StatusCode::OK);
        let source_bootstrap: SyncBootstrapResponse = read_json(source_bootstrap).await;
        assert_eq!(source_bootstrap.object_count, 1);

        let destination_bootstrap = authed_request(
            router.clone(),
            &destination_member_keys,
            "GET",
            "/_admin/vaults/dest/sync/bootstrap",
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(destination_bootstrap.status(), StatusCode::OK);
        let destination_bootstrap: SyncBootstrapResponse = read_json(destination_bootstrap).await;
        assert_eq!(destination_bootstrap.object_count, 0);

        let remove_connection_member_body = serde_json::json!({
            "action": "remove",
            "targetNpub": destination_member_npub,
            "grant": null,
            "newKeyVersion": 2,
            "grants": [
                folder_key_grant_value("grant-strategy-source-admin-v2", 2, source_admin_npub.as_str()),
                folder_key_grant_value("grant-strategy-dest-admin-v2", 2, destination_admin_npub.as_str())
            ],
            "reencryptedRecords": [
                rotation_object_value(
                    &destination_admin_keys,
                    "acme",
                    "strategy",
                    "obj_000000000101",
                    2,
                    Some(1),
                    2,
                    "reencrypted after dest member removal",
                    22,
                )
            ],
        })
        .to_string();
        let remove_connection_member = authed_request(
            router.clone(),
            &destination_admin_keys,
            "PATCH",
            &format!("/_admin/shared-folder-connections/{connection_id}/members"),
            Some(remove_connection_member_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(remove_connection_member.status(), StatusCode::OK);

        let locked_metadata =
            get_metadata(router.clone(), &destination_member_keys, "dest", TEST_NOW).await;
        assert_eq!(locked_metadata.status(), StatusCode::OK);
        let locked_metadata: VaultMetadataResponse = read_json(locked_metadata).await;
        assert_eq!(locked_metadata.mounted_folders[0].state, "locked");

        let revoke_connection_body = serde_json::json!({
            "newKeyVersion": 3,
            "grants": [
                folder_key_grant_value("grant-strategy-source-admin-v3", 3, source_admin_npub.as_str())
            ],
            "reencryptedRecords": [
                rotation_object_value(
                    &source_admin_keys,
                    "acme",
                    "strategy",
                    "obj_000000000101",
                    3,
                    Some(2),
                    3,
                    "reencrypted after source revocation",
                    23,
                )
            ],
        })
        .to_string();
        let revoke_connection = authed_request(
            router.clone(),
            &source_admin_keys,
            "DELETE",
            &format!("/_admin/shared-folder-connections/{connection_id}"),
            Some(revoke_connection_body),
            TEST_NOW,
        )
        .await;
        assert_eq!(revoke_connection.status(), StatusCode::OK);
        let revoked: SharedFolderConnectionResponse = read_json(revoke_connection).await;
        assert_eq!(revoked.status, "revoked");

        let revoked_mounts = authed_request(
            router,
            &destination_admin_keys,
            "GET",
            "/_admin/vaults/dest/organization-folder-mounts",
            None,
            TEST_NOW,
        )
        .await;
        assert_eq!(revoked_mounts.status(), StatusCode::OK);
        let revoked_mounts: Vec<MountedFolderResponse> = read_json(revoked_mounts).await;
        assert_eq!(revoked_mounts[0].state, "revoked");
    }

    fn test_router() -> Router {
        router_with_state(test_state())
    }

    fn test_state() -> ServerState {
        let store = BrainStore::open_in_memory().unwrap();
        ServerState::new(store, TEST_BASE_URL).with_auth_clock(TEST_NOW, 60)
    }

    fn sqlite_test_router(path: &std::path::Path) -> Router {
        let store = BrainStore::open(path).unwrap();
        router_with_state(ServerState::new(store, TEST_BASE_URL).with_auth_clock(TEST_NOW, 60))
    }

    async fn router_with_bootstrapped_org(keys: &Keys) -> Router {
        let router = test_router();
        let create_vault = post_vault(
            router.clone(),
            keys,
            &create_vault_body("acme", "organization"),
            TEST_NOW,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(create_vault.status(), StatusCode::OK);
        router
    }

    fn create_vault_body(vault_id: &str, kind: &str) -> String {
        serde_json::json!({
            "vaultId": vault_id,
            "kind": kind,
            "name": "Acme"
        })
        .to_string()
    }

    async fn post_vault(
        router: Router,
        keys: &Keys,
        body: &str,
        created_at: u64,
        auth_method: Option<&str>,
        auth_path: Option<&str>,
        auth_body: Option<&[u8]>,
    ) -> axum::response::Response {
        let auth_method = auth_method.unwrap_or("POST");
        let auth_path = auth_path.unwrap_or("/_admin/vaults");
        let auth_body = auth_body.unwrap_or(body.as_bytes());
        let auth = auth_header(keys, auth_method, auth_path, Some(auth_body), created_at);

        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_admin/vaults")
                    .header(AUTHORIZATION, auth)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_owned()))
                    .expect("valid create request"),
            )
            .await
            .expect("create response")
    }

    async fn post_vault_with_header(
        router: Router,
        keys: &Keys,
        body: &str,
        created_at: u64,
        header_name: &'static str,
    ) -> axum::response::Response {
        let auth = auth_header(
            keys,
            "POST",
            "/_admin/vaults",
            Some(body.as_bytes()),
            created_at,
        );

        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_admin/vaults")
                    .header(header_name, auth)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_owned()))
                    .expect("valid create request"),
            )
            .await
            .expect("create response")
    }

    async fn get_metadata(
        router: Router,
        keys: &Keys,
        vault_id: &str,
        created_at: u64,
    ) -> axum::response::Response {
        let path = format!("/_admin/vaults/{vault_id}/metadata");
        let auth = auth_header(keys, "GET", &path, None, created_at);
        router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&path)
                    .header(AUTHORIZATION, auth)
                    .body(Body::empty())
                    .expect("valid metadata request"),
            )
            .await
            .expect("metadata response")
    }

    async fn authed_request(
        router: Router,
        keys: &Keys,
        method: &str,
        path: &str,
        body: Option<String>,
        created_at: u64,
    ) -> axum::response::Response {
        let auth = auth_header(
            keys,
            method,
            path,
            body.as_deref().map(str::as_bytes),
            created_at,
        );
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(AUTHORIZATION, auth);
        if body.is_some() {
            request = request.header("content-type", "application/json");
        }

        router
            .oneshot(
                request
                    .body(body.map_or_else(Body::empty, Body::from))
                    .expect("valid authed request"),
            )
            .await
            .expect("authed response")
    }

    #[derive(Debug, Clone)]
    struct RevisionFixture<'a> {
        vault_id: &'a str,
        folder_id: &'a str,
        object_id: &'a str,
        operation: FolderObjectOperation,
        revision: u64,
        base_revision: Option<u64>,
        key_version: u32,
        content: &'a str,
        nonce: u8,
        record_type: bool,
    }

    #[derive(Debug, Clone)]
    struct RevisionEventFixture<'a> {
        vault_id: &'a str,
        folder_id: &'a str,
        object_id: &'a str,
        operation: FolderObjectOperation,
        revision: u64,
        base_revision: Option<u64>,
        key_version: u32,
        envelope_json: String,
    }

    #[derive(Debug, Clone)]
    struct TombstoneFixture<'a> {
        vault_id: &'a str,
        folder_id: &'a str,
        object_id: &'a str,
        revision: u64,
        base_revision: u64,
        record_type: bool,
    }

    fn object_write_body(keys: &Keys, fixture: RevisionFixture<'_>) -> String {
        let envelope_json = object_envelope_json(
            fixture.vault_id,
            fixture.folder_id,
            fixture.object_id,
            fixture.key_version,
            fixture.content,
            fixture.nonce,
        );
        let event = revision_event_for_author(
            keys,
            npub(keys),
            RevisionEventFixture {
                vault_id: fixture.vault_id,
                folder_id: fixture.folder_id,
                object_id: fixture.object_id,
                operation: fixture.operation,
                revision: fixture.revision,
                base_revision: fixture.base_revision,
                key_version: fixture.key_version,
                envelope_json: envelope_json.clone(),
            },
        );
        let mut body = serde_json::json!({
            "baseRevision": fixture.base_revision,
            "keyVersion": fixture.key_version,
            "cipher": "AES-256-GCM",
            "ciphertext": envelope_json,
            "revisionEvent": event,
        });
        if fixture.record_type {
            body["recordType"] = serde_json::json!("folder_object_revision");
            body["folderId"] = serde_json::json!(fixture.folder_id);
            body["objectId"] = serde_json::json!(fixture.object_id);
        }
        body.to_string()
    }

    fn object_delete_body(keys: &Keys, fixture: TombstoneFixture<'_>) -> String {
        let event = tombstone_event(keys, &fixture);
        let mut body = serde_json::json!({
            "baseRevision": fixture.base_revision,
            "tombstoneEvent": event,
        });
        if fixture.record_type {
            body["recordType"] = serde_json::json!("folder_object_tombstone");
            body["folderId"] = serde_json::json!(fixture.folder_id);
            body["objectId"] = serde_json::json!(fixture.object_id);
        }
        body.to_string()
    }

    fn object_envelope_json(
        vault_id: &str,
        folder_id: &str,
        object_id: &str,
        key_version: u32,
        content: &str,
        nonce: u8,
    ) -> String {
        let key = FolderKey::from_bytes([9; 32]);
        let aad = FolderObjectAad {
            vault_id: VaultId::new(vault_id).unwrap(),
            folder_id: FolderId::new(folder_id).unwrap(),
            object_id: ObjectId::new(object_id).unwrap(),
            key_version,
        };
        encrypt_folder_object_with_nonce(&key, &aad, [nonce; 12], content.as_bytes())
            .unwrap()
            .canonical_json()
    }

    fn revision_event_for_author(
        signer_keys: &Keys,
        author_npub: String,
        fixture: RevisionEventFixture<'_>,
    ) -> Event {
        let expected = RevisionValidation {
            vault_id: VaultId::new(fixture.vault_id).unwrap(),
            folder_id: FolderId::new(fixture.folder_id).unwrap(),
            object_id: ObjectId::new(fixture.object_id).unwrap(),
            operation: fixture.operation,
            revision: fixture.revision,
            base_revision: fixture.base_revision,
            key_version: fixture.key_version,
            envelope_json: fixture.envelope_json,
            author_npub,
            created_at: TEST_NOW.to_string(),
        };
        let payload = FolderObjectRevisionPayload::new(&expected);
        sign_app_event(
            signer_keys,
            payload.canonical_json(),
            revision_tags(&expected),
        )
    }

    fn tombstone_event(keys: &Keys, fixture: &TombstoneFixture<'_>) -> Event {
        let expected = TombstoneValidation {
            vault_id: VaultId::new(fixture.vault_id).unwrap(),
            folder_id: FolderId::new(fixture.folder_id).unwrap(),
            object_id: ObjectId::new(fixture.object_id).unwrap(),
            revision: fixture.revision,
            base_revision: fixture.base_revision,
            author_npub: npub(keys),
            deleted_at: TEST_NOW.to_string(),
        };
        let payload = FolderObjectTombstonePayload::new(&expected);
        sign_app_event(keys, payload.canonical_json(), tombstone_tags(&expected))
    }

    fn revision_tags(input: &RevisionValidation) -> Vec<Vec<String>> {
        vec![
            vec![
                "d".to_owned(),
                format!(
                    "finite-folder-object-revision:{}:{}:{}:{}",
                    input.vault_id,
                    input.folder_id,
                    input.object_id.as_str(),
                    input.revision
                ),
            ],
            vec!["vault".to_owned(), input.vault_id.to_string()],
            vec!["folder".to_owned(), input.folder_id.to_string()],
            vec!["object".to_owned(), input.object_id.as_str().to_owned()],
            vec!["operation".to_owned(), input.operation.as_str().to_owned()],
            vec!["keyVersion".to_owned(), input.key_version.to_string()],
        ]
    }

    fn tombstone_tags(input: &TombstoneValidation) -> Vec<Vec<String>> {
        vec![
            vec![
                "d".to_owned(),
                format!(
                    "finite-folder-object-tombstone:{}:{}:{}:{}",
                    input.vault_id,
                    input.folder_id,
                    input.object_id.as_str(),
                    input.revision
                ),
            ],
            vec!["vault".to_owned(), input.vault_id.to_string()],
            vec!["folder".to_owned(), input.folder_id.to_string()],
            vec!["object".to_owned(), input.object_id.as_str().to_owned()],
            vec!["operation".to_owned(), "delete".to_owned()],
        ]
    }

    fn admin_event(
        keys: &Keys,
        vault_id: &str,
        change_id: &str,
        action: AdminAccessAction,
        folder_id: Option<&str>,
        target_npub: Option<&str>,
        key_version: Option<u32>,
    ) -> Event {
        let expected = AdminAccessChangeValidation {
            vault_id: VaultId::new(vault_id).unwrap(),
            change_id: change_id.to_owned(),
            action,
            admin_npub: npub(keys),
            folder_id: folder_id.map(FolderId::new).transpose().unwrap(),
            target_npub: target_npub.map(ToOwned::to_owned),
            key_version,
            note: None,
            created_at: TEST_NOW.to_string(),
        };
        let payload = AdminAccessChangePayload::new(&expected);
        sign_app_event(
            keys,
            payload.canonical_json(),
            admin_access_change_tags(&expected),
        )
    }

    fn admin_access_change_tags(input: &AdminAccessChangeValidation) -> Vec<Vec<String>> {
        let mut tags = vec![
            vec![
                "d".to_owned(),
                format!(
                    "finite-vault-admin-access-change:{}:{}",
                    input.vault_id, input.change_id
                ),
            ],
            vec!["vault".to_owned(), input.vault_id.to_string()],
            vec!["action".to_owned(), input.action.as_str().to_owned()],
        ];
        if let Some(folder_id) = &input.folder_id {
            tags.push(vec!["folder".to_owned(), folder_id.to_string()]);
        }
        if let Some(target_npub) = &input.target_npub {
            tags.push(vec![
                "p".to_owned(),
                NostrPublicKey::parse(target_npub).unwrap().to_hex(),
            ]);
        }
        if let Some(key_version) = input.key_version {
            tags.push(vec!["keyVersion".to_owned(), key_version.to_string()]);
        }
        tags
    }

    fn folder_key_grant_value(
        id: &str,
        key_version: u32,
        recipient_npub: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "keyVersion": key_version,
            "recipientNpub": recipient_npub,
            "wrappedEventJson": "{\"kind\":1059}",
            "createdAt": "2026-06-23T00:00:00.000Z",
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn rotation_object_value(
        keys: &Keys,
        vault_id: &str,
        folder_id: &str,
        object_id: &str,
        revision: u64,
        base_revision: Option<u64>,
        key_version: u32,
        content: &str,
        nonce: u8,
    ) -> serde_json::Value {
        let envelope_json =
            object_envelope_json(vault_id, folder_id, object_id, key_version, content, nonce);
        let event = revision_event_for_author(
            keys,
            npub(keys),
            RevisionEventFixture {
                vault_id,
                folder_id,
                object_id,
                operation: FolderObjectOperation::Update,
                revision,
                base_revision,
                key_version,
                envelope_json: envelope_json.clone(),
            },
        );
        serde_json::json!({
            "objectId": object_id,
            "baseRevision": base_revision,
            "keyVersion": key_version,
            "cipher": "AES-256-GCM",
            "ciphertext": envelope_json,
            "revisionEvent": event,
        })
    }

    fn test_strategy_folder() -> Folder {
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

    fn sign_app_event(keys: &Keys, content: String, tags: Vec<Vec<String>>) -> Event {
        let tags = tags
            .into_iter()
            .map(|tag| Tag::parse(tag).unwrap())
            .collect::<Vec<_>>();
        EventBuilder::new(Kind::ApplicationSpecificData, content)
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(TEST_NOW))
            .finalize(keys)
            .unwrap()
    }

    fn auth_header(
        keys: &Keys,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        created_at: u64,
    ) -> String {
        let url = format!("{TEST_BASE_URL}{path}");
        let mut tags = vec![tag(["u", url.as_str()]), tag(["method", method])];
        if let Some(body) = body {
            tags.push(tag(["payload", &Sha256Hash::hash(body).to_string()]));
        }
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(keys)
            .unwrap();
        format!("Nostr {}", BASE64_STANDARD.encode(event.as_json()))
    }

    fn tag<const N: usize>(parts: [&str; N]) -> Tag {
        Tag::parse(parts.into_iter().map(ToOwned::to_owned).collect::<Vec<_>>()).unwrap()
    }

    fn npub(keys: &Keys) -> String {
        NostrPublicKey::from_protocol(keys.public_key())
            .to_npub()
            .unwrap()
    }

    async fn read_json<T>(response: axum::response::Response) -> T
    where
        T: for<'de> Deserialize<'de>,
    {
        let body = to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("response body");
        serde_json::from_slice(&body).expect("json response")
    }

    async fn assert_error(response: axum::response::Response, status: StatusCode, contains: &str) {
        assert_eq!(response.status(), status);
        let body: ApiErrorBody = read_json(response).await;
        assert!(
            body.error.contains(contains),
            "expected error containing {contains:?}, got {:?}",
            body.error
        );
    }
}
