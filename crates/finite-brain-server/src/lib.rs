//! FiniteBrain HTTP server and API surface.

use std::path::Path;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{OriginalUri, Path as AxumPath, Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use finite_brain_core::{
    BootstrapSmokeSummary, CoreError, CryptoRecordError, FolderAccessMode, FolderId,
    FolderObjectOperation, FolderObjectRevisionPayload, FolderObjectTombstonePayload, FolderRole,
    ObjectId, RequiredFolderKeyGrant, RevisionValidation, TombstoneValidation, UserId, VaultId,
    VaultKind, bootstrap_organization_vault, bootstrap_personal_vault, validate_revision_event,
    validate_tombstone_event,
};
use finite_brain_store::{
    BrainStore, FolderKeyGrantMetadata, FolderObjectRevisionSyncRecord,
    FolderObjectTombstoneSyncRecord, StoreError, StoredSyncRecord, StoredVault, SyncRecordInput,
    SyncRecordType,
};
use finite_nostr::{HttpAuthValidation, NostrPrimitiveError, NostrPublicKey};
use nostr::Event;
use serde::{Deserialize, Serialize};

const DEFAULT_PUBLIC_BASE_URL: &str = "http://127.0.0.1:3015";
const DEFAULT_MAX_AUTH_SKEW_SECONDS: u64 = 300;

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
    auth_now_unix_seconds: u64,
    max_auth_skew_seconds: u64,
}

impl ServerState {
    /// Build state around an existing store.
    pub fn new(store: BrainStore, public_base_url: impl Into<String>) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            public_base_url: Arc::<str>::from(public_base_url.into()),
            auth_now_unix_seconds: current_unix_seconds(),
            max_auth_skew_seconds: DEFAULT_MAX_AUTH_SKEW_SECONDS,
        }
    }

    /// Override the auth validation clock for deterministic tests.
    pub fn with_auth_clock(mut self, now_unix_seconds: u64, max_skew_seconds: u64) -> Self {
        self.auth_now_unix_seconds = now_unix_seconds;
        self.max_auth_skew_seconds = max_skew_seconds;
        self
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
            StoreError::Database { .. } => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, value.to_string())
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
        .route("/_admin/vaults", post(create_vault_handler))
        .route(
            "/_admin/vaults/{vault_id}/metadata",
            get(vault_metadata_handler),
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

    Ok(Json(metadata_response(stored)))
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
        store.pull_sync_records(
            &vault_id,
            query.after.unwrap_or(0),
            query.limit.unwrap_or(100),
        )?
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
        state.auth_now_unix_seconds,
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
    if request.cipher != "AES-256-GCM" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "cipher must be AES-256-GCM",
        ));
    }
    let vault_id = VaultId::new(vault_id)?;
    let folder_id = FolderId::new(folder_id)?;
    let object_id = ObjectId::new(object_id)?;
    let revision = request.base_revision.map_or(1, |base| base + 1);
    let event = event_from_value(request.revision_event)?;

    let stored = {
        let store = state.store.lock().map_err(lock_error)?;
        store.load_vault(&vault_id)?
    };
    ensure_folder_visible(&stored, &folder_id, &actor_npub)?;
    ensure_folder_key_version(&stored, &folder_id, request.key_version)?;

    let expected = RevisionValidation {
        vault_id: vault_id.clone(),
        folder_id: folder_id.clone(),
        object_id: object_id.clone(),
        operation,
        revision,
        base_revision: request.base_revision,
        key_version: request.key_version,
        envelope_json: request.ciphertext.clone(),
        author_npub: actor_npub.clone(),
        created_at: expected_created_at(&event),
    };
    let payload: FolderObjectRevisionPayload = validate_revision_event(&event, &expected)?;
    let outcome = {
        let mut store = state.store.lock().map_err(lock_error)?;
        store.submit_sync_record(
            &vault_id,
            &SyncRecordInput::FolderObjectRevision(FolderObjectRevisionSyncRecord {
                record_event_id: event.id.to_hex(),
                folder_id,
                object_id,
                revision,
                base_revision: request.base_revision,
                actor_npub: UserId::new(actor_npub)?,
                client_created_at: payload.created_at,
                payload_json: request.ciphertext,
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

fn expected_created_at(event: &Event) -> String {
    event.created_at.as_secs().to_string()
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
        grant_count: stored.grants.len(),
    }
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

    fn test_router() -> Router {
        router_with_state(test_state())
    }

    fn test_state() -> ServerState {
        let store = BrainStore::open_in_memory().unwrap();
        ServerState::new(store, TEST_BASE_URL).with_auth_clock(TEST_NOW, 60)
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
