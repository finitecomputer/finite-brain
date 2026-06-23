//! FiniteBrain HTTP server and API surface.

use std::path::Path;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{OriginalUri, Path as AxumPath, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use finite_brain_core::{
    BootstrapSmokeSummary, CoreError, FolderAccessMode, FolderRole, RequiredFolderKeyGrant, UserId,
    VaultId, VaultKind, bootstrap_organization_vault, bootstrap_personal_vault,
};
use finite_brain_store::{BrainStore, FolderKeyGrantMetadata, StoreError, StoredVault};
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
    use nostr::event::FinalizeEvent;
    use nostr::hashes::Hash;
    use nostr::hashes::sha256::Hash as Sha256Hash;
    use nostr::nips::nip98::{HttpData, HttpMethod};
    use nostr::{EventBuilder, Keys, Timestamp, Url};
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

    fn test_router() -> Router {
        let store = BrainStore::open_in_memory().unwrap();
        router_with_state(ServerState::new(store, TEST_BASE_URL).with_auth_clock(TEST_NOW, 60))
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

    fn auth_header(
        keys: &Keys,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        created_at: u64,
    ) -> String {
        let method = method.parse::<HttpMethod>().unwrap();
        let url = Url::parse(&format!("{TEST_BASE_URL}{path}")).unwrap();
        let mut data = HttpData::new(url, method);
        if let Some(body) = body {
            data = data.payload(Sha256Hash::hash(body));
        }
        let event = EventBuilder::http_auth(data)
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(keys)
            .unwrap();
        format!("Nostr {}", BASE64_STANDARD.encode(event.as_json()))
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
