//! Separate public and loopback operator listeners.
//!
//! The operator console uses a random bearer token, exact Host checks, and
//! same-origin checks. No cookies or browser storage retain the token. Public
//! writes fail closed while the storage contract remains unproven.

use std::{
    collections::VecDeque,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Result, bail, ensure};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Query, Request, State, rejection::JsonRejection},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, Notify};

use crate::{
    account::{self, AccountNode},
    journal::{self, Journal, OPERATION_CAPACITY, Operation, OperationKind},
    lab,
    settings::{ConfigStore, Settings, SettingsError},
};

/// Configuration for the operator console. The token is intentionally not Debug.
pub struct ConsoleConfig {
    /// Actual bound loopback address, including port.
    pub admin_addr: SocketAddr,
    /// Actual public API address, including port.
    pub public_addr: SocketAddr,
    /// Directory for token and offline experiment output.
    pub data_dir: PathBuf,
    /// Operator token loaded from a local restricted file.
    pub token: String,
    /// Validated, durable operator settings.
    pub store: ConfigStore,
}

/// Shared state scoped to one worker, with an isolated private credential store.
pub struct ConsoleState {
    account: Arc<AccountNode>,
    admin_addr: SocketAddr,
    public_addr: SocketAddr,
    data_dir: PathBuf,
    token: String,
    startup: Settings,
    started: Instant,
    instance_id: String,
    control: Mutex<Control>,
    idle: Notify,
}

struct Control {
    store: ConfigStore,
    preflight: Option<Value>,
    preflight_revision: Option<u64>,
    last_check_at: Option<u64>,
    lab: Option<Value>,
    lab_revision: Option<u64>,
    journal: Journal,
    active: Option<Operation>,
    recent: VecDeque<Operation>,
    next_operation: u64,
    shutting_down: bool,
}

impl ConsoleState {
    /// Validate the admin binding and construct isolated worker state.
    pub fn new(config: ConsoleConfig) -> Result<Arc<Self>> {
        ensure!(
            config.admin_addr.ip().is_loopback(),
            "admin listener must bind loopback"
        );
        ensure!(
            valid_token(&config.token),
            "admin token must be 64 hexadecimal characters"
        );
        let startup = config.store.snapshot().settings;
        startup.validate()?;
        let account = AccountNode::open(
            &config.data_dir,
            startup.account.clone(),
            config.public_addr,
        )?;
        let mut journal = Journal::default();
        journal.push(
            "info",
            "node_started",
            "Management console started; production PDS is unavailable",
        );
        let mut instance = [0; 16];
        OsRng.fill_bytes(&mut instance);
        Ok(Arc::new(Self {
            account,
            admin_addr: config.admin_addr,
            public_addr: config.public_addr,
            data_dir: config.data_dir,
            token: config.token,
            startup,
            started: Instant::now(),
            instance_id: hex::encode(instance),
            idle: Notify::new(),
            control: Mutex::new(Control {
                store: config.store,
                preflight: None,
                preflight_revision: None,
                last_check_at: None,
                lab: None,
                lab_revision: None,
                journal,
                active: None,
                recent: VecDeque::new(),
                next_operation: 1,
                shutting_down: false,
            }),
        }))
    }

    fn restart_required(&self, settings: &Settings) -> bool {
        settings.admin_bind != self.startup.admin_bind
            || settings.public_bind != self.startup.public_bind
    }

    /// Reject new changes and wait for accepted diagnostics before process shutdown.
    pub async fn drain(&self) {
        loop {
            let notified = self.idle.notified();
            let mut control = self.control.lock().await;
            if !control.shutting_down {
                control.shutting_down = true;
                control.journal.push(
                    "info",
                    "shutdown_started",
                    "Finishing accepted diagnostics before shutdown",
                );
            }
            if control.active.is_none() {
                return;
            }
            // Register before releasing the lock so task completion cannot be missed.
            tokio::pin!(notified);
            notified.as_mut().enable();
            drop(control);
            notified.await;
        }
    }

    async fn finish(&self, mut operation: Operation, result: Result<Value, &'static str>) {
        let mut control = self.control.lock().await;
        operation.finished_at = Some(journal::now());
        match result {
            Ok(report) => {
                operation.status = "succeeded";
                match operation.kind {
                    OperationKind::Preflight => {
                        let healthy = report["healthy"].as_bool().unwrap_or(false);
                        control.preflight = Some(report);
                        control.preflight_revision = Some(operation.config_revision);
                        control.last_check_at = operation.finished_at;
                        control.journal.push(
                            if healthy { "info" } else { "warning" },
                            "preflight_finished",
                            if healthy {
                                "Peer checks passed; storage reconstruction is still unproven"
                            } else {
                                "Peer checks finished with unhealthy or unknown observations"
                            },
                        );
                    }
                    OperationKind::Reconstruct => {
                        control.lab = Some(report);
                        control.lab_revision = Some(operation.config_revision);
                        control.journal.push(
                            "info",
                            "reconstruction_finished",
                            "Offline fixture reconstruction passed; this is not network proof",
                        );
                    }
                }
            }
            Err(error) => {
                operation.status = "failed";
                operation.error = Some(error);
                match operation.kind {
                    OperationKind::Preflight => {
                        control.preflight = None;
                        control.preflight_revision = None;
                        control.last_check_at = None;
                    }
                    OperationKind::Reconstruct => {
                        control.lab = Some(json!({"error":"LabFailed", "network_proof":false}));
                        control.lab_revision = Some(operation.config_revision);
                    }
                }
                control.journal.push("error", "operation_failed", error);
            }
        }
        control.active = None;
        if control.recent.len() == OPERATION_CAPACITY {
            control.recent.pop_back();
        }
        control.recent.push_front(operation);
        self.idle.notify_waiters();
    }
}

fn valid_token(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Load or generate a 256-bit token in a new mode-0600 file on Unix.
///
/// Refuses symlinks, malformed tokens, and existing group/world-accessible
/// token files. This function never prints the token.
pub fn load_admin_token(data_dir: &Path) -> Result<String> {
    fs::create_dir_all(data_dir)?;
    let path = data_dir.join("admin.token");
    match fs::symlink_metadata(&path) {
        Ok(_) => read_admin_token(data_dir),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            use std::io::Write;
            let mut bytes = [0; 32];
            OsRng.fill_bytes(&mut bytes);
            let token = hex::encode(bytes);
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(path).context("create admin token file")?;
            file.write_all(token.as_bytes())?;
            file.sync_all()?;
            Ok(token)
        }
        Err(error) => bail!(error),
    }
}

/// Read an existing operator token without creating files or printing it.
pub fn read_admin_token(data_dir: &Path) -> Result<String> {
    let path = data_dir.join("admin.token");
    let meta = fs::symlink_metadata(&path).context("read existing admin token metadata")?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "admin token must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "admin token file permissions must be 0600"
        );
    }
    ensure!(meta.len() <= 65, "malformed admin token file");
    let token = fs::read_to_string(path)?.trim().to_owned();
    ensure!(valid_token(&token), "malformed admin token file");
    Ok(token)
}

fn failure(status: StatusCode, error: &str, message: &str) -> Response {
    (status, Json(json!({"error":error,"message":message}))).into_response()
}

fn host_allowed(headers: &HeaderMap, addr: SocketAddr) -> bool {
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok());
    host.is_some_and(|h| h == addr.to_string() || h == format!("localhost:{}", addr.port()))
}

fn origin_allowed(headers: &HeaderMap, addr: SocketAddr) -> bool {
    if headers.get("sec-fetch-site").and_then(|h| h.to_str().ok()) == Some("cross-site") {
        return false;
    }
    match headers.get(header::ORIGIN) {
        None => true, // CLI requests still require the bearer token.
        Some(origin) => origin.to_str().is_ok_and(|o| {
            o == format!("http://{addr}") || o == format!("http://localhost:{}", addr.port())
        }),
    }
}

async fn protect(State(state): State<Arc<ConsoleState>>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    let mut response =
        if !host_allowed(headers, state.admin_addr) || !origin_allowed(headers, state.admin_addr) {
            failure(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "Use the local console origin",
            )
        } else {
            let shell = matches!(*req.method(), Method::GET | Method::HEAD)
                && matches!(
                    req.uri().path(),
                    "/" | "/admin.js" | "/admin.css" | "/llms.txt"
                );
            let provided = headers
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "));
            let authorized =
                provided.is_some_and(|p| p.as_bytes().ct_eq(state.token.as_bytes()).into());
            if shell || authorized {
                next.run(req).await
            } else {
                failure(
                    StatusCode::UNAUTHORIZED,
                    "AuthenticationRequired",
                    "Provide the local admin bearer token",
                )
            }
        };
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'".parse().unwrap());
    response
}

/// Build the localhost console router, including origin and token protection.
pub fn admin_router(state: Arc<ConsoleState>) -> Router {
    Router::new()
        .route("/", get(|| async { Html(include_str!("console.html")) }))
        .route(
            "/admin.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("console.js"),
                )
            }),
        )
        .route(
            "/admin.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("console.css"),
                )
            }),
        )
        .route(
            "/llms.txt",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                    include_str!("../../../llms.txt"),
                )
            }),
        )
        .route("/admin/status", get(status))
        .route("/admin/config", get(config).put(update_config))
        .route("/admin/logs", get(logs))
        .route(
            "/admin/account/logs",
            get(|State(state): State<Arc<ConsoleState>>| async move {
                Json(state.account.events().await)
            }),
        )
        .route("/admin/operations", get(operations))
        .route("/admin/preflight", post(preflight))
        .route("/admin/reconstruct", post(reconstruct))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), protect))
        .with_state(state)
}

async fn status(State(state): State<Arc<ConsoleState>>) -> Json<Value> {
    let control = state.control.lock().await;
    let document = control.store.snapshot();
    let account = state.account.status().await;
    Json(json!({
        "api_version": 1,
        "instance_id": state.instance_id,
        "uptime_seconds": state.started.elapsed().as_secs(),
        "version": env!("CARGO_PKG_VERSION"),
        "node_name": document.settings.node_name,
        "config_revision": document.revision,
        "restart_required": state.restart_required(&document.settings),
        "shutting_down": control.shutting_down,
        "mode": "preflight-and-offline-lab",
        "pds_ready": false,
        "storage_gate": "unmodified Hypersnap durability and payload mapping are not proven",
        "account_binding": if account["busy"] == true { "Account check in progress" } else if account["bound"] == true { "Farcaster-bound account" } else if account["enabled"] == true { "Awaiting Farcaster sign-in" } else { "Login disabled" },
        "account": account,
        "signer": "Publishing signer not configured; app passwords cannot publish yet",
        "publication_watermark": null,
        "operation_running": control.active.is_some(),
        "active_operation": control.active,
        "last_check_at": control.last_check_at,
        "preflight_config_revision": control.preflight_revision,
        "lab_config_revision": control.lab_revision,
        "preflight": control.preflight,
        "lab": control.lab
    }))
}

fn config_response(state: &ConsoleState, control: &Control) -> Json<Value> {
    let document = control.store.snapshot();
    Json(
        json!({"revision":document.revision,"settings":document.settings,
        "active_listeners":{"admin_bind":state.admin_addr,"public_bind":state.public_addr},
        "restart_required":state.restart_required(&document.settings)}),
    )
}

async fn config(State(state): State<Arc<ConsoleState>>) -> Json<Value> {
    config_response(&state, &*state.control.lock().await)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigUpdate {
    expected_revision: u64,
    settings: Settings,
}

fn unavailable(control: &Control) -> Option<Response> {
    if control.shutting_down {
        Some(failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "ShuttingDown",
            "Node is shutting down",
        ))
    } else if control.active.is_some() {
        Some(failure(
            StatusCode::CONFLICT,
            "Busy",
            "An operator action is running",
        ))
    } else {
        None
    }
}

async fn update_config(
    State(state): State<Arc<ConsoleState>>,
    input: Result<Json<ConfigUpdate>, JsonRejection>,
) -> Response {
    let Ok(Json(input)) = input else {
        return failure(
            StatusCode::BAD_REQUEST,
            "InvalidConfig",
            "Expected a bounded JSON settings document and revision",
        );
    };
    let mut control = state.control.lock().await;
    if let Some(response) = unavailable(&control) {
        return response;
    }
    let mut account_config = state.account.configuration().await;
    if let Err(message) = account_config.check(&input.settings.account) {
        return failure(StatusCode::BAD_REQUEST, "InvalidConfig", message);
    }
    match control
        .store
        .replace(input.expected_revision, input.settings)
    {
        Ok(_) => {
            account_config.apply(control.store.snapshot().settings.account);
            control.preflight = None;
            control.preflight_revision = None;
            control.last_check_at = None;
            control.journal.push(
                "info",
                "config_updated",
                "Settings saved; rerun peer checks for this revision",
            );
            config_response(&state, &control).into_response()
        }
        Err(SettingsError::Conflict) => failure(
            StatusCode::CONFLICT,
            "ConfigConflict",
            "Settings changed; fetch the latest revision and reapply your edits",
        ),
        Err(SettingsError::Invalid(message)) => {
            failure(StatusCode::BAD_REQUEST, "InvalidConfig", message)
        }
        Err(SettingsError::Persistence(_)) => {
            if control.store.snapshot().revision != input.expected_revision {
                account_config.apply(control.store.snapshot().settings.account);
                control.preflight = None;
                control.preflight_revision = None;
                control.last_check_at = None;
                control.journal.push("error", "config_durability_unknown", "Settings published but directory sync failed; reread configuration before retrying");
                failure(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ConfigDurabilityUnknown",
                    "Settings published but durability is uncertain; reread configuration and check disk health before retrying",
                )
            } else {
                control.journal.push(
                    "error",
                    "config_save_failed",
                    "Settings could not be saved; check data directory access and free space",
                );
                failure(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ConfigSaveFailed",
                    "Settings could not be saved; active settings are unchanged",
                )
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogQuery {
    #[serde(default)]
    after: u64,
    #[serde(default = "log_limit")]
    limit: usize,
}
fn log_limit() -> usize {
    100
}

async fn logs(
    State(state): State<Arc<ConsoleState>>,
    query: Result<Query<LogQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return failure(
            StatusCode::BAD_REQUEST,
            "InvalidCursor",
            "Use integer after and limit parameters",
        );
    };
    if !(1..=journal::LOG_CAPACITY).contains(&query.limit) {
        return failure(
            StatusCode::BAD_REQUEST,
            "InvalidLimit",
            "Log limit must be 1 through 200",
        );
    }
    let control = state.control.lock().await;
    Json(control.journal.page(query.after, query.limit)).into_response()
}

async fn operations(State(state): State<Arc<ConsoleState>>) -> Json<Value> {
    let control = state.control.lock().await;
    Json(json!({"active":control.active,"recent":control.recent}))
}

async fn preflight(State(state): State<Arc<ConsoleState>>) -> Response {
    start(state, OperationKind::Preflight).await
}

async fn reconstruct(State(state): State<Arc<ConsoleState>>) -> Response {
    start(state, OperationKind::Reconstruct).await
}

async fn start(state: Arc<ConsoleState>, kind: OperationKind) -> Response {
    let mut control = state.control.lock().await;
    if let Some(response) = unavailable(&control) {
        return response;
    }
    let document = control.store.snapshot();
    let client = if kind == OperationKind::Preflight {
        match document.settings.preflight() {
            Ok(Some(config)) => match psky_hypersnap::PreflightClient::new(config) {
                Ok(client) => Some(client),
                Err(_) => {
                    return failure(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "PreflightError",
                        "Could not construct preflight client",
                    );
                }
            },
            Ok(None) => {
                return failure(
                    StatusCode::BAD_REQUEST,
                    "NoEndpoints",
                    "Add endpoints in Settings before checking peers",
                );
            }
            Err(_) => {
                return failure(
                    StatusCode::BAD_REQUEST,
                    "InvalidConfig",
                    "Peer settings are invalid",
                );
            }
        }
    } else {
        None
    };
    let operation = Operation {
        id: control.next_operation,
        kind,
        status: "running",
        started_at: journal::now(),
        finished_at: None,
        error: None,
        config_revision: document.revision,
    };
    control.next_operation += 1;
    control.active = Some(operation.clone());
    control.journal.push(
        "info",
        "operation_started",
        match kind {
            OperationKind::Preflight => "Reading configured peers; no network writes will be sent",
            OperationKind::Reconstruct => {
                "Starting a synthetic reconstruction in a new local directory"
            }
        },
    );
    drop(control);
    let started = operation.clone();
    tokio::spawn(async move {
        // A supervisor records panics/failures and outlives the HTTP request.
        let result = if let Some(client) = client {
            tokio::spawn(async move { serde_json::to_value(client.run().await) })
                .await
                .ok()
                .and_then(Result::ok)
                .ok_or("Preflight task failed")
        } else {
            let mut id = [0; 8];
            OsRng.fill_bytes(&mut id);
            let artifact_dir = format!("lab-{}", hex::encode(id));
            let output = state.data_dir.join(&artifact_dir);
            tokio::task::spawn_blocking(move || {
                lab::run(&output).and_then(|v| {
                    let mut report = serde_json::to_value(v)?;
                    report["artifact_dir"] = json!(artifact_dir);
                    Ok(report)
                })
            })
            .await
            .ok()
            .and_then(Result::ok)
            .ok_or("Offline reconstruction failed; check data directory access and free space")
        };
        state.finish(operation, result).await;
    });
    (StatusCode::ACCEPTED, Json(started)).into_response()
}

#[derive(Deserialize)]
struct RepoQuery {
    did: String,
}

/// Public routes. Production writes always fail; fixture export is opt-in.
pub fn public_router(state: Arc<ConsoleState>) -> Router {
    let account_routes = account::router(state.account.clone());
    Router::new()
        .route(
            "/health",
            get(|| async { Json(json!({"service":"PurpleSky", "pds_ready":false})) }),
        )
        .route("/ready", get(not_ready))
        .route(
            "/xrpc/com.atproto.sync.getRepo",
            get(
                move |State(state): State<Arc<ConsoleState>>, query: Query<RepoQuery>| async move {
                    if let Some(result) = state.account.repository(&query.did).await {
                        return match result {
                            Ok(car) => (
                                [
                                    ("content-type", "application/vnd.ipld.car"),
                                    ("x-psky-evidence", "empty-account-repository"),
                                ],
                                Body::from(car),
                            )
                                .into_response(),
                            Err(_) => failure(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "RepoError",
                                "Could not read account metadata",
                            ),
                        };
                    }
                    if !state
                        .control
                        .lock()
                        .await
                        .store
                        .snapshot()
                        .settings
                        .serve_fixture
                    {
                        return not_ready().await;
                    }
                    if query.did != lab::FIXTURE_DID {
                        return failure(
                            StatusCode::NOT_FOUND,
                            "RepoNotFound",
                            "Only the documented offline fixture DID is available",
                        );
                    }
                    match lab::fixture_car(true) {
                        Ok(car) => (
                            [
                                ("content-type", "application/vnd.ipld.car"),
                                ("x-psky-evidence", "offline-fixture"),
                            ],
                            Body::from(car),
                        )
                            .into_response(),
                        Err(_) => failure(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "FixtureError",
                            "Could not build fixture",
                        ),
                    }
                },
            ),
        )
        .fallback(not_ready)
        .with_state(state)
        .merge(account_routes)
}

async fn not_ready() -> Response {
    failure(
        StatusCode::SERVICE_UNAVAILABLE,
        "StorageContractUnproven",
        "Production PDS operations are unavailable; see the storage feasibility report",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn state(dir: &Path) -> Arc<ConsoleState> {
        state_with(dir, Settings::default())
    }

    fn state_with(dir: &Path, settings: Settings) -> Arc<ConsoleState> {
        ConsoleState::new(ConsoleConfig {
            admin_addr: "127.0.0.1:8788".parse().unwrap(),
            public_addr: "127.0.0.1:8787".parse().unwrap(),
            data_dir: dir.to_owned(),
            token: "ab".repeat(32),
            store: ConfigStore::open(dir, settings).unwrap(),
        })
        .unwrap()
    }

    async fn call(path: &str, host: &str, origin: Option<&str>, token: Option<&str>) -> Response {
        let dir = tempfile::tempdir().unwrap();
        let router = admin_router(state(dir.path()));
        let mut request = Request::builder().uri(path).header("host", host);
        if let Some(o) = origin {
            request = request.header("origin", o);
        }
        if let Some(t) = token {
            request = request.header("authorization", format!("Bearer {t}"));
        }
        router
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn shell_is_local_but_status_needs_token() {
        assert_eq!(
            call("/", "127.0.0.1:8788", None, None).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            call("/admin/status", "127.0.0.1:8788", None, None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call("/admin/status", "127.0.0.1:8788", None, Some("wrong"))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn authorized_status_does_not_leak_token_or_claim_readiness() {
        let token = "ab".repeat(32);
        let res = call(
            "/admin/status",
            "localhost:8788",
            Some("http://localhost:8788"),
            Some(&token),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()["cache-control"], "no-store");
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let status: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(status["pds_ready"], false);
        assert!(!String::from_utf8_lossy(&body).contains(&token));
    }

    #[tokio::test]
    async fn hostile_hosts_and_origins_fail_even_with_token() {
        let token = "ab".repeat(32);
        for host in [
            "evil.example:8788",
            "127.0.0.1.evil.example:8788",
            "localhost",
            "127.0.0.1:80",
        ] {
            assert_eq!(
                call("/admin/status", host, None, Some(&token))
                    .await
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        for origin in [
            "null",
            "https://evil.example",
            "http://localhost:9999",
            "https://localhost:8788",
        ] {
            assert_eq!(
                call(
                    "/admin/status",
                    "localhost:8788",
                    Some(origin),
                    Some(&token)
                )
                .await
                .status(),
                StatusCode::FORBIDDEN
            );
        }
    }

    #[tokio::test]
    async fn public_listener_has_no_admin_or_production_writes() {
        let dir = tempfile::tempdir().unwrap();
        for path in [
            "/admin/status",
            "/admin/reconstruct",
            "/admin/config",
            "/admin/logs",
            "/admin/operations",
            "/llms.txt",
            "/xrpc/com.atproto.repo.createRecord",
            "/ready",
        ] {
            let res = public_router(state(dir.path()))
                .oneshot(Request::post(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert!(!res.status().is_success());
        }
    }

    #[tokio::test]
    async fn public_fixture_is_explicit_and_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        let path = format!("/xrpc/com.atproto.sync.getRepo?did={}", lab::FIXTURE_DID);
        let request = || Request::get(&path).body(Body::empty()).unwrap();
        assert_eq!(
            public_router(state.clone())
                .oneshot(request())
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        {
            let mut control = state.control.lock().await;
            let mut settings = control.store.snapshot().settings;
            settings.serve_fixture = true;
            control.store.replace(1, settings).unwrap();
        }
        let res = public_router(state.clone())
            .oneshot(request())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()["x-psky-evidence"], "offline-fixture");
        assert_eq!(
            res.into_body().collect().await.unwrap().to_bytes().as_ref(),
            lab::fixture_car(true).unwrap()
        );
        let bad = Request::get("/xrpc/com.atproto.sync.getRepo?did=did:plc:someoneelse")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            public_router(state).oneshot(bad).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn mutations_need_auth_and_report_actual_results() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        let router = admin_router(state.clone());
        let request = |path: &str| {
            Request::post(path)
                .header("host", "localhost:8788")
                .header("authorization", format!("Bearer {}", "ab".repeat(32)))
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            router
                .clone()
                .oneshot(request("/admin/preflight"))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        let result = router.oneshot(request("/admin/reconstruct")).await.unwrap();
        assert_eq!(result.status(), StatusCode::ACCEPTED);
        let report: Value =
            serde_json::from_slice(&result.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(report["status"], "running");
        state.drain().await;
        let control = state.control.lock().await;
        assert_eq!(control.lab.as_ref().unwrap()["network_proof"], false);
        assert_eq!(control.recent[0].status, "succeeded");
        assert!(control.active.is_none());
    }

    #[test]
    fn non_loopback_admin_bind_rejected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            ConsoleState::new(ConsoleConfig {
                admin_addr: "0.0.0.0:8788".parse().unwrap(),
                public_addr: "127.0.0.1:8787".parse().unwrap(),
                data_dir: dir.path().to_owned(),
                token: "ab".repeat(32),
                store: ConfigStore::open(dir.path(), Settings::default()).unwrap()
            })
            .is_err()
        );
    }

    #[test]
    fn token_persists_and_malformed_token_fails() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_admin_token(dir.path()).unwrap();
        assert!(valid_token(&first));
        assert_eq!(load_admin_token(dir.path()).unwrap(), first);
        fs::write(dir.path().join("admin.token"), "short").unwrap();
        assert!(load_admin_token(dir.path()).is_err());
    }

    async fn request(state: Arc<ConsoleState>, method: &str, path: &str, body: Value) -> Response {
        admin_router(state)
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("host", "localhost:8788")
                    .header("authorization", format!("Bearer {}", "ab".repeat(32)))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn value(response: Response) -> Value {
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    #[tokio::test]
    async fn settings_apply_live_persist_and_mark_listener_restart() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        let initial =
            value(request(state.clone(), "GET", "/admin/config", Value::Null).await).await;
        assert_eq!(initial["revision"], 1);
        assert_eq!(initial["restart_required"], false);
        let mut settings = initial["settings"].clone();
        settings["node_name"] = json!("Worker A");
        settings["serve_fixture"] = json!(true);
        settings["admin_bind"] = json!("127.0.0.1:9988");
        let response = request(
            state.clone(),
            "PUT",
            "/admin/config",
            json!({"expected_revision":1,"settings":settings}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let saved = value(response).await;
        assert_eq!(saved["revision"], 2);
        assert_eq!(saved["restart_required"], true);
        assert_eq!(saved["active_listeners"]["admin_bind"], "127.0.0.1:8788");
        let status = value(request(state.clone(), "GET", "/admin/status", Value::Null).await).await;
        assert_eq!(status["node_name"], "Worker A");
        assert_eq!(status["pds_ready"], false);
        let res = public_router(state.clone())
            .oneshot(
                Request::get(format!(
                    "/xrpc/com.atproto.sync.getRepo?did={}",
                    lab::FIXTURE_DID
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            ConfigStore::open(dir.path(), Settings::default())
                .unwrap()
                .snapshot()
                .revision,
            2
        );
        assert_eq!(
            request(
                state,
                "PUT",
                "/admin/config",
                json!({"expected_revision":1,"settings":settings})
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn invalid_config_is_redacted_and_does_not_change_revision() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        for invalid in [
            json!({"endpoints":["https://user:SECRET_MARKER@example.com"]}),
            json!({"private_key":"SECRET_MARKER"}),
            json!({"admin_bind":"0.0.0.0:8788"}),
        ] {
            let mut settings = serde_json::to_value(Settings::default()).unwrap();
            for (k, v) in invalid.as_object().unwrap() {
                settings[k] = v.clone();
            }
            let res = request(
                state.clone(),
                "PUT",
                "/admin/config",
                json!({"expected_revision":1,"settings":settings}),
            )
            .await;
            assert_eq!(res.status(), StatusCode::BAD_REQUEST);
            assert!(!value(res).await.to_string().contains("SECRET_MARKER"));
            assert_eq!(state.control.lock().await.store.snapshot().revision, 1);
        }
        let logs = value(request(state, "GET", "/admin/logs", Value::Null).await).await;
        assert!(!logs.to_string().contains("SECRET_MARKER"));
    }

    #[tokio::test]
    async fn logs_are_bounded_validated_and_protected() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        for _ in 0..205 {
            state
                .control
                .lock()
                .await
                .journal
                .push("info", "test", "fixed");
        }
        let page = value(
            request(
                state.clone(),
                "GET",
                "/admin/logs?after=0&limit=2",
                Value::Null,
            )
            .await,
        )
        .await;
        assert_eq!(page["entries"].as_array().unwrap().len(), 2);
        assert_eq!(page["truncated"], true);
        assert_eq!(page["dropped_before"], 6);
        for query in [
            "limit=0",
            "limit=201",
            "after=-1",
            "after=secret",
            "unknown=1",
        ] {
            assert_eq!(
                request(
                    state.clone(),
                    "GET",
                    &format!("/admin/logs?{query}"),
                    Value::Null
                )
                .await
                .status(),
                StatusCode::BAD_REQUEST
            );
        }
        for path in ["/admin/config", "/admin/logs", "/admin/operations"] {
            assert_eq!(
                call(path, "localhost:8788", None, None).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }

    #[tokio::test]
    async fn static_agent_guide_is_local_and_has_no_secret() {
        for path in ["/llms.txt", "/admin.css", "/admin.js"] {
            let res = call(path, "localhost:8788", None, None).await;
            assert_eq!(res.status(), StatusCode::OK);
            assert!(
                res.headers()["content-security-policy"]
                    .to_str()
                    .unwrap()
                    .contains("style-src 'self'")
            );
            assert_eq!(
                call(path, "evil.example:8788", None, None).await.status(),
                StatusCode::FORBIDDEN
            );
        }
        let body = call("/llms.txt", "localhost:8788", None, None)
            .await
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("expected_revision"));
        assert!(!String::from_utf8_lossy(&body).contains(&"ab".repeat(32)));
    }

    #[tokio::test]
    async fn actions_survive_disconnect_reject_overlap_and_drain_on_shutdown() {
        let release = Arc::new(Notify::new());
        let handler_release = release.clone();
        let fixture = Router::new().route(
            "/v1/info",
            get(move || {
                let release = handler_release.clone();
                async move {
                    release.notified().await;
                    Json(json!({"version":"0.13.5"}))
                }
            }),
        );
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", socket.local_addr().unwrap());
        let fixture_task = tokio::spawn(async {
            axum::serve(socket, fixture).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            endpoints: vec![endpoint],
            ..Settings::default()
        };
        let state = state_with(dir.path(), settings.clone());
        let accepted = request(state.clone(), "POST", "/admin/preflight", Value::Null).await;
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        drop(accepted); // Accepted work must not depend on consuming the response.
        assert_eq!(
            request(state.clone(), "POST", "/admin/reconstruct", Value::Null)
                .await
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            request(
                state.clone(),
                "PUT",
                "/admin/config",
                json!({"expected_revision":1,"settings":settings})
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let drain_state = state.clone();
        let draining = tokio::spawn(async move {
            drain_state.drain().await;
        });
        tokio::task::yield_now().await;
        assert!(!draining.is_finished());
        release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), draining)
            .await
            .unwrap()
            .unwrap();
        let control = state.control.lock().await;
        assert!(control.active.is_none());
        assert_eq!(control.recent[0].status, "succeeded");
        assert_eq!(control.preflight.as_ref().unwrap()["healthy"], false);
        assert_eq!(control.preflight_revision, Some(1));
        drop(control);
        assert_eq!(
            request(state, "POST", "/admin/preflight", Value::Null)
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        fixture_task.abort();
    }

    #[tokio::test]
    async fn failed_lab_is_recorded_without_paths_or_partial_success() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        // Simulate a vanished data directory after startup, without touching user files.
        dir.close().unwrap();
        assert_eq!(
            request(state.clone(), "POST", "/admin/reconstruct", Value::Null)
                .await
                .status(),
            StatusCode::ACCEPTED
        );
        state.drain().await;
        let control = state.control.lock().await;
        assert_eq!(control.lab.as_ref().unwrap()["error"], "LabFailed");
        assert_eq!(control.recent[0].status, "failed");
        assert!(control.recent[0].error.is_some());
        assert!(
            !serde_json::to_string(&control.recent)
                .unwrap()
                .contains("/tmp/")
        );
    }

    #[cfg(unix)]
    #[test]
    fn insecure_permissions_and_symlinks_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        load_admin_token(dir.path()).unwrap();
        fs::set_permissions(
            dir.path().join("admin.token"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(load_admin_token(dir.path()).is_err());
        let linked = tempfile::tempdir().unwrap();
        symlink(
            dir.path().join("admin.token"),
            linked.path().join("admin.token"),
        )
        .unwrap();
        assert!(load_admin_token(linked.path()).is_err());
    }
}
