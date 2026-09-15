//! Separate public and loopback operator listeners.
//!
//! The operator console uses a random bearer token, exact Host checks, and
//! same-origin checks. No cookies or browser storage retain the token. Public
//! writes fail closed while the storage contract remains unproven.

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail, ensure};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, Semaphore};

use crate::lab;

/// Configuration for the operator console. The token is intentionally not Debug.
pub struct ConsoleConfig {
    /// Actual bound loopback address, including port.
    pub admin_addr: SocketAddr,
    /// Directory for token and offline experiment output.
    pub data_dir: PathBuf,
    /// Operator token loaded from a local restricted file.
    pub token: String,
    /// Optional read-only remote-node preflight configuration.
    pub preflight: Option<psky_hypersnap::PreflightConfig>,
}

/// Shared state scoped to one worker. No production account state lives here.
pub struct ConsoleState {
    config: ConsoleConfig,
    preflight: Mutex<Option<Value>>,
    lab: Mutex<Option<Value>>,
    operations: Arc<Semaphore>,
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
        Ok(Arc::new(Self {
            config,
            preflight: Mutex::new(None),
            lab: Mutex::new(None),
            operations: Arc::new(Semaphore::new(1)),
        }))
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
        Ok(meta) => {
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
            let token = fs::read_to_string(&path)?;
            let token = token.trim().to_owned();
            ensure!(valid_token(&token), "malformed admin token file");
            Ok(token)
        }
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
    let mut response = if !host_allowed(headers, state.config.admin_addr)
        || !origin_allowed(headers, state.config.admin_addr)
    {
        failure(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "Use the local console origin",
        )
    } else {
        let shell = matches!(req.uri().path(), "/" | "/admin.js");
        let provided = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        let authorized =
            provided.is_some_and(|p| p.as_bytes().ct_eq(state.config.token.as_bytes()).into());
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
    headers.insert("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'".parse().unwrap());
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
        .route("/admin/status", get(status))
        .route("/admin/preflight", post(preflight))
        .route("/admin/reconstruct", post(reconstruct))
        .layer(DefaultBodyLimit::max(4096))
        .layer(middleware::from_fn_with_state(state.clone(), protect))
        .with_state(state)
}

async fn status(State(state): State<Arc<ConsoleState>>) -> Json<Value> {
    Json(json!({
        "mode": "preflight-and-offline-lab",
        "pds_ready": false,
        "storage_gate": "unmodified Hypersnap durability and payload mapping are not proven",
        "account_binding": "not implemented",
        "signer": "no production signer; laboratory uses a public fixture key",
        "publication_watermark": null,
        "operation_running": state.operations.available_permits() == 0,
        "preflight": state.preflight.lock().await.clone(),
        "lab": state.lab.lock().await.clone()
    }))
}

async fn preflight(State(state): State<Arc<ConsoleState>>) -> Response {
    let Ok(_permit) = state.operations.clone().try_acquire_owned() else {
        return failure(
            StatusCode::CONFLICT,
            "Busy",
            "An operator action is running",
        );
    };
    let Some(config) = state.config.preflight.clone() else {
        return failure(
            StatusCode::BAD_REQUEST,
            "NoEndpoints",
            "Configure --endpoint before running preflight",
        );
    };
    let client = match psky_hypersnap::PreflightClient::new(config) {
        Ok(client) => client,
        Err(_) => {
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PreflightError",
                "Could not construct preflight client",
            );
        }
    };
    let report = serde_json::to_value(client.run().await).expect("serializable preflight report");
    *state.preflight.lock().await = Some(report.clone());
    Json(report).into_response()
}

async fn reconstruct(State(state): State<Arc<ConsoleState>>) -> Response {
    let Ok(_permit) = state.operations.clone().try_acquire_owned() else {
        return failure(
            StatusCode::CONFLICT,
            "Busy",
            "An operator action is running",
        );
    };
    let mut id = [0; 8];
    OsRng.fill_bytes(&mut id);
    let output = state
        .config
        .data_dir
        .join(format!("lab-{}", hex::encode(id)));
    let task_state = state.clone();
    let result = tokio::task::spawn_blocking(move || {
        // Hold the permit even if the HTTP requester disconnects.
        let _permit = _permit;
        let result = lab::run(&output);
        // Record the outcome even if the requester has stopped awaiting it.
        *task_state.lab.blocking_lock() = Some(match &result {
            Ok(report) => serde_json::to_value(report).expect("serializable lab report"),
            Err(_) => json!({"error":"LabFailed", "network_proof":false}),
        });
        result
    })
    .await;
    match result {
        Ok(Ok(report)) => {
            let report = serde_json::to_value(report).expect("serializable lab report");
            Json(report).into_response()
        }
        _ => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "LabFailed",
            "Offline reconstruction failed; check local output directory",
        ),
    }
}

#[derive(Deserialize)]
struct RepoQuery {
    did: String,
}

/// Public routes. Production writes always fail; fixture export is opt-in.
pub fn public_router(serve_fixture: bool) -> Router {
    Router::new()
        .route(
            "/health",
            get(|| async { Json(json!({"service":"PurpleSky", "pds_ready":false})) }),
        )
        .route("/ready", get(not_ready))
        .route(
            "/xrpc/com.atproto.sync.getRepo",
            get(move |query: Query<RepoQuery>| async move {
                if !serve_fixture {
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
            }),
        )
        .fallback(not_ready)
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
        ConsoleState::new(ConsoleConfig {
            admin_addr: "127.0.0.1:8788".parse().unwrap(),
            data_dir: dir.to_owned(),
            token: "ab".repeat(32),
            preflight: None,
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
        for path in [
            "/admin/status",
            "/admin/reconstruct",
            "/xrpc/com.atproto.repo.createRecord",
            "/ready",
        ] {
            let res = public_router(false)
                .oneshot(Request::post(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert!(!res.status().is_success());
        }
    }

    #[tokio::test]
    async fn public_fixture_is_explicit_and_scoped() {
        let path = format!("/xrpc/com.atproto.sync.getRepo?did={}", lab::FIXTURE_DID);
        let request = || Request::get(&path).body(Body::empty()).unwrap();
        assert_eq!(
            public_router(false)
                .oneshot(request())
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let res = public_router(true).oneshot(request()).await.unwrap();
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
            public_router(true).oneshot(bad).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn mutations_need_auth_and_report_actual_results() {
        let dir = tempfile::tempdir().unwrap();
        let router = admin_router(state(dir.path()));
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
        assert_eq!(result.status(), StatusCode::OK);
        let report: Value =
            serde_json::from_slice(&result.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(report["network_proof"], false);
    }

    #[test]
    fn non_loopback_admin_bind_rejected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            ConsoleState::new(ConsoleConfig {
                admin_addr: "0.0.0.0:8788".parse().unwrap(),
                data_dir: dir.path().to_owned(),
                token: "ab".repeat(32),
                preflight: None
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
