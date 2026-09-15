//! Farcaster consent, revocable app passwords, and the ATProto session boundary.
//!
//! The relay is a transport, never an identity oracle. A challenge is consumed
//! once, proofs are checked against finalized Optimism state, and credentials
//! are tied to that authority. Publishing is deliberately absent. Stored SIWE
//! evidence is private metadata used to recheck contract wallets and registry
//! permissions; it cannot authorize a new sign-in.

use std::{
    collections::{HashMap, VecDeque},
    path::Path,
    sync::Arc,
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path as RoutePath, Request, State, rejection::JsonRejection},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use psky_credentials::{Error as CredentialError, Store};
use psky_farcaster_auth::{
    AuthClient, AuthConfig, AuthError, Challenge, ChannelStatus, SignedProof, VerifiedIdentity,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, MutexGuard};

use crate::{journal, settings::AccountSettings};

const CHALLENGE_TTL: u64 = 300;
const GRANT_TTL: u64 = 600;
const AUTHORITY_CACHE: u64 = 30;
const MAX_PENDING: usize = 8;

/// One worker's account service. Private credentials survive process restarts.
pub struct AccountNode {
    core: Mutex<Core>,
    listener: std::net::SocketAddr,
}

struct Core {
    settings: AccountSettings,
    store: Store,
    pending: HashMap<String, Pending>,
    grants: HashMap<String, u64>,
    start_times: Vec<u64>,
    password_times: Vec<u64>,
    checked_at: Option<u64>,
    events: VecDeque<Value>,
    next_event: u64,
}

struct Pending {
    poll_hash: String,
    challenge: Challenge,
    channel: String,
    proof: Option<SignedProof>,
    last_poll: u64,
    completion: Option<Value>,
}

#[derive(Serialize, Deserialize)]
struct Evidence {
    identity: VerifiedIdentity,
    proof: SignedProof,
}

/// Guard that makes persisted configuration changes atomic with login policy.
pub(crate) struct ConfigurationGuard<'a>(MutexGuard<'a, Core>);

impl ConfigurationGuard<'_> {
    pub(crate) fn check(&self, settings: &AccountSettings) -> Result<(), &'static str> {
        settings
            .validate()
            .map_err(|_| "Invalid account configuration")?;
        if let Some(account) = self
            .0
            .store
            .account()
            .map_err(|_| "Cannot read account binding")?
            && (settings.allowed_fid != Some(account.fid)
                || settings
                    .identity()
                    .map_err(|_| "A bound account needs its original service URL")?
                    != account.identity)
        {
            return Err("The bound FID and service identity cannot be changed on this node");
        }
        Ok(())
    }

    pub(crate) fn apply(&mut self, settings: AccountSettings) {
        if self.0.settings != settings {
            self.0.settings = settings;
            self.0.pending.clear();
            self.0.grants.clear();
            self.0.checked_at = None;
        }
    }
}

impl AccountNode {
    /// Open the private credential store without generating an account or key.
    pub fn open(
        path: &Path,
        settings: AccountSettings,
        listener: std::net::SocketAddr,
    ) -> anyhow::Result<Arc<Self>> {
        settings.validate()?;
        let store = Store::open(path)?;
        if let Some(account) = store.account()? {
            anyhow::ensure!(
                settings.allowed_fid == Some(account.fid)
                    && settings.identity()? == account.identity,
                "saved account configuration conflicts with its established identity"
            );
        }
        let core = Core {
            settings,
            store,
            pending: HashMap::new(),
            grants: HashMap::new(),
            start_times: Vec::new(),
            password_times: Vec::new(),
            checked_at: None,
            events: VecDeque::new(),
            next_event: 1,
        };
        let node = Arc::new(Self {
            core: Mutex::new(core),
            listener,
        });
        Ok(node)
    }

    pub(crate) async fn configuration(&self) -> ConfigurationGuard<'_> {
        ConfigurationGuard(self.core.lock().await)
    }

    /// Public-safe status. No relay capabilities, proofs, passwords or keys.
    pub async fn status(&self) -> Value {
        match self.core.try_lock() {
            Ok(core) => core.status(),
            Err(_) => json!({"busy":true,"storage_ready":false,"signer_ready":false}),
        }
    }

    /// Bounded process-local event metadata for the protected management API.
    pub async fn events(&self) -> Value {
        match self.core.try_lock() {
            Ok(core) => json!({"busy":false,"events":core.events}),
            Err(_) => json!({"busy":true,"events":[]}),
        }
    }

    async fn execute(self: &Arc<Self>, operation: Action) -> Result<Value, Failure> {
        let node = self.clone();
        // Accepted work survives a browser disconnect. In particular, a relay
        // completion must be retained before attempting retryable RPC checks.
        tokio::spawn(async move {
            let mut core = node.core.try_lock().map_err(|_| Failure::busy())?;
            let label=operation.label();
            let result=tokio::time::timeout(std::time::Duration::from_secs(25), core.execute(operation))
                .await.unwrap_or_else(|_| Err(Failure::auth(AuthError::Unavailable)));
            let event=json!({"sequence":core.next_event,"at":journal::now(),"event":label,"result":result.as_ref().map(|_|"ok").unwrap_or_else(|error|error.1)});
            core.next_event=core.next_event.saturating_add(1);
            if core.events.len() == 100 { core.events.pop_front(); }
            core.events.push_back(event);
            result
        }).await.map_err(|_| Failure::internal())?
    }

    /// Return the account's genuine, empty signed repository if the DID matches.
    pub async fn repository(&self, did: &str) -> Option<Result<Vec<u8>, CredentialError>> {
        let core = self.core.lock().await;
        let account = core.store.account().ok().flatten()?;
        (core.settings.enabled && account.identity.did == did)
            .then(|| core.store.empty_repository())
    }
}

impl Core {
    fn status(&self) -> Value {
        let account = self.store.account().ok().flatten();
        json!({"enabled":self.settings.enabled,"service_url":self.settings.service_url,
            "handle":self.settings.identity().ok().map(|identity|identity.handle),
            "bound":account.is_some(),"fid":account.as_ref().map(|a|a.fid),
            "account_enabled":account.as_ref().is_some_and(|a|a.enabled),
            "storage_ready":false,"signer_ready":false,"authority_checked_at":self.checked_at})
    }

    fn client(&self) -> Result<AuthClient, Failure> {
        if !self.settings.enabled {
            return Err(Failure::disabled());
        }
        let origin =
            url::Url::parse(&self.settings.service_url).map_err(|_| Failure::disabled())?;
        AuthClient::new(AuthConfig {
            domain: origin[url::Position::BeforeHost..url::Position::AfterPort].to_owned(),
            uri: format!("{}/account", origin.origin().ascii_serialization()),
            relay_url: "https://relay.farcaster.xyz".into(),
            optimism_rpc_url: self.settings.optimism_rpc_url.clone(),
        })
        .map_err(Failure::auth)
    }

    async fn authority(&mut self) -> Result<(), Failure> {
        if !self.settings.enabled {
            return Err(Failure::disabled());
        }
        let now = journal::now();
        if self
            .checked_at
            .is_some_and(|time| now >= time && now - time < AUTHORITY_CACHE)
        {
            return Ok(());
        }
        let account = self.store.account()?.ok_or(CredentialError::NotBound)?;
        if !account.enabled {
            return Err(CredentialError::Disabled.into());
        }
        let raw = self.store.evidence()?.ok_or_else(Failure::unverified)?;
        let mut evidence: Evidence =
            serde_json::from_str(&raw).map_err(|_| Failure::unverified())?;
        if evidence.identity.fid != account.fid
            || fingerprint(&evidence.identity) != account.authority
        {
            return Err(Failure::unverified());
        }
        match self
            .client()?
            .recheck_identity(&evidence.identity, &evidence.proof, now)
            .await
        {
            Ok(identity) => {
                evidence.identity = identity;
                self.store.set_evidence(
                    &serde_json::to_string(&evidence).map_err(|_| Failure::internal())?,
                )?;
                self.checked_at = Some(now);
                Ok(())
            }
            Err(error) => {
                self.checked_at = None;
                if matches!(error, AuthError::Unauthorized | AuthError::InvalidSignature) {
                    self.store.invalidate_authority()?;
                    self.grants.clear();
                }
                Err(Failure::auth(error))
            }
        }
    }

    fn grant(&self, token: &str) -> Result<(), Failure> {
        let now = journal::now();
        if self
            .grants
            .get(&hash(token))
            .is_some_and(|expires| *expires > now)
        {
            Ok(())
        } else {
            Err(Failure(
                StatusCode::UNAUTHORIZED,
                "InvalidToken",
                "Sign in with Farcaster again".into(),
            ))
        }
    }

    async fn execute(&mut self, action: Action) -> Result<Value, Failure> {
        if !self.settings.enabled {
            return Err(Failure::disabled());
        }
        let now = journal::now();
        self.pending
            .retain(|_, pending| pending.challenge.expires_at > now);
        self.grants.retain(|_, expiry| *expiry > now);
        match action {
            Action::Start => {
                limit(&mut self.start_times, now, 60, 5)?;
                if self.pending.len() >= MAX_PENDING {
                    return Err(Failure::busy());
                }
                let challenge = Challenge {
                    nonce: random_token(),
                    created_at: now,
                    expires_at: now + CHALLENGE_TTL,
                };
                let channel = self
                    .client()?
                    .start(&challenge)
                    .await
                    .map_err(Failure::auth)?;
                let id = random_token();
                let poll_token = random_token();
                let svg = qrcode::QrCode::new(channel.auth_url.as_bytes())
                    .map_err(|_| Failure::internal())?
                    .render::<qrcode::render::svg::Color>()
                    .min_dimensions(240, 240)
                    .build();
                let qr = format!(
                    "data:image/svg+xml;base64,{}",
                    base64::engine::general_purpose::STANDARD.encode(svg)
                );
                let response = json!({"request_id":id,"poll_token":poll_token,"auth_url":channel.auth_url,"qr_data_url":qr,"expires_at":challenge.expires_at});
                self.pending.insert(
                    id,
                    Pending {
                        poll_hash: hash(&poll_token),
                        challenge,
                        channel: channel.channel_token,
                        proof: None,
                        last_poll: 0,
                        completion: None,
                    },
                );
                Ok(response)
            }
            Action::Poll(id, token) => {
                let client = self.client()?;
                let pending = self.pending.get_mut(&id).ok_or_else(Failure::unverified)?;
                if hash(&token) != pending.poll_hash {
                    return Err(Failure::unverified());
                }
                if let Some(completion) = &pending.completion {
                    return Ok(completion.clone());
                }
                if now.saturating_sub(pending.last_poll) < 2 {
                    return Err(Failure::busy());
                }
                pending.last_poll = now;
                if pending.proof.is_none() {
                    match client
                        .status(&pending.channel)
                        .await
                        .map_err(Failure::auth)?
                    {
                        ChannelStatus::Pending => return Ok(json!({"status":"pending"})),
                        ChannelStatus::Completed(proof) => pending.proof = Some(proof),
                    }
                }
                let proof = pending.proof.as_ref().ok_or_else(Failure::unverified)?;
                let verified = client
                    .verify(proof, &pending.challenge, journal::now())
                    .await
                    .map_err(Failure::auth)?;
                if journal::now() >= pending.challenge.expires_at {
                    self.pending.remove(&id);
                    return Err(Failure::unverified());
                }
                if self.settings.allowed_fid != Some(verified.fid) {
                    self.pending.remove(&id);
                    return Err(Failure(
                        StatusCode::FORBIDDEN,
                        "AccountNotAllowed",
                        "This FID is not permitted on this node".into(),
                    ));
                }
                if let Some(raw) = self.store.evidence()? {
                    let previous: Evidence =
                        serde_json::from_str(&raw).map_err(|_| Failure::unverified())?;
                    if verified.checked_block < previous.identity.checked_block
                        || (verified.checked_block == previous.identity.checked_block
                            && verified.block_hash != previous.identity.block_hash)
                    {
                        return Err(Failure::auth(AuthError::InvalidChainEvidence));
                    }
                }
                let authority = fingerprint(&verified);
                if let Some(account) = self.store.account()?
                    && account.authority != authority
                {
                    self.store.invalidate_authority()?;
                    self.grants.clear();
                }
                let identity = self.settings.identity().map_err(|_| Failure::disabled())?;
                let account = self
                    .store
                    .bind_verified(verified.fid, &authority, identity)?;
                let evidence = Evidence {
                    identity: verified,
                    proof: proof.clone(),
                };
                self.store.set_evidence(
                    &serde_json::to_string(&evidence).map_err(|_| Failure::internal())?,
                )?;
                self.checked_at = Some(journal::now());
                let account_token = random_token();
                self.grants.insert(hash(&account_token), now + GRANT_TTL);
                let response = json!({"status":"complete","account_token":account_token,"fid":account.fid,"handle":account.identity.handle,"service_url":account.identity.service_url,"expires_at":now + GRANT_TTL});
                // Completion is idempotent for this poll capability, not another login.
                pending.proof = None;
                pending.channel.clear();
                pending.completion = Some(response.clone());
                Ok(response)
            }
            Action::Passwords(token) => {
                self.grant(&token)?;
                self.authority().await?;
                self.grant(&token)?;
                Ok(json!({"passwords":self.store.list_passwords()?}))
            }
            Action::Issue(token, name) => {
                self.grant(&token)?;
                self.authority().await?;
                self.grant(&token)?;
                let issued = self.store.issue_password(&name)?;
                let account = self.store.account()?.ok_or(CredentialError::NotBound)?;
                let mut value = serde_json::to_value(issued).map_err(|_| Failure::internal())?;
                value["handle"] = json!(account.identity.handle);
                value["service_url"] = json!(account.identity.service_url);
                Ok(value)
            }
            Action::Revoke(token, name) => {
                self.grant(&token)?;
                // Local revocation remains available during an RPC outage.
                self.store.revoke_password(&name)?;
                Ok(json!({}))
            }
            Action::Login(identifier, password) => {
                limit(&mut self.password_times, now, 60, 20)?;
                // Invalid guesses do not cause upstream RPC work.
                self.store.validate_password(&identifier, &password)?;
                self.authority().await?;
                let session = self.store.authenticate(&identifier, &password)?;
                serde_json::to_value(session).map_err(|_| Failure::internal())
            }
            Action::Session(token) => {
                let session = self.store.get_session(&token)?;
                self.authority().await?;
                serde_json::to_value(session).map_err(|_| Failure::internal())
            }
            Action::Refresh(token) => {
                // Validate and recheck before rotating a refresh credential.
                self.store.validate_refresh(&token)?;
                self.authority().await?;
                serde_json::to_value(self.store.refresh_session(&token)?)
                    .map_err(|_| Failure::internal())
            }
            Action::Logout(token) => {
                self.store.delete_session(&token)?;
                Ok(json!({}))
            }
            Action::Describe => {
                let identity = self.settings.identity().map_err(|_| Failure::disabled())?;
                Ok(
                    json!({"did":identity.service_did,"availableUserDomains":[],"inviteCodeRequired":true}),
                )
            }
            Action::Did => self.store.did_document().map_err(Into::into),
            Action::Preferences(token) => {
                self.store.get_session(&token)?;
                self.authority().await?;
                Ok(json!({"preferences":[]}))
            }
        }
    }
}

enum Action {
    Start,
    Poll(String, String),
    Passwords(String),
    Issue(String, String),
    Revoke(String, String),
    Login(String, String),
    Session(String),
    Refresh(String),
    Logout(String),
    Describe,
    Did,
    Preferences(String),
}

impl Action {
    fn label(&self) -> &'static str {
        match self {
            Self::Start => "farcaster_login_start",
            Self::Poll(..) => "farcaster_login_poll",
            Self::Passwords(..) => "password_list",
            Self::Issue(..) => "password_issue",
            Self::Revoke(..) => "password_revoke",
            Self::Login(..) => "session_login",
            Self::Session(..) => "session_check",
            Self::Refresh(..) => "session_refresh",
            Self::Logout(..) => "session_logout",
            Self::Describe => "server_description",
            Self::Did => "identity_read",
            Self::Preferences(..) => "preferences_read",
        }
    }
}

struct Failure(StatusCode, &'static str, String);
impl Failure {
    fn busy() -> Self {
        Self(
            StatusCode::TOO_MANY_REQUESTS,
            "RateLimitExceeded",
            "Account service is busy; retry in a few seconds".into(),
        )
    }
    fn internal() -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AccountStoreError",
            "Account state could not be safely accessed".into(),
        )
    }
    fn disabled() -> Self {
        Self(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountLoginDisabled",
            "Configure and enable Farcaster login in the local management console".into(),
        )
    }
    fn unverified() -> Self {
        Self(
            StatusCode::UNAUTHORIZED,
            "InvalidToken",
            "Farcaster sign-in is missing or expired; sign in again".into(),
        )
    }
    fn auth(error: AuthError) -> Self {
        let unavailable = matches!(
            error,
            AuthError::Unavailable
                | AuthError::InvalidChainEvidence
                | AuthError::InvalidRelayResponse
        );
        Self(
            if unavailable {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::UNAUTHORIZED
            },
            "FarcasterAuthFailed",
            error.to_string(),
        )
    }
}
impl From<CredentialError> for Failure {
    fn from(error: CredentialError) -> Self {
        let (status, code) = match error {
            CredentialError::InvalidCredentials => {
                (StatusCode::UNAUTHORIZED, "AuthenticationRequired")
            }
            CredentialError::InvalidToken => (StatusCode::UNAUTHORIZED, "InvalidToken"),
            CredentialError::ExpiredToken => (StatusCode::UNAUTHORIZED, "ExpiredToken"),
            CredentialError::Disabled => (StatusCode::FORBIDDEN, "AccountTakedown"),
            CredentialError::NotBound => (StatusCode::UNAUTHORIZED, "AccountNotFound"),
            CredentialError::Persistence => return Self::internal(),
            CredentialError::Limit => (StatusCode::TOO_MANY_REQUESTS, "LimitExceeded"),
            CredentialError::BindingConflict => (StatusCode::CONFLICT, "BindingConflict"),
            CredentialError::InvalidInput => (StatusCode::BAD_REQUEST, "InvalidRequest"),
        };
        Self(status, code, error.to_string())
    }
}
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1,"message":self.2}))).into_response()
    }
}

fn random_token() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
fn fingerprint(identity: &VerifiedIdentity) -> String {
    hash(&format!(
        "{}:{}:{}",
        identity.fid, identity.address, identity.custody_address
    ))
}
fn limit(times: &mut Vec<u64>, now: u64, window: u64, capacity: usize) -> Result<(), Failure> {
    times.retain(|time| now.saturating_sub(*time) < window);
    if times.len() >= capacity {
        return Err(Failure::busy());
    }
    times.push(now);
    Ok(())
}
fn bearer(headers: &HeaderMap) -> Result<String, Failure> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| !v.is_empty() && v.len() <= 8192)
        .map(str::to_owned)
        .ok_or_else(Failure::unverified)
}
fn json_input<T>(input: Result<Json<T>, JsonRejection>) -> Result<T, Failure> {
    input.map(|Json(value)| value).map_err(|_| {
        Failure(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Expected a bounded JSON request".into(),
        )
    })
}
async fn respond(
    node: Arc<AccountNode>,
    action: Result<Action, Failure>,
) -> Result<Json<Value>, Failure> {
    Ok(Json(node.execute(action?).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordName {
    name: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Login {
    identifier: String,
    password: String,
    #[serde(default)]
    allow_takendown: bool,
    #[serde(default)]
    auth_factor_token: Option<String>,
}

async fn security(State(node): State<Arc<AccountNode>>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let xrpc = path.starts_with("/xrpc/") || path.starts_with("/.well-known/");
    let settings = match node.core.try_lock() {
        Ok(core) => core.settings.clone(),
        Err(_) => return harden(Failure::busy().into_response(), xrpc),
    };
    let canonical = url::Url::parse(&settings.service_url).ok();
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let canonical_host = canonical
        .as_ref()
        .map(|url| &url[url::Position::BeforeHost..url::Position::AfterPort]);
    let local_host =
        host == node.listener.to_string() || host == format!("localhost:{}", node.listener.port());
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok());
    let same_origin = origin.is_none_or(|value| {
        canonical
            .as_ref()
            .is_some_and(|url| value == url.origin().ascii_serialization())
            || (local_host && value == format!("http://{host}"))
    });
    let allowed = (local_host || canonical_host == Some(host)) && (xrpc || same_origin);
    let response = if !allowed {
        Failure(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "Use the configured account origin".into(),
        )
        .into_response()
    } else if xrpc && req.method() == Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };
    harden(response, xrpc)
}

fn harden(mut response: Response, xrpc: bool) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'".parse().unwrap());
    if xrpc {
        headers.insert("access-control-allow-origin", "*".parse().unwrap());
        headers.insert(
            "access-control-allow-methods",
            "GET, POST, OPTIONS".parse().unwrap(),
        );
        headers.insert(
            "access-control-allow-headers",
            "Authorization, Content-Type, atproto-proxy, atproto-accept-labelers"
                .parse()
                .unwrap(),
        );
    }
    response
}

/// Public account portal and password-session routes, separate from management.
pub fn router(node: Arc<AccountNode>) -> Router {
    Router::new()
        .route("/account", get(|| async { Html(include_str!("account.html")) }))
        .route("/account.js", get(|| async { ([(header::CONTENT_TYPE,"text/javascript; charset=utf-8")], include_str!("account.js")) }))
        .route("/account.css", get(|| async { ([(header::CONTENT_TYPE,"text/css; charset=utf-8")], include_str!("account.css")) }))
        .route("/account/status", get(|State(node): State<Arc<AccountNode>>| async move { Json(node.status().await) }))
        .route("/account/login", post(|State(node): State<Arc<AccountNode>>, input: Result<Json<serde_json::Map<String,Value>>,JsonRejection>| async move {
            json_input(input)?; respond(node, Ok(Action::Start)).await
        }))
        .route("/account/login/{id}", get(|State(node): State<Arc<AccountNode>>, RoutePath(id): RoutePath<String>, headers: HeaderMap| async move { respond(node,bearer(&headers).map(|token|Action::Poll(id,token))).await }))
        .route("/account/passwords", get(|State(node): State<Arc<AccountNode>>, headers: HeaderMap| async move { respond(node,bearer(&headers).map(Action::Passwords)).await })
            .post(|State(node): State<Arc<AccountNode>>, headers: HeaderMap, input: Result<Json<PasswordName>,JsonRejection>| async move { let name=json_input(input)?; respond(node,bearer(&headers).map(|token|Action::Issue(token,name.name))).await })
            .delete(|State(node): State<Arc<AccountNode>>, headers: HeaderMap, input: Result<Json<PasswordName>,JsonRejection>| async move { let name=json_input(input)?; respond(node,bearer(&headers).map(|token|Action::Revoke(token,name.name))).await }))
        .route("/xrpc/com.atproto.server.describeServer", get(|State(node):State<Arc<AccountNode>>| async move {respond(node,Ok(Action::Describe)).await}))
        .route("/xrpc/com.atproto.server.createSession", post(|State(node):State<Arc<AccountNode>>, input:Result<Json<Login>,JsonRejection>| async move {
            let login=json_input(input)?;
            let _ = login.allow_takendown;
            if login.auth_factor_token.is_some_and(|token| !token.is_empty()) { return Err(Failure(StatusCode::BAD_REQUEST,"InvalidRequest","Email authentication factors are not supported".into())); }
            respond(node,Ok(Action::Login(login.identifier,login.password))).await
        }))
        .route("/xrpc/com.atproto.server.getSession", get(|State(node):State<Arc<AccountNode>>, headers:HeaderMap|async move{respond(node,bearer(&headers).map(Action::Session)).await}))
        .route("/xrpc/com.atproto.server.refreshSession", post(|State(node):State<Arc<AccountNode>>, headers:HeaderMap|async move{respond(node,bearer(&headers).map(Action::Refresh)).await}))
        .route("/xrpc/com.atproto.server.deleteSession", post(|State(node):State<Arc<AccountNode>>, headers:HeaderMap|async move{respond(node,bearer(&headers).map(Action::Logout)).await}))
        .route("/xrpc/app.bsky.actor.getPreferences", get(|State(node):State<Arc<AccountNode>>, headers:HeaderMap|async move{respond(node,bearer(&headers).map(Action::Preferences)).await}))
        .route("/.well-known/did.json", get(|State(node):State<Arc<AccountNode>>|async move{respond(node,Ok(Action::Did)).await}))
        .route("/.well-known/atproto-did", get(|State(node):State<Arc<AccountNode>>|async move{
            let document=node.execute(Action::Did).await?;
            Ok::<_,Failure>(([(header::CONTENT_TYPE,"text/plain; charset=utf-8")],document["id"].as_str().ok_or_else(Failure::internal)?.to_owned()))
        }))
        .layer(DefaultBodyLimit::max(16*1024))
        .layer(middleware::from_fn_with_state(node.clone(),security))
        .with_state(node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn settings(port: u16) -> AccountSettings {
        AccountSettings {
            enabled: true,
            service_url: format!("http://localhost:{port}"),
            allowed_fid: Some(8531),
            optimism_rpc_url: "http://localhost:9".into(),
        }
    }

    async fn fixture(dir: &Path) -> (Arc<AccountNode>, String, String) {
        let node =
            AccountNode::open(dir, settings(8787), "127.0.0.1:8787".parse().unwrap()).unwrap();
        let (password, grant) = seed(&node).await;
        (node, password, grant)
    }

    // This helper exists only in unit tests. It bypasses network consent to
    // isolate routing/session behavior; cryptographic proofs have separate fixtures.
    async fn seed(node: &Arc<AccountNode>) -> (String, String) {
        let mut core = node.core.lock().await;
        let identity = core.settings.identity().unwrap();
        core.store
            .bind_verified(8531, "test-authority", identity)
            .unwrap();
        let password = core.store.issue_password("SDK test").unwrap().password;
        let grant = random_token();
        core.grants.insert(hash(&grant), journal::now() + GRANT_TTL);
        core.checked_at = Some(journal::now());
        (password, grant)
    }

    async fn call(
        node: &Arc<AccountNode>,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .uri(path)
            .method(method)
            .header("host", "localhost:8787")
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = router(node.clone())
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    #[tokio::test]
    async fn session_lifecycle_accepts_actual_bluesky_empty_factor_and_rejects_replay() {
        let dir = tempfile::tempdir().unwrap();
        let (node, password, _) = fixture(dir.path()).await;
        let (status,session) = call(&node,"POST","/xrpc/com.atproto.server.createSession",None,json!({"identifier":"psky.test","password":password,"authFactorToken":"","allowTakendown":true})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(session["did"], "did:web:localhost%3A8787");
        assert_eq!(session["handle"], "psky.test");
        let access = session["accessJwt"].as_str().unwrap();
        let refresh = session["refreshJwt"].as_str().unwrap();
        assert_eq!(
            call(
                &node,
                "GET",
                "/xrpc/com.atproto.server.getSession",
                Some(access),
                json!({})
            )
            .await
            .0,
            StatusCode::OK
        );
        let (status, rotated) = call(
            &node,
            "POST",
            "/xrpc/com.atproto.server.refreshSession",
            Some(refresh),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(rotated["refreshJwt"], session["refreshJwt"]);
        assert_eq!(
            call(
                &node,
                "POST",
                "/xrpc/com.atproto.server.refreshSession",
                Some(refresh),
                json!({})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                &node,
                "POST",
                "/xrpc/com.atproto.server.deleteSession",
                rotated["refreshJwt"].as_str(),
                json!({})
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                &node,
                "GET",
                "/xrpc/com.atproto.server.getSession",
                Some(access),
                json!({})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn password_management_requires_grant_and_revoke_kills_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let (node, password, grant) = fixture(dir.path()).await;
        assert_eq!(
            call(&node, "GET", "/account/passwords", None, json!({}))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let (_, session) = call(
            &node,
            "POST",
            "/xrpc/com.atproto.server.createSession",
            None,
            json!({"identifier":"psky.test","password":password}),
        )
        .await;
        assert_eq!(
            call(
                &node,
                "GET",
                "/account/passwords",
                session["accessJwt"].as_str(),
                json!({})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let (_, issued) = call(
            &node,
            "POST",
            "/account/passwords",
            Some(&grant),
            json!({"name":"Phone"}),
        )
        .await;
        assert!(
            issued["password"]
                .as_str()
                .is_some_and(|value| value.len() >= 32)
        );
        let (_, list) = call(&node, "GET", "/account/passwords", Some(&grant), json!({})).await;
        assert!(
            !list
                .to_string()
                .contains(issued["password"].as_str().unwrap())
        );
        assert_eq!(
            call(
                &node,
                "DELETE",
                "/account/passwords",
                Some(&grant),
                json!({"name":"SDK test"})
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                &node,
                "GET",
                "/xrpc/com.atproto.server.getSession",
                session["accessJwt"].as_str(),
                json!({})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn expired_or_wrong_grants_never_issue_passwords() {
        let dir = tempfile::tempdir().unwrap();
        let (node, _, grant) = fixture(dir.path()).await;
        node.core
            .lock()
            .await
            .grants
            .insert(hash(&grant), journal::now());
        for token in [grant, "wrong".into()] {
            assert_eq!(
                call(
                    &node,
                    "POST",
                    "/account/passwords",
                    Some(&token),
                    json!({"name":"No"})
                )
                .await
                .0,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            node.core.lock().await.store.list_passwords().unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn missing_authority_evidence_fails_closed_and_logout_still_works() {
        let dir = tempfile::tempdir().unwrap();
        let (node, password, grant) = fixture(dir.path()).await;
        let (_, session) = call(
            &node,
            "POST",
            "/xrpc/com.atproto.server.createSession",
            None,
            json!({"identifier":"psky.test","password":password}),
        )
        .await;
        node.core.lock().await.checked_at = None;
        assert_eq!(
            call(
                &node,
                "GET",
                "/xrpc/com.atproto.server.getSession",
                session["accessJwt"].as_str(),
                json!({})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                &node,
                "POST",
                "/account/passwords",
                Some(&grant),
                json!({"name":"No"})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                &node,
                "POST",
                "/xrpc/com.atproto.server.deleteSession",
                session["refreshJwt"].as_str(),
                json!({})
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                &node,
                "DELETE",
                "/account/passwords",
                Some(&grant),
                json!({"name":"SDK test"})
            )
            .await
            .0,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn credentials_cannot_be_retrieved_from_status_or_did_document() {
        let dir = tempfile::tempdir().unwrap();
        let (node, password, grant) = fixture(dir.path()).await;
        for path in [
            "/account/status",
            "/.well-known/did.json",
            "/xrpc/com.atproto.server.describeServer",
        ] {
            let (status, value) = call(&node, "GET", path, None, json!({})).await;
            assert_eq!(status, StatusCode::OK);
            assert!(!value.to_string().contains(&password));
            assert!(!value.to_string().contains(&grant));
        }
        assert_eq!(node.status().await["storage_ready"], false);
        let car = node
            .repository("did:web:localhost%3A8787")
            .await
            .unwrap()
            .unwrap();
        assert!(!car.is_empty());
        assert!(node.repository("did:web:other.example").await.is_none());
        let _ = call(&node, "GET", "/account/passwords", Some(&grant), json!({})).await;
        let events = node.events().await.to_string();
        assert!(!events.contains(&grant));
        assert!(!events.contains(&password));
    }

    #[tokio::test]
    async fn host_origin_and_cors_boundaries_are_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let (node, _, _) = fixture(dir.path()).await;
        for (path, host, origin, status) in [
            (
                "/account/status",
                "attacker.example",
                "http://attacker.example",
                403,
            ),
            (
                "/account/status",
                "localhost:8787",
                "https://attacker.example",
                403,
            ),
            (
                "/account/status",
                "localhost:8787",
                "http://localhost:8787",
                200,
            ),
            (
                "/xrpc/com.atproto.server.describeServer",
                "localhost:8787",
                "https://bsky.app",
                200,
            ),
        ] {
            let response = router(node.clone())
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("host", host)
                        .header("origin", origin)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status);
        }
        let response = router(node)
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/xrpc/com.atproto.server.createSession")
                    .header("host", "localhost:8787")
                    .header("origin", "https://bsky.app")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert!(
            response
                .headers()
                .get("access-control-allow-credentials")
                .is_none()
        );
    }

    #[tokio::test]
    async fn configuration_changes_clear_transient_credentials_and_freeze_bound_identity() {
        let dir = tempfile::tempdir().unwrap();
        let (node, _, grant) = fixture(dir.path()).await;
        let mut config = node.configuration().await;
        let mut changed = settings(8787);
        changed.allowed_fid = Some(1);
        assert!(config.check(&changed).is_err());
        changed = settings(8787);
        changed.service_url = "https://pds.example".into();
        assert!(config.check(&changed).is_err());
        changed = settings(8787);
        changed.enabled = false;
        assert!(config.check(&changed).is_ok());
        config.apply(changed);
        assert!(config.0.grant(&grant).is_err());
        drop(config);
        assert_eq!(
            call(
                &node,
                "POST",
                "/xrpc/com.atproto.server.createSession",
                None,
                json!({"identifier":"psky.test","password":"any"})
            )
            .await
            .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn restart_does_not_restore_grants_or_assume_authority_is_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let (node, _, grant) = fixture(dir.path()).await;
        drop(node);
        let reopened = AccountNode::open(
            dir.path(),
            settings(8787),
            "127.0.0.1:8787".parse().unwrap(),
        )
        .unwrap();
        assert!(reopened.core.lock().await.checked_at.is_none());
        assert!(reopened.core.lock().await.grant(&grant).is_err());
        assert_eq!(reopened.status().await["bound"], true);
        assert!(
            AccountNode::open(
                dir.path(),
                settings(8789),
                "127.0.0.1:8789".parse().unwrap()
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn invalid_requests_and_password_attempts_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let (node, _, _) = fixture(dir.path()).await;
        for _ in 0..20 {
            assert_eq!(
                call(
                    &node,
                    "POST",
                    "/xrpc/com.atproto.server.createSession",
                    None,
                    json!({"identifier":"psky.test","password":"wrong"})
                )
                .await
                .0,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            call(
                &node,
                "POST",
                "/xrpc/com.atproto.server.createSession",
                None,
                json!({"identifier":"psky.test","password":"wrong"})
            )
            .await
            .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            call(
                &node,
                "POST",
                "/xrpc/com.atproto.server.createSession",
                None,
                json!({"identifier":"psky.test","password":"wrong","authFactorToken":"123456"})
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &node,
                "POST",
                "/account/passwords",
                None,
                json!({"name":"x".repeat(20_000)})
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(&node, "GET", "/account/login/missing", None, json!({}))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn pending_completion_requires_its_capability_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let (node, _, _) = fixture(dir.path()).await;
        node.core.lock().await.pending.insert(
            "test-id".into(),
            Pending {
                poll_hash: hash("poll-secret"),
                challenge: Challenge {
                    nonce: random_token(),
                    created_at: journal::now(),
                    expires_at: journal::now() + 300,
                },
                channel: String::new(),
                proof: None,
                last_poll: 0,
                completion: Some(json!({"status":"complete","account_token":"already-issued"})),
            },
        );
        assert_eq!(
            call(
                &node,
                "GET",
                "/account/login/test-id",
                Some("wrong"),
                json!({})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let first = call(
            &node,
            "GET",
            "/account/login/test-id",
            Some("poll-secret"),
            json!({}),
        )
        .await;
        let second = call(
            &node,
            "GET",
            "/account/login/test-id",
            Some("poll-secret"),
            json!({}),
        )
        .await;
        assert_eq!(first, second);
        assert_eq!(first.0, StatusCode::OK);
    }

    #[test]
    fn account_origins_and_allowlist_are_validated_before_persistence() {
        assert!(AccountSettings::default().validate().is_ok());
        assert!(settings(8787).validate().is_ok());
        let mut valid = settings(8787);
        valid.service_url = "https://pds.psky.org".into();
        assert!(valid.validate().is_ok());
        for value in [
            "https://user:secret@pds.psky.org",
            "http://pds.psky.org",
            "https://pds.psky.org/path",
            "https://pds.psky.org?token=x",
            "https://pds.psky.org#fragment",
            "https://pds.psky.org:123",
            "javascript:alert(1)",
            "http://127.0.0.1:8787",
        ] {
            let mut config = settings(8787);
            config.service_url = value.into();
            assert!(config.validate().is_err(), "{value}");
        }
        valid.allowed_fid = None;
        assert!(valid.validate().is_err());
    }

    #[tokio::test]
    async fn busy_authority_checks_do_not_queue_management_status_or_public_requests() {
        let dir = tempfile::tempdir().unwrap();
        let (node, _, _) = fixture(dir.path()).await;
        let _guard = node.core.lock().await;
        assert_eq!(node.status().await["busy"], true);
        assert_eq!(node.events().await["busy"], true);
        assert_eq!(
            call(&node, "GET", "/account/status", None, json!({}))
                .await
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn authority_fingerprint_tracks_principal_not_permission_route_or_block() {
        use psky_farcaster_auth::{ProofKind, WalletKind};
        let original = VerifiedIdentity {
            fid: 8531,
            address: format!("0x{}", "11".repeat(20)),
            custody_address: format!("0x{}", "22".repeat(20)),
            wallet_kind: WalletKind::Eoa,
            proof_kind: ProofKind::AuthAddress,
            checked_block: 1,
            block_hash: "01".repeat(32),
            checked_at: 1,
        };
        let mut updated = original.clone();
        updated.checked_block = 2;
        updated.checked_at = 2;
        updated.proof_kind = ProofKind::Custody;
        assert_eq!(fingerprint(&original), fingerprint(&updated));
        updated.custody_address = format!("0x{}", "33".repeat(20));
        assert_ne!(fingerprint(&original), fingerprint(&updated));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires npm ci --ignore-scripts in crates/psky/interop; no live identity or network writes"]
    async fn official_password_session_sdk() {
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let node = AccountNode::open(dir.path(), settings(address.port()), address).unwrap();
        let (password, _) = seed(&node).await;
        let input=json!({"service":format!("http://localhost:{}",address.port()),"identifier":"psky.test","password":password,"did":format!("did:web:localhost%3A{}",address.port())}).to_string();
        let service = tokio::spawn(async move {
            axum::serve(listener, router(node)).await.unwrap();
        });
        let output = tokio::task::spawn_blocking(move || {
            let mut child = Command::new("node")
                .arg("verify-session.mjs")
                .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/interop"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
            child.wait_with_output().unwrap()
        })
        .await
        .unwrap();
        service.abort();
        assert!(
            output.status.success(),
            "official SDK smoke failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("passed"));
    }
}
