//! Private, single-account credentials for the legacy AT Protocol login flow.
//!
//! A caller must verify Farcaster authority before [`Store::bind_verified`].
//! This crate does not verify that proof, publish a DID, delegate a Farcaster
//! signer, proxy an AppView, or write any user content. Its empty repository
//! contains no fixture identity or test key. Credentials and keys are local
//! private metadata, not content reconstructed from Hypersnap.
//!
//! Passwords contain 256 uniformly random bits. A salted SHA-256 verifier is
//! appropriate for this generated-only format: even an offline attacker faces
//! a 256-bit preimage search. User-selected passwords are deliberately not an
//! API. A password grants session access, never local management access or the
//! ability to mint additional passwords. Refresh rotation and revocation use
//! SQLite transactions; access tokens are checked against live session state.

use std::{
    fs::{self, OpenOptions},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use psky_repo::{RecordSet, RepoSigner, Repository};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Maximum simultaneously valid app passwords for this single account.
pub const MAX_PASSWORDS: u64 = 16;
/// Maximum simultaneously valid sessions for this single account.
pub const MAX_SESSIONS: u64 = 64;
/// Short access-token lifetime, in seconds.
pub const ACCESS_SECONDS: u64 = 30 * 60;
/// Maximum refresh-token lifetime, in seconds.
pub const REFRESH_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Fixed errors which never contain passwords, tokens, keys, or database paths.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// An identity, password name, or bounded argument is invalid.
    #[error("invalid credential configuration")]
    InvalidInput,
    /// Login failed without revealing whether an identifier exists.
    #[error("Invalid identifier or password")]
    InvalidCredentials,
    /// A token failed verification, was rotated, or was revoked.
    #[error("Token is invalid")]
    InvalidToken,
    /// A cryptographically valid token has expired.
    #[error("Token has expired")]
    ExpiredToken,
    /// Farcaster authority has not yet been bound to an account.
    #[error("no verified account is configured")]
    NotBound,
    /// Authority invalidation has disabled this account.
    #[error("account authority must be verified again")]
    Disabled,
    /// A different FID, authority, or identity cannot replace the binding.
    #[error("account binding conflicts with the existing identity")]
    BindingConflict,
    /// The bounded password or session budget was reached.
    #[error("credential limit reached")]
    Limit,
    /// Private storage is unavailable, unsafe, or malformed.
    #[error("private credential storage is unavailable")]
    Persistence,
}

impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Persistence
    }
}

/// Public identity chosen by the operator before Farcaster verification.
///
/// Configuration is not proof of domain control. Callers must separately
/// verify public DID and handle resolution before claiming network readiness.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// A normalized DNS handle, or a `.test` handle for explicit local development.
    pub handle: String,
    /// A hostname-only `did:web` account identifier, or the localhost development form.
    pub did: String,
    /// Public PDS origin, or an explicit loopback origin for development.
    pub service_url: String,
    /// Hostname-only `did:web` identifier of the PDS issuing session tokens.
    pub service_did: String,
}

impl Identity {
    /// Validate the supported single-account identity configuration.
    pub fn validate(&self) -> Result<(), Error> {
        let url = url::Url::parse(&self.service_url).map_err(|_| Error::InvalidInput)?;
        if url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.host_str().is_none()
            || !valid_hostname(&self.handle)
        {
            return Err(Error::InvalidInput);
        }
        if url.scheme() == "http" && url.host_str() == Some("localhost") {
            let local_did = format!(
                "did:web:localhost{}",
                url.port()
                    .map(|port| format!("%3A{port}"))
                    .unwrap_or_default()
            );
            return if self.did == local_did
                && self.service_did == local_did
                && self.handle.ends_with(".test")
                && url.port() != Some(0)
            {
                Ok(())
            } else {
                Err(Error::InvalidInput)
            };
        }
        let did_host = self
            .did
            .strip_prefix("did:web:")
            .ok_or(Error::InvalidInput)?;
        let service_host = self
            .service_did
            .strip_prefix("did:web:")
            .ok_or(Error::InvalidInput)?;
        if !valid_hostname(did_host)
            || self.handle != did_host
            || !valid_hostname(service_host)
            || self.handle.ends_with(".test")
            || service_host.ends_with(".test")
        {
            return Err(Error::InvalidInput);
        }
        if url.scheme() != "https" || url.port().is_some() || url.host_str() != Some(service_host) {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}

/// Public account state with no credentials or secret key bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    /// Verified Farcaster identifier, fixed for the store's lifetime.
    pub fid: u64,
    /// Fingerprint of the verified Farcaster authority, not a bearer secret.
    pub authority: String,
    /// Configured public identity.
    pub identity: Identity,
    /// Whether this account may authenticate.
    pub enabled: bool,
    /// Unix time at initial account creation.
    pub created_at: u64,
    /// Multicodec secp256k1 public key in base58btc.
    pub public_key_multibase: String,
    /// Stable initial repository revision.
    pub repo_revision: String,
    /// Stable signed empty repository root CID.
    pub repo_cid: String,
}

/// A password's public metadata. Plaintext is never retained in the store.
#[derive(Clone, Debug, Serialize)]
pub struct PasswordInfo {
    /// Operator-supplied display name.
    pub name: String,
    /// Unix time at issuance.
    pub created_at: u64,
}

/// One-time-display response, deliberately without a `Debug` implementation.
#[derive(Serialize)]
pub struct IssuedPassword {
    /// Public metadata for subsequent listing and revocation.
    #[serde(flatten)]
    pub info: PasswordInfo,
    /// Random plaintext password. The caller must display it only once.
    pub password: String,
}

/// Non-secret standard `getSession` response.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    /// Configured DNS handle.
    pub handle: String,
    /// Account DID.
    pub did: String,
    /// Account DID document containing its actual public signing key.
    pub did_doc: Value,
    /// Always false: this flow does not assert a verified email address.
    pub email_confirmed: bool,
    /// Always false: Farcaster proof is not an email second factor.
    pub email_auth_factor: bool,
    /// The account is enabled in this PDS, not a claim of federation readiness.
    pub active: bool,
}

/// Standard create/refresh response, deliberately without `Debug`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    /// Short-lived access credential.
    pub access_jwt: String,
    /// Single-use rotating refresh credential.
    pub refresh_jwt: String,
    /// Public account information.
    #[serde(flatten)]
    pub info: SessionInfo,
}

/// Durable private credentials for one verified Farcaster account.
///
/// The store is synchronous. Callers should serialize access and move blocking
/// disk operations off their async executor as appropriate. No `Debug` or key
/// export API exists. The private subdirectory must not be served over HTTP.
pub struct Store {
    connection: Connection,
    jwt_key: Zeroizing<Vec<u8>>,
    #[cfg(test)]
    clock: Option<u64>,
}

impl Store {
    /// Open or atomically initialize `credentials/state.sqlite3` below an existing data directory.
    ///
    /// Existing symlinks, non-directories, non-files, and group/world-accessible
    /// credential storage are rejected on Unix. Only this private subdirectory
    /// is created with restrictive permissions; unrelated files are untouched.
    pub fn open(data_dir: &Path) -> Result<Self, Error> {
        let directory = data_dir.join("credentials");
        prepare_directory(&directory)?;
        let path = directory.join("state.sqlite3");
        prepare_database(&path)?;
        let mut connection = Connection::open(&path)?;
        connection.busy_timeout(Duration::from_secs(3))?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;",
        )?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: u64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > 1 {
            return Err(Error::Persistence);
        }
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY CHECK(id=1), jwt_key BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS account (id INTEGER PRIMARY KEY CHECK(id=1), document TEXT NOT NULL, repo_key BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS passwords (name TEXT PRIMARY KEY, salt BLOB NOT NULL, verifier BLOB NOT NULL, created_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, password_name TEXT NOT NULL REFERENCES passwords(name) ON DELETE CASCADE, refresh_jti TEXT NOT NULL, refresh_exp INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY CHECK(id=1), document TEXT NOT NULL);
             PRAGMA user_version=1;",
        )?;
        let key: Option<Vec<u8>> = tx
            .query_row("SELECT jwt_key FROM secrets WHERE id=1", [], |row| {
                row.get(0)
            })
            .optional()?;
        let jwt_key = match key {
            Some(key) if key.len() == 32 => Zeroizing::new(key),
            Some(_) => return Err(Error::Persistence),
            None => {
                let key = Zeroizing::new(random_bytes().to_vec());
                tx.execute(
                    "INSERT INTO secrets(id,jwt_key) VALUES(1,?1)",
                    params![key.as_slice()],
                )?;
                key
            }
        };
        tx.commit()?;
        let store = Self {
            connection,
            jwt_key,
            #[cfg(test)]
            clock: None,
        };
        if let Some(account) = store.account()? {
            account
                .identity
                .validate()
                .map_err(|_| Error::Persistence)?;
            if account.fid == 0 || !valid_authority(&account.authority) {
                return Err(Error::Persistence);
            }
            let repo = store.repository()?;
            if repo.root().to_string() != account.repo_cid {
                return Err(Error::Persistence);
            }
        }
        Ok(store)
    }

    /// Return public binding state, or `None` before successful verification.
    pub fn account(&self) -> Result<Option<Account>, Error> {
        load_account(&self.connection)
    }

    /// Persist caller-verified identity proof for later authority revalidation.
    ///
    /// This opaque metadata is private and limited to 32 KiB. It is never
    /// included in account or session responses. The caller owns proof format,
    /// signature validation, freshness, and the policy for issuing credentials.
    pub fn set_evidence(&mut self, document: &str) -> Result<(), Error> {
        if document.is_empty() || document.len() > 32 * 1024 {
            return Err(Error::InvalidInput);
        }
        enabled_account(&self.connection)?;
        self.connection.execute("INSERT INTO evidence(id,document) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET document=excluded.document", [document])?;
        Ok(())
    }

    /// Read private proof metadata for the caller's revalidation policy.
    pub fn evidence(&self) -> Result<Option<String>, Error> {
        let document: Option<String> = self
            .connection
            .query_row("SELECT document FROM evidence WHERE id=1", [], |row| {
                row.get(0)
            })
            .optional()?;
        if document
            .as_ref()
            .is_some_and(|value| value.len() > 32 * 1024)
        {
            return Err(Error::Persistence);
        }
        Ok(document)
    }

    /// Bind a caller-verified FID and authority to a configured identity.
    ///
    /// Callers must verify a fresh signature and current FID ownership first.
    /// The same binding may re-enable an account. After explicit invalidation,
    /// the same FID and identity may bind a newly verified authority. Neither a
    /// different FID nor a changed identity is silently accepted.
    pub fn bind_verified(
        &mut self,
        fid: u64,
        authority: &str,
        identity: Identity,
    ) -> Result<Account, Error> {
        identity.validate()?;
        if fid == 0 || fid > i64::MAX as u64 || !valid_authority(authority) {
            return Err(Error::InvalidInput);
        }
        let now = self.now();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut account) = load_account(&tx)? {
            if account.fid != fid
                || account.identity != identity
                || (account.enabled && account.authority != authority)
            {
                return Err(Error::BindingConflict);
            }
            account.enabled = true;
            account.authority = authority.into();
            tx.execute(
                "UPDATE account SET document=?1 WHERE id=1",
                [encode_account(&account)?],
            )?;
            tx.commit()?;
            return Ok(account);
        }
        let key = Zeroizing::new(random_bytes());
        let signer = RepoSigner::from_bytes(*key).map_err(|_| Error::Persistence)?;
        let revision = revision(now);
        let repo = Repository::build(&identity.did, &revision, &RecordSet::new(), &signer)
            .map_err(|_| Error::InvalidInput)?;
        let mut multicodec = vec![0xe7, 0x01];
        multicodec.extend(signer.public_key_sec1());
        let account = Account {
            fid,
            authority: authority.into(),
            identity,
            enabled: true,
            created_at: now,
            public_key_multibase: format!("z{}", bs58::encode(multicodec).into_string()),
            repo_revision: revision,
            repo_cid: repo.root().to_string(),
        };
        tx.execute(
            "INSERT INTO account(id,document,repo_key) VALUES(1,?1,?2)",
            params![encode_account(&account)?, key.as_slice()],
        )?;
        tx.commit()?;
        Ok(account)
    }

    /// Disable account authentication and atomically revoke every password and session.
    ///
    /// Invoke this when the verified Farcaster authority changes or is revoked.
    /// A fresh, verified bind is required to re-enable the same identity.
    pub fn invalidate_authority(&mut self) -> Result<(), Error> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut account = load_account(&tx)?.ok_or(Error::NotBound)?;
        account.enabled = false;
        tx.execute(
            "UPDATE account SET document=?1 WHERE id=1",
            [encode_account(&account)?],
        )?;
        tx.execute("DELETE FROM passwords", [])?;
        tx.execute("DELETE FROM evidence", [])?;
        tx.commit()?;
        Ok(())
    }

    /// Create a named random password, returning its plaintext only this once.
    pub fn issue_password(&mut self, name: &str) -> Result<IssuedPassword, Error> {
        if !valid_name(name) {
            return Err(Error::InvalidInput);
        }
        let now = self.now();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        enabled_account(&tx)?;
        let count: u64 = tx.query_row("SELECT COUNT(*) FROM passwords", [], |row| row.get(0))?;
        if count >= MAX_PASSWORDS {
            return Err(Error::Limit);
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM passwords WHERE name=?1)",
            [name],
            |row| row.get(0),
        )?;
        if exists {
            return Err(Error::InvalidInput);
        }
        let password = format!("psky-{}", URL_SAFE_NO_PAD.encode(random_bytes()));
        let salt = random_bytes();
        let verifier = password_hash(&salt, &password);
        tx.execute(
            "INSERT INTO passwords(name,salt,verifier,created_at) VALUES(?1,?2,?3,?4)",
            params![name, salt.as_slice(), verifier.as_slice(), now],
        )?;
        tx.commit()?;
        Ok(IssuedPassword {
            info: PasswordInfo {
                name: name.into(),
                created_at: now,
            },
            password,
        })
    }

    /// List currently valid password metadata without plaintext or verifiers.
    pub fn list_passwords(&self) -> Result<Vec<PasswordInfo>, Error> {
        let mut statement = self
            .connection
            .prepare("SELECT name,created_at FROM passwords ORDER BY created_at,name LIMIT 16")?;
        let items = statement.query_map([], |row| {
            Ok(PasswordInfo {
                name: row.get(0)?,
                created_at: row.get(1)?,
            })
        })?;
        Ok(items.collect::<Result<Vec<_>, _>>()?)
    }

    /// Revoke a named password and every access/refresh session derived from it.
    /// Repeating revocation is harmless.
    pub fn revoke_password(&mut self, name: &str) -> Result<(), Error> {
        if !valid_name(name) {
            return Err(Error::InvalidInput);
        }
        self.connection
            .execute("DELETE FROM passwords WHERE name=?1", [name])?;
        Ok(())
    }

    /// Check an identifier/password without creating a session or writing state.
    ///
    /// Use this before a remote authority check. Authentication must still be
    /// repeated after that check: this read does not reserve authorization.
    pub fn validate_password(&self, identifier: &str, password: &str) -> Result<(), Error> {
        verify_password(&self.connection, identifier, password).map(|_| ())
    }

    /// Authenticate a generated password and create a revocable standard session.
    /// Identifiers may be the configured handle or DID, never arbitrary FIDs.
    pub fn authenticate(&mut self, identifier: &str, password: &str) -> Result<Session, Error> {
        if identifier.len() > 512 || password.len() != 48 || !password.starts_with("psky-") {
            return Err(Error::InvalidCredentials);
        }
        let now = self.now();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (account, name) = verify_password(&tx, identifier, password)?;
        tx.execute("DELETE FROM sessions WHERE refresh_exp<=?1", [now])?;
        let count: u64 = tx.query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))?;
        if count >= MAX_SESSIONS {
            return Err(Error::Limit);
        }
        let sid = random_id();
        let refresh_jti = random_id();
        let expires = now + REFRESH_SECONDS;
        let session = create_session(&self.jwt_key, &account, &sid, &refresh_jti, now, expires)?;
        tx.execute(
            "INSERT INTO sessions(id,password_name,refresh_jti,refresh_exp) VALUES(?1,?2,?3,?4)",
            params![sid, name, refresh_jti, expires],
        )?;
        tx.commit()?;
        Ok(session)
    }

    /// Validate an access token against both its signature and live revocation state.
    pub fn get_session(&self, access: &str) -> Result<SessionInfo, Error> {
        let account = enabled_account(&self.connection).map_err(token_account_error)?;
        let claims = verify_token(
            &self.jwt_key,
            access,
            &account,
            TokenKind::Access,
            self.now(),
        )?;
        validate_session(&self.connection, &claims, false, self.now())?;
        Ok(session_info(&account))
    }

    /// Validate a refresh bearer without consuming or rotating it.
    ///
    /// Callers can reject unauthenticated requests before making remote
    /// Farcaster authority checks. The eventual rotation revalidates this token
    /// inside its transaction, so this read is not an authorization reservation.
    pub fn validate_refresh(&self, refresh: &str) -> Result<SessionInfo, Error> {
        let account = enabled_account(&self.connection).map_err(token_account_error)?;
        let now = self.now();
        let claims = verify_token(&self.jwt_key, refresh, &account, TokenKind::Refresh, now)?;
        validate_session(&self.connection, &claims, true, now)?;
        Ok(session_info(&account))
    }

    /// Atomically consume a refresh token and return a new access/refresh pair.
    /// A rotated refresh token cannot be replayed, including after a restart.
    pub fn refresh_session(&mut self, refresh: &str) -> Result<Session, Error> {
        let now = self.now();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let account = enabled_account(&tx).map_err(token_account_error)?;
        let claims = verify_token(&self.jwt_key, refresh, &account, TokenKind::Refresh, now)?;
        validate_session(&tx, &claims, true, now)?;
        let jti = random_id();
        // Rotation does not extend the absolute session lifetime.
        let session = create_session(&self.jwt_key, &account, &claims.sid, &jti, now, claims.exp)?;
        let changed = tx.execute(
            "UPDATE sessions SET refresh_jti=?1 WHERE id=?2 AND refresh_jti=?3",
            params![jti, claims.sid, claims.jti],
        )?;
        if changed != 1 {
            return Err(Error::InvalidToken);
        }
        tx.commit()?;
        Ok(session)
    }

    /// Revoke the session identified by a currently valid refresh token.
    /// Both token kinds become invalid immediately.
    pub fn delete_session(&mut self, refresh: &str) -> Result<(), Error> {
        let now = self.now();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let account = enabled_account(&tx).map_err(token_account_error)?;
        let claims = verify_token(&self.jwt_key, refresh, &account, TokenKind::Refresh, now)?;
        validate_session(&tx, &claims, true, now)?;
        tx.execute("DELETE FROM sessions WHERE id=?1", [&claims.sid])?;
        tx.commit()?;
        Ok(())
    }

    /// Build the stable, genuinely signed empty account repository.
    /// This never includes or publishes user content.
    pub fn repository(&self) -> Result<Repository, Error> {
        let account = self.account()?.ok_or(Error::NotBound)?;
        let bytes: Vec<u8> =
            self.connection
                .query_row("SELECT repo_key FROM account WHERE id=1", [], |row| {
                    row.get(0)
                })?;
        let bytes = Zeroizing::new(bytes);
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Persistence)?;
        let signer = RepoSigner::from_bytes(key).map_err(|_| Error::Persistence)?;
        Repository::build(
            &account.identity.did,
            &account.repo_revision,
            &RecordSet::new(),
            &signer,
        )
        .map_err(|_| Error::Persistence)
    }

    /// Export the stable signed empty repository as CARv1.
    pub fn empty_repository(&self) -> Result<Vec<u8>, Error> {
        self.repository()?.to_car().map_err(|_| Error::Persistence)
    }

    /// Return the locally configured DID document, without claiming public resolution.
    pub fn did_document(&self) -> Result<Value, Error> {
        self.account()?
            .map(|account| did_document(&account))
            .ok_or(Error::NotBound)
    }

    fn now(&self) -> u64 {
        #[cfg(test)]
        if let Some(now) = self.clock {
            return now;
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

fn valid_hostname(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && host.rsplit('.').next().is_some_and(|tld| {
            tld.as_bytes()[0].is_ascii_alphabetic()
                && !matches!(tld, "arpa" | "invalid" | "local" | "onion")
        })
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.trim() == name
        && name.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn valid_authority(authority: &str) -> bool {
    !authority.is_empty()
        && authority.len() <= 128
        && authority
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":_-".contains(&byte))
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn random_id() -> String {
    hex::encode(random_bytes())
}

fn password_hash(salt: &[u8], password: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"PurpleSky generated app password v1\0");
    digest.update(salt);
    digest.update(password.as_bytes());
    digest.finalize().into()
}

fn verify_password(
    connection: &Connection,
    identifier: &str,
    password: &str,
) -> Result<(Account, String), Error> {
    if identifier.len() > 512 || password.len() != 48 || !password.starts_with("psky-") {
        return Err(Error::InvalidCredentials);
    }
    let account = enabled_account(connection).map_err(|error| match error {
        Error::Persistence => error,
        _ => Error::InvalidCredentials,
    })?;
    let mut statement = connection.prepare("SELECT name,salt,verifier FROM passwords LIMIT 16")?;
    let mut rows = statement.query([])?;
    let mut matched = None;
    while let Some(row) = rows.next()? {
        let name: String = row.get(0)?;
        let salt: Vec<u8> = row.get(1)?;
        let verifier: Vec<u8> = row.get(2)?;
        if salt.len() != 32 || verifier.len() != 32 {
            return Err(Error::Persistence);
        }
        if bool::from(
            password_hash(&salt, password)
                .as_slice()
                .ct_eq(verifier.as_slice()),
        ) {
            matched = Some(name);
        }
    }
    if identifier != account.identity.handle && identifier != account.identity.did {
        return Err(Error::InvalidCredentials);
    }
    Ok((account, matched.ok_or(Error::InvalidCredentials)?))
}

fn load_account(connection: &Connection) -> Result<Option<Account>, Error> {
    let document: Option<String> = connection
        .query_row("SELECT document FROM account WHERE id=1", [], |row| {
            row.get(0)
        })
        .optional()?;
    document
        .map(|document| {
            if document.len() > 8192 {
                return Err(Error::Persistence);
            }
            serde_json::from_str(&document).map_err(|_| Error::Persistence)
        })
        .transpose()
}

fn enabled_account(connection: &Connection) -> Result<Account, Error> {
    let account = load_account(connection)?.ok_or(Error::NotBound)?;
    if !account.enabled {
        return Err(Error::Disabled);
    }
    Ok(account)
}

fn token_account_error(error: Error) -> Error {
    match error {
        Error::Persistence => error,
        _ => Error::InvalidToken,
    }
}

fn encode_account(account: &Account) -> Result<String, Error> {
    serde_json::to_string(account).map_err(|_| Error::Persistence)
}

fn did_document(account: &Account) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": account.identity.did,
        "alsoKnownAs": [format!("at://{}", account.identity.handle)],
        "verificationMethod": [{"id": format!("{}#atproto", account.identity.did), "type": "Multikey", "controller": account.identity.did, "publicKeyMultibase": account.public_key_multibase}],
        "service": [{"id": format!("{}#atproto_pds", account.identity.did), "type": "AtprotoPersonalDataServer", "serviceEndpoint": account.identity.service_url}]
    })
}

fn session_info(account: &Account) -> SessionInfo {
    SessionInfo {
        handle: account.identity.handle.clone(),
        did: account.identity.did.clone(),
        did_doc: did_document(account),
        email_confirmed: false,
        email_auth_factor: false,
        active: account.enabled,
    }
}

#[derive(Clone, Copy)]
enum TokenKind {
    Access,
    Refresh,
}

impl TokenKind {
    fn typ(self) -> &'static str {
        match self {
            Self::Access => "at+jwt",
            Self::Refresh => "refresh+jwt",
        }
    }
    fn scope(self) -> &'static str {
        match self {
            Self::Access => "com.atproto.appPass",
            Self::Refresh => "com.atproto.refresh",
        }
    }
    fn lifetime(self) -> u64 {
        match self {
            Self::Access => ACCESS_SECONDS,
            Self::Refresh => REFRESH_SECONDS,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    sub: String,
    aud: String,
    scope: String,
    iat: u64,
    exp: u64,
    jti: String,
    sid: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
}

fn create_session(
    key: &[u8],
    account: &Account,
    sid: &str,
    refresh_jti: &str,
    now: u64,
    refresh_exp: u64,
) -> Result<Session, Error> {
    let claims = |kind: TokenKind, jti: &str, exp: u64| Claims {
        sub: account.identity.did.clone(),
        aud: account.identity.service_did.clone(),
        scope: kind.scope().into(),
        iat: now,
        exp,
        jti: jti.into(),
        sid: sid.into(),
    };
    let access = claims(
        TokenKind::Access,
        &random_id(),
        (now + ACCESS_SECONDS).min(refresh_exp),
    );
    let refresh = claims(TokenKind::Refresh, refresh_jti, refresh_exp);
    Ok(Session {
        access_jwt: sign_token(key, &access, TokenKind::Access)?,
        refresh_jwt: sign_token(key, &refresh, TokenKind::Refresh)?,
        info: session_info(account),
    })
}

fn sign_token(key: &[u8], claims: &Claims, kind: TokenKind) -> Result<String, Error> {
    let header = Header {
        alg: "HS256".into(),
        typ: kind.typ().into(),
    };
    let encode = |value: &Value| {
        serde_json::to_vec(value)
            .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
            .map_err(|_| Error::Persistence)
    };
    let input = format!("{}.{}", encode(&json!(header))?, encode(&json!(claims))?);
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Persistence)?;
    mac.update(input.as_bytes());
    Ok(format!(
        "{}.{}",
        input,
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

fn verify_token(
    key: &[u8],
    token: &str,
    account: &Account,
    kind: TokenKind,
    now: u64,
) -> Result<Claims, Error> {
    if token.len() > 4096 {
        return Err(Error::InvalidToken);
    }
    let mut parts = token.split('.');
    let (Some(header), Some(body), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::InvalidToken);
    };
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| Error::InvalidToken)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Persistence)?;
    mac.update(format!("{header}.{body}").as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| Error::InvalidToken)?;
    let header: Header = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header)
            .map_err(|_| Error::InvalidToken)?,
    )
    .map_err(|_| Error::InvalidToken)?;
    if header.alg != "HS256" || header.typ != kind.typ() {
        return Err(Error::InvalidToken);
    }
    let claims: Claims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| Error::InvalidToken)?,
    )
    .map_err(|_| Error::InvalidToken)?;
    if claims.sub != account.identity.did
        || claims.aud != account.identity.service_did
        || claims.scope != kind.scope()
        || claims.iat > now
        || claims.exp <= claims.iat
        || claims.exp - claims.iat > kind.lifetime()
        || claims.sid.len() != 64
        || claims.jti.len() != 64
        || !claims.sid.bytes().all(|b| b.is_ascii_hexdigit())
        || !claims.jti.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::InvalidToken);
    }
    if claims.exp <= now {
        return Err(Error::ExpiredToken);
    }
    Ok(claims)
}

fn validate_session(
    connection: &Connection,
    claims: &Claims,
    refresh: bool,
    now: u64,
) -> Result<(), Error> {
    let value: Option<(String, u64)> = connection
        .query_row(
            "SELECT refresh_jti,refresh_exp FROM sessions WHERE id=?1",
            [&claims.sid],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (jti, expires) = value.ok_or(Error::InvalidToken)?;
    if expires <= now || (refresh && (jti != claims.jti || expires != claims.exp)) {
        return Err(Error::InvalidToken);
    }
    Ok(())
}

fn revision(seconds: u64) -> String {
    const ALPHABET: &[u8] = b"234567abcdefghijklmnopqrstuvwxyz";
    let mut value = seconds.saturating_mul(1_000_000).saturating_mul(1024);
    let mut result = [b'2'; 13];
    for byte in result.iter_mut().rev() {
        *byte = ALPHABET[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8(result.to_vec()).expect("ASCII alphabet")
}

fn prepare_directory(path: &Path) -> Result<(), Error> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err(Error::Persistence),
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::Persistence)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::Persistence);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Persistence);
        }
    }
    Ok(())
}

fn prepare_database(path: &Path) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(file) => file.sync_all().map_err(|_| Error::Persistence)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err(Error::Persistence),
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::Persistence)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::Persistence);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(Error::Persistence);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
