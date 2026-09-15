//! Validated, revisioned node configuration for the management API.
//!
//! [`ConfigStore`] loads `settings.json` from the node's data directory. An
//! existing document takes precedence over bootstrap settings. Replacements
//! require the revision returned by [`ConfigStore::snapshot`], and publish a
//! complete document atomically. The server must serialize access to a store;
//! independent processes must not manage the same data directory concurrently.
//!
//! Files contain operational settings only. Credentials do not belong in node
//! names or endpoint URLs. Errors contain fixed diagnostic text without paths,
//! URLs, or rejected values.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use psky_hypersnap::{
    DEFAULT_MAX_BLOCK_DELAY_SECS, DEFAULT_MAX_RESPONSE_BYTES, MAX_BLOCK_DELAY_SECS,
    MAX_RESPONSE_BYTES, Network, PreflightConfig,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Current settings document format.
pub const SCHEMA_VERSION: u32 = 1;
/// Maximum encoded settings document size, including formatting.
pub const MAX_SETTINGS_BYTES: usize = 32 * 1024;
/// Largest integer that management clients can represent exactly in JSON.
pub const MAX_TEST_FID: u64 = 9_007_199_254_740_991;

/// Complete operator configuration, available through the management API.
///
/// Listener changes take effect after restart. An empty endpoint list is a
/// valid unconfigured node and disables live checks until endpoints are saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Farcaster sign-in and the single hosted account. Disabled by default.
    #[serde(default)]
    pub account: AccountSettings,
    /// Display name, containing 1 through 64 characters and no control codes.
    pub node_name: String,
    /// Explicit Hypersnap HTTP API roots, without credentials or URL queries.
    pub endpoints: Vec<String>,
    /// Expected Farcaster network.
    pub network: Network,
    /// Optional public-read FID, from 1 through the largest safe JSON integer.
    pub test_fid: Option<u64>,
    /// Per-request timeout, from 10 through 30,000 milliseconds.
    pub request_timeout_ms: u64,
    /// Per-response body limit, from 1 through 1,048,576 bytes.
    pub max_response_bytes: usize,
    /// Greatest reported block delay considered within the operator threshold.
    pub max_block_delay_seconds: u64,
    /// Whether the public listener may expose the explicitly offline fixture.
    pub serve_fixture: bool,
    /// Management listener address; only loopback addresses are accepted.
    pub admin_bind: SocketAddr,
    /// Public API listener address, separate from the management listener.
    pub public_bind: SocketAddr,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            account: AccountSettings::default(),
            node_name: "PurpleSky".into(),
            endpoints: Vec::new(),
            network: Network::Mainnet,
            test_fid: None,
            request_timeout_ms: 5_000,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_block_delay_seconds: DEFAULT_MAX_BLOCK_DELAY_SECS,
            serve_fixture: false,
            admin_bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 8788)),
            public_bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 8787)),
        }
    }
}

impl Settings {
    /// Validate settings before persistence or use.
    ///
    /// Remote Hypersnap endpoints require HTTPS. HTTP is permitted only for
    /// literal loopback addresses or `localhost`, including local SSH tunnels.
    /// This validates address syntax, not whether a listener can bind its port.
    pub fn validate(&self) -> Result<(), SettingsError> {
        self.account.validate()?;
        if self.node_name.trim().is_empty()
            || self.node_name.chars().count() > 64
            || self.node_name.chars().any(char::is_control)
        {
            return Err(SettingsError::Invalid(
                "node name must contain 1 through 64 printable characters",
            ));
        }
        if !self.admin_bind.ip().is_loopback() {
            return Err(SettingsError::Invalid("admin listener must bind loopback"));
        }
        if self.admin_bind == self.public_bind && self.admin_bind.port() != 0 {
            return Err(SettingsError::Invalid("listener addresses must differ"));
        }
        if self.public_bind.ip().is_multicast() {
            return Err(SettingsError::Invalid(
                "public listener must not bind a multicast address",
            ));
        }
        if self
            .test_fid
            .is_some_and(|fid| !(1..=MAX_TEST_FID).contains(&fid))
        {
            return Err(SettingsError::Invalid(
                "test FID must be 1 through 9007199254740991",
            ));
        }
        if !(10..=30_000).contains(&self.request_timeout_ms) {
            return Err(SettingsError::Invalid(
                "request timeout must be 10 through 30000 milliseconds",
            ));
        }
        if !(1..=MAX_RESPONSE_BYTES).contains(&self.max_response_bytes) {
            return Err(SettingsError::Invalid(
                "response limit must be 1 through 1048576 bytes",
            ));
        }
        if !(1..=MAX_BLOCK_DELAY_SECS).contains(&self.max_block_delay_seconds) {
            return Err(SettingsError::Invalid(
                "block delay threshold must be 1 through 86400 seconds",
            ));
        }
        if self.endpoints.iter().any(|endpoint| endpoint.len() > 2_048) {
            return Err(SettingsError::Invalid("endpoint URL exceeds length limit"));
        }
        if !self.endpoints.is_empty() {
            self.build_preflight()?;
        }
        Ok(())
    }

    /// Construct the bounded read-only client configuration, if configured.
    pub fn preflight(&self) -> Result<Option<PreflightConfig>, SettingsError> {
        self.validate()?;
        if self.endpoints.is_empty() {
            Ok(None)
        } else {
            self.build_preflight().map(Some)
        }
    }

    fn build_preflight(&self) -> Result<PreflightConfig, SettingsError> {
        PreflightConfig::new(self.endpoints.clone(), self.network, self.test_fid)
            .and_then(|config| {
                config.with_limits(
                    Duration::from_millis(self.request_timeout_ms),
                    self.max_response_bytes,
                )
            })
            .and_then(|config| config.with_max_block_delay_secs(self.max_block_delay_seconds))
            .map_err(|_| SettingsError::Invalid("invalid Hypersnap endpoints or read limits"))
    }
}

/// Public identity and read-only authentication services, managed through the console.
///
/// The initial implementation hosts one FID with a hostname-level `did:web`.
/// Changing its identity after binding is rejected. No publishing key is requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSettings {
    /// Enable the account portal and password/session endpoints.
    pub enabled: bool,
    /// Canonical HTTPS service origin; HTTP loopback is development-only.
    pub service_url: String,
    /// Sole FID permitted to bind this node; required when enabled.
    pub allowed_fid: Option<u64>,
    /// Optimism JSON-RPC origin used to verify current registry authority.
    pub optimism_rpc_url: String,
}

impl Default for AccountSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            service_url: String::new(),
            allowed_fid: None,
            optimism_rpc_url: "https://mainnet.optimism.io".into(),
        }
    }
}

impl AccountSettings {
    /// Validate configuration without sending network requests.
    pub fn validate(&self) -> Result<(), SettingsError> {
        if self
            .allowed_fid
            .is_some_and(|fid| !(1..=MAX_TEST_FID).contains(&fid))
            || (self.enabled && self.allowed_fid.is_none())
        {
            return Err(SettingsError::Invalid(
                "account login requires a permitted FID",
            ));
        }
        if self.service_url.is_empty() && !self.enabled {
            return Self::origin(&self.optimism_rpc_url).map(|_| ());
        }
        let service = Self::origin(&self.service_url)?;
        if service.host_str().is_none_or(|host| host.contains(':')) {
            return Err(SettingsError::Invalid(
                "account service requires a DNS hostname or IPv4 loopback",
            ));
        }
        Self::origin(&self.optimism_rpc_url)?;
        self.identity()?.validate().map_err(|_| {
            SettingsError::Invalid(
                "use a canonical HTTPS hostname, or http://localhost:port for development",
            )
        })?;
        Ok(())
    }

    fn origin(value: &str) -> Result<url::Url, SettingsError> {
        let invalid = || {
            SettingsError::Invalid(
                "account URLs must be HTTPS origins without credentials, paths or queries; HTTP loopback is allowed for development",
            )
        };
        if value.len() > 2048 {
            return Err(invalid());
        }
        let url = url::Url::parse(value).map_err(|_| invalid())?;
        let loopback = url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.host_str().is_none()
        {
            return Err(invalid());
        }
        Ok(url)
    }

    /// Identity derived from the configured origin, without claiming a PLC DID.
    pub fn identity(&self) -> Result<psky_credentials::Identity, SettingsError> {
        let url = Self::origin(&self.service_url)?;
        let host = url
            .host_str()
            .ok_or(SettingsError::Invalid("missing account hostname"))?;
        let authority = match url.port() {
            Some(port) => format!("{host}%3A{port}"),
            None => host.to_owned(),
        };
        Ok(psky_credentials::Identity {
            handle: if host == "localhost" {
                "psky.test".to_owned()
            } else {
                host.to_owned()
            },
            did: format!("did:web:{authority}"),
            service_did: format!("did:web:{authority}"),
            service_url: url.origin().ascii_serialization(),
        })
    }
}

/// Persisted configuration and its optimistic concurrency revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigDocument {
    /// Document format identifier; currently always 1.
    pub schema_version: u32,
    /// Monotonic revision; the first persisted document has revision 1.
    pub revision: u64,
    /// Operator-controlled settings for this revision.
    pub settings: Settings,
}

/// Fixed diagnostics suitable for returning through the management interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsError {
    /// Rejected configuration. No settings have been changed.
    Invalid(&'static str),
    /// The supplied revision is stale, or another writer changed the file.
    Conflict,
    /// The saved configuration could not be read or safely persisted.
    ///
    /// A directory synchronization failure can occur after publication. The
    /// error identifies this case, and the store snapshot then reflects the
    /// published revision so callers can reread instead of retrying blindly.
    Persistence(&'static str),
}

impl fmt::Display for SettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) | Self::Persistence(message) => formatter.write_str(message),
            Self::Conflict => {
                formatter.write_str("configuration revision conflict; reload settings")
            }
        }
    }
}

impl std::error::Error for SettingsError {}

/// A durable settings store owned by one running node.
///
/// The management server must hold its configuration lock across each replace.
/// Temporary files are created in the same directory as `settings.json` with
/// mode 0600 on Unix. First creation uses a hard link to avoid overwriting a
/// document that appeared concurrently; replacements use an atomic rename.
pub struct ConfigStore {
    path: PathBuf,
    document: ConfigDocument,
}

impl ConfigStore {
    /// Load saved settings, or initialize a new document from bootstrap values.
    ///
    /// Existing files must be regular, must not be symlinks, and on Unix must
    /// have no group or other permissions. Malformed, oversized, unsupported,
    /// and invalid documents are rejected without replacing them.
    pub fn open(data_dir: &Path, initial_settings: Settings) -> Result<Self, SettingsError> {
        match fs::symlink_metadata(data_dir) {
            Ok(directory) if !directory.file_type().is_dir() => {
                return Err(SettingsError::Persistence(
                    "configuration directory must be a regular directory",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                initial_settings.validate()?;
            }
            Err(_) => {
                return Err(SettingsError::Persistence(
                    "cannot inspect configuration directory",
                ));
            }
            Ok(_) => {}
        }
        fs::create_dir_all(data_dir)
            .map_err(|_| SettingsError::Persistence("cannot create configuration directory"))?;
        let directory = fs::symlink_metadata(data_dir)
            .map_err(|_| SettingsError::Persistence("cannot inspect configuration directory"))?;
        if !directory.file_type().is_dir() {
            return Err(SettingsError::Persistence(
                "configuration directory must be a regular directory",
            ));
        }
        let path = data_dir.join("settings.json");
        let document = if let Some(document) = read_document(&path)? {
            document
        } else {
            initial_settings.validate()?;
            let document = ConfigDocument {
                schema_version: SCHEMA_VERSION,
                revision: 1,
                settings: initial_settings,
            };
            publish(&path, &document, true)?;
            sync_directory(&path).map_err(|_| synchronization_failed())?;
            document
        };
        Ok(Self { path, document })
    }

    /// Return an owned snapshot without exposing mutable store internals.
    pub fn snapshot(&self) -> ConfigDocument {
        self.document.clone()
    }

    /// Validate and atomically replace settings if the revision still matches.
    ///
    /// Every successful save increments the revision, including a save with
    /// unchanged values. Revision conflicts and invalid values never write.
    /// If directory synchronization fails after publication, the returned error
    /// reports uncertain durability and the snapshot exposes the new revision.
    pub fn replace(
        &mut self,
        expected_revision: u64,
        settings: Settings,
    ) -> Result<ConfigDocument, SettingsError> {
        self.replace_with_sync(expected_revision, settings, sync_directory)
    }

    fn replace_with_sync(
        &mut self,
        expected_revision: u64,
        settings: Settings,
        sync: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> Result<ConfigDocument, SettingsError> {
        if expected_revision != self.document.revision {
            return Err(SettingsError::Conflict);
        }
        settings.validate()?;
        if read_document(&self.path)?.as_ref() != Some(&self.document) {
            return Err(SettingsError::Conflict);
        }
        let document =
            ConfigDocument {
                schema_version: SCHEMA_VERSION,
                revision: self.document.revision.checked_add(1).ok_or(
                    SettingsError::Persistence("configuration revision is exhausted"),
                )?,
                settings,
            };
        publish(&self.path, &document, false)?;
        self.document = document;
        sync(&self.path).map_err(|_| synchronization_failed())?;
        Ok(self.snapshot())
    }
}

fn read_document(path: &Path) -> Result<Option<ConfigDocument>, SettingsError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(SettingsError::Persistence(
                "cannot inspect saved configuration",
            ));
        }
    };
    if !metadata.file_type().is_file() {
        return Err(SettingsError::Persistence(
            "saved configuration must be a regular file, not a symlink",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(SettingsError::Persistence(
                "saved configuration permissions must exclude group and other access",
            ));
        }
    }
    if metadata.len() > MAX_SETTINGS_BYTES as u64 {
        return Err(SettingsError::Persistence(
            "saved configuration exceeds size limit",
        ));
    }
    let file = File::open(path)
        .map_err(|_| SettingsError::Persistence("cannot read saved configuration"))?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| SettingsError::Persistence("cannot inspect opened configuration"))?;
    if !opened_metadata.is_file() {
        return Err(SettingsError::Persistence(
            "saved configuration changed while opening",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.dev() != opened_metadata.dev() || metadata.ino() != opened_metadata.ino() {
            return Err(SettingsError::Persistence(
                "saved configuration changed while opening",
            ));
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_SETTINGS_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SettingsError::Persistence("cannot read saved configuration"))?;
    if bytes.len() > MAX_SETTINGS_BYTES {
        return Err(SettingsError::Persistence(
            "saved configuration exceeds size limit",
        ));
    }
    let document: ConfigDocument = serde_json::from_slice(&bytes)
        .map_err(|_| SettingsError::Persistence("saved configuration is malformed"))?;
    if document.schema_version != SCHEMA_VERSION {
        return Err(SettingsError::Persistence(
            "saved configuration schema is unsupported",
        ));
    }
    if document.revision == 0 {
        return Err(SettingsError::Persistence(
            "saved configuration revision must be positive",
        ));
    }
    document
        .settings
        .validate()
        .map_err(|_| SettingsError::Persistence("saved configuration contains invalid settings"))?;
    Ok(Some(document))
}

struct TemporaryFile(PathBuf);

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn publish(path: &Path, document: &ConfigDocument, initial: bool) -> Result<(), SettingsError> {
    let bytes = serde_json::to_vec_pretty(document)
        .map_err(|_| SettingsError::Persistence("cannot encode configuration"))?;
    if bytes.len() > MAX_SETTINGS_BYTES {
        return Err(SettingsError::Invalid("configuration exceeds size limit"));
    }
    let parent = path.parent().ok_or(SettingsError::Persistence(
        "configuration directory is missing",
    ))?;
    let mut random = [0; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let temporary = parent.join(format!(".settings-{}.tmp", hex::encode(random)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| SettingsError::Persistence("cannot create temporary configuration"))?;
    let temporary = TemporaryFile(temporary);
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| SettingsError::Persistence("cannot synchronize configuration"))?;
    drop(file);
    if initial {
        fs::hard_link(&temporary.0, path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                SettingsError::Conflict
            } else {
                SettingsError::Persistence("cannot publish initial configuration")
            }
        })?;
    } else {
        fs::rename(&temporary.0, path)
            .map_err(|_| SettingsError::Persistence("cannot replace configuration"))?;
    }
    drop(temporary);
    Ok(())
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path.parent().expect("configuration path has a directory"))?.sync_all()
}

fn synchronization_failed() -> SettingsError {
    SettingsError::Persistence(
        "configuration published but directory synchronization failed; reread settings before retrying",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(settings: Settings) -> ConfigDocument {
        ConfigDocument {
            schema_version: SCHEMA_VERSION,
            revision: 1,
            settings,
        }
    }

    fn write_saved(directory: &Path, value: &[u8]) {
        let path = directory.join("settings.json");
        fs::write(&path, value).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn defaults_are_valid_but_unconfigured() {
        let settings = Settings::default();
        assert_eq!(settings.node_name, "PurpleSky");
        assert_eq!(settings.network, Network::Mainnet);
        assert_eq!(settings.request_timeout_ms, 5_000);
        assert_eq!(settings.max_response_bytes, 256 * 1024);
        assert_eq!(settings.max_block_delay_seconds, 30);
        assert!(settings.validate().is_ok());
        assert!(settings.preflight().unwrap().is_none());
    }

    #[test]
    fn configures_https_and_tunnel_endpoints() {
        let settings = Settings {
            endpoints: vec![
                "https://haatz.quilibrium.com".into(),
                "http://127.0.0.1:3381".into(),
            ],
            test_fid: Some(8531),
            ..Settings::default()
        };
        assert_eq!(
            settings.preflight().unwrap().unwrap().endpoints().count(),
            2
        );
    }

    #[test]
    fn rejects_invalid_names() {
        for name in [
            "".to_owned(),
            "   ".into(),
            "x".repeat(65),
            "hello\nnode".into(),
            "n\0de".into(),
            "\u{7f}".into(),
        ] {
            assert!(
                Settings {
                    node_name: name,
                    ..Settings::default()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            Settings {
                node_name: "n".repeat(64),
                ..Settings::default()
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn rejects_credentials_queries_duplicate_and_insecure_endpoints() {
        for endpoints in [
            vec!["https://alice:supersecret@example.com".into()],
            vec!["https://example.com?token=supersecret".into()],
            vec!["https://example.com/route".into()],
            vec!["http://example.com".into()],
            vec!["https://example.com".into(), "https://example.com/".into()],
            vec![format!("https://{}", "x".repeat(2048))],
        ] {
            let error = Settings {
                endpoints,
                ..Settings::default()
            }
            .validate()
            .unwrap_err();
            assert!(!format!("{error:?} {error}").contains("supersecret"));
        }
    }

    #[test]
    fn rejects_too_many_endpoints() {
        let settings = Settings {
            endpoints: (0..9)
                .map(|i| format!("https://node{i}.example.com"))
                .collect(),
            ..Settings::default()
        };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn validates_limits_even_without_endpoints() {
        for timeout in [0, 9, 30_001, u64::MAX] {
            assert!(
                Settings {
                    request_timeout_ms: timeout,
                    ..Settings::default()
                }
                .validate()
                .is_err()
            );
        }
        for bytes in [0, MAX_RESPONSE_BYTES + 1, usize::MAX] {
            assert!(
                Settings {
                    max_response_bytes: bytes,
                    ..Settings::default()
                }
                .validate()
                .is_err()
            );
        }
        for seconds in [0, MAX_BLOCK_DELAY_SECS + 1, u64::MAX] {
            assert!(
                Settings {
                    max_block_delay_seconds: seconds,
                    ..Settings::default()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            Settings {
                test_fid: Some(0),
                ..Settings::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Settings {
                test_fid: Some(MAX_TEST_FID),
                ..Settings::default()
            }
            .validate()
            .is_ok()
        );
        for fid in [MAX_TEST_FID + 1, u64::MAX] {
            assert!(
                Settings {
                    test_fid: Some(fid),
                    ..Settings::default()
                }
                .validate()
                .is_err()
            );
        }
        for (timeout, bytes, seconds) in [
            (10, 1, 1),
            (30_000, MAX_RESPONSE_BYTES, MAX_BLOCK_DELAY_SECS),
        ] {
            assert!(
                Settings {
                    request_timeout_ms: timeout,
                    max_response_bytes: bytes,
                    max_block_delay_seconds: seconds,
                    ..Settings::default()
                }
                .validate()
                .is_ok()
            );
        }
    }

    #[test]
    fn requires_loopback_admin_and_distinct_listeners() {
        for address in ["0.0.0.0:8788", "[::]:8788", "192.0.2.1:8788"] {
            assert!(
                Settings {
                    admin_bind: address.parse().unwrap(),
                    ..Settings::default()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            Settings {
                admin_bind: "[::1]:8788".parse().unwrap(),
                ..Settings::default()
            }
            .validate()
            .is_ok()
        );
        assert!(
            Settings {
                public_bind: "127.0.0.1:8788".parse().unwrap(),
                ..Settings::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Settings {
                admin_bind: "127.0.0.1:0".parse().unwrap(),
                public_bind: "127.0.0.1:0".parse().unwrap(),
                ..Settings::default()
            }
            .validate()
            .is_ok()
        );
        assert!(
            Settings {
                public_bind: "0.0.0.0:8787".parse().unwrap(),
                ..Settings::default()
            }
            .validate()
            .is_ok()
        );
        assert!(
            Settings {
                public_bind: "224.0.0.1:8787".parse().unwrap(),
                ..Settings::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn persists_bootstrap_and_uses_saved_settings_on_restart() {
        let directory = tempfile::tempdir().unwrap();
        let saved = Settings {
            node_name: "Majin".into(),
            ..Settings::default()
        };
        let store = ConfigStore::open(directory.path(), saved.clone()).unwrap();
        assert_eq!(store.snapshot(), document(saved));
        let invalid_bootstrap = Settings {
            node_name: "".into(),
            ..Settings::default()
        };
        let reopened = ConfigStore::open(directory.path(), invalid_bootstrap).unwrap();
        assert_eq!(reopened.snapshot(), store.snapshot());
    }

    #[test]
    fn replacement_increments_revision_and_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open(directory.path(), Settings::default()).unwrap();
        let updated = Settings {
            node_name: "Majin".into(),
            serve_fixture: true,
            ..Settings::default()
        };
        let saved = store.replace(1, updated.clone()).unwrap();
        assert_eq!(saved.revision, 2);
        assert_eq!(saved.settings, updated);
        assert_eq!(
            ConfigStore::open(directory.path(), Settings::default())
                .unwrap()
                .snapshot(),
            saved
        );
        assert_eq!(store.replace(2, updated).unwrap().revision, 3);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn stale_revision_never_changes_memory_or_disk() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open(directory.path(), Settings::default()).unwrap();
        let before = fs::read(directory.path().join("settings.json")).unwrap();
        let snapshot = store.snapshot();
        let settings = Settings {
            node_name: "Other".into(),
            ..Settings::default()
        };
        assert_eq!(
            store.replace(0, settings.clone()).unwrap_err(),
            SettingsError::Conflict
        );
        assert_eq!(
            store.replace(2, settings).unwrap_err(),
            SettingsError::Conflict
        );
        assert_eq!(store.snapshot(), snapshot);
        assert_eq!(
            fs::read(directory.path().join("settings.json")).unwrap(),
            before
        );
    }

    #[test]
    fn invalid_replacement_never_changes_memory_or_disk() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open(directory.path(), Settings::default()).unwrap();
        let before = fs::read(directory.path().join("settings.json")).unwrap();
        let settings = Settings {
            admin_bind: "0.0.0.0:8788".parse().unwrap(),
            ..Settings::default()
        };
        assert!(matches!(
            store.replace(1, settings),
            Err(SettingsError::Invalid(_))
        ));
        assert_eq!(store.snapshot().revision, 1);
        assert_eq!(
            fs::read(directory.path().join("settings.json")).unwrap(),
            before
        );
    }

    #[test]
    fn invalid_bootstrap_does_not_create_document() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings {
            test_fid: Some(0),
            ..Settings::default()
        };
        assert!(ConfigStore::open(directory.path(), settings).is_err());
        assert!(!directory.path().join("settings.json").exists());
    }

    #[test]
    fn invalid_bootstrap_does_not_create_data_directory() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("new-node");
        let settings = Settings {
            admin_bind: "0.0.0.0:8788".parse().unwrap(),
            ..Settings::default()
        };
        assert!(matches!(
            ConfigStore::open(&directory, settings),
            Err(SettingsError::Invalid(_))
        ));
        assert!(!directory.exists());
    }

    #[test]
    fn post_publication_sync_failure_exposes_published_revision() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open(directory.path(), Settings::default()).unwrap();
        let settings = Settings {
            node_name: "Saved but uncertain durability".into(),
            ..Settings::default()
        };
        let error = store
            .replace_with_sync(1, settings.clone(), |_| {
                Err(std::io::Error::other("test failure"))
            })
            .unwrap_err();
        assert_eq!(error, synchronization_failed());
        assert_eq!(store.snapshot().revision, 2);
        assert_eq!(store.snapshot().settings, settings);
        let saved = ConfigStore::open(directory.path(), Settings::default())
            .unwrap()
            .snapshot();
        assert_eq!(store.snapshot(), saved);
        assert_eq!(
            store.replace(1, Settings::default()).unwrap_err(),
            SettingsError::Conflict
        );
        assert_eq!(store.replace(2, Settings::default()).unwrap().revision, 3);
    }

    #[test]
    fn independent_stale_store_detects_replaced_document() {
        let directory = tempfile::tempdir().unwrap();
        let mut first = ConfigStore::open(directory.path(), Settings::default()).unwrap();
        let mut stale = ConfigStore::open(directory.path(), Settings::default()).unwrap();
        first
            .replace(
                1,
                Settings {
                    node_name: "New".into(),
                    ..Settings::default()
                },
            )
            .unwrap();
        assert_eq!(
            stale.replace(1, Settings::default()).unwrap_err(),
            SettingsError::Conflict
        );
        assert_eq!(
            ConfigStore::open(directory.path(), Settings::default())
                .unwrap()
                .snapshot()
                .settings
                .node_name,
            "New"
        );
    }

    #[test]
    fn missing_saved_document_does_not_silently_reinitialize_on_save() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open(directory.path(), Settings::default()).unwrap();
        fs::remove_file(directory.path().join("settings.json")).unwrap();
        assert_eq!(
            store.replace(1, Settings::default()).unwrap_err(),
            SettingsError::Conflict
        );
        assert!(!directory.path().join("settings.json").exists());
    }

    #[test]
    fn malformed_oversized_and_unknown_documents_are_preserved() {
        let mut unknown_field = serde_json::to_value(document(Settings::default())).unwrap();
        unknown_field["surprise"] = true.into();
        let mut unknown_setting = serde_json::to_value(document(Settings::default())).unwrap();
        unknown_setting["settings"]["password"] = "supersecret".into();
        let mut unknown_schema = document(Settings::default());
        unknown_schema.schema_version = 2;
        let mut invalid_revision = document(Settings::default());
        invalid_revision.revision = 0;
        let invalid = document(Settings {
            test_fid: Some(0),
            ..Settings::default()
        });
        for bytes in [
            b"{\"secret\":\"supersecret\"".to_vec(),
            vec![b' '; MAX_SETTINGS_BYTES + 1],
            serde_json::to_vec(&unknown_field).unwrap(),
            serde_json::to_vec(&unknown_setting).unwrap(),
            serde_json::to_vec(&unknown_schema).unwrap(),
            serde_json::to_vec(&invalid_revision).unwrap(),
            serde_json::to_vec(&invalid).unwrap(),
        ] {
            let directory = tempfile::tempdir().unwrap();
            write_saved(directory.path(), &bytes);
            let error = ConfigStore::open(directory.path(), Settings::default())
                .err()
                .unwrap();
            assert!(matches!(error, SettingsError::Persistence(_)));
            assert!(!format!("{error:?} {error}").contains("supersecret"));
            assert_eq!(
                fs::read(directory.path().join("settings.json")).unwrap(),
                bytes
            );
        }
    }

    #[test]
    fn does_not_overflow_revision() {
        let directory = tempfile::tempdir().unwrap();
        let mut saved = document(Settings::default());
        saved.revision = u64::MAX;
        let bytes = serde_json::to_vec(&saved).unwrap();
        write_saved(directory.path(), &bytes);
        let mut store = ConfigStore::open(directory.path(), Settings::default()).unwrap();
        assert!(matches!(
            store.replace(u64::MAX, Settings::default()),
            Err(SettingsError::Persistence(_))
        ));
        assert_eq!(
            fs::read(directory.path().join("settings.json")).unwrap(),
            bytes
        );
    }

    #[test]
    fn initial_publish_cannot_clobber_existing_document() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        let existing = document(Settings::default());
        publish(&path, &existing, true).unwrap();
        let replacement = document(Settings {
            node_name: "Other".into(),
            ..Settings::default()
        });
        assert_eq!(
            publish(&path, &replacement, true).unwrap_err(),
            SettingsError::Conflict
        );
        assert_eq!(read_document(&path).unwrap(), Some(existing));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn rejects_directory_in_place_of_document() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("settings.json")).unwrap();
        assert!(ConfigStore::open(directory.path(), Settings::default()).is_err());
        assert!(directory.path().join("settings.json").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn files_remain_private_across_replacements() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open(directory.path(), Settings::default()).unwrap();
        let path = directory.path().join("settings.json");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        store.replace(1, Settings::default()).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_insecure_saved_permissions_without_changing_them() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        write_saved(
            directory.path(),
            &serde_json::to_vec(&document(Settings::default())).unwrap(),
        );
        for mode in [0o644, 0o640, 0o606] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(ConfigStore::open(directory.path(), Settings::default()).is_err());
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                mode
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_even_when_target_is_valid() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.json");
        let contents = serde_json::to_vec(&document(Settings::default())).unwrap();
        fs::write(&target, &contents).unwrap();
        symlink(&target, directory.path().join("settings.json")).unwrap();
        assert!(ConfigStore::open(directory.path(), Settings::default()).is_err());
        assert_eq!(fs::read(target).unwrap(), contents);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_dangling_symlink_instead_of_initializing_through_it() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.json");
        symlink(&missing, directory.path().join("settings.json")).unwrap();
        assert!(ConfigStore::open(directory.path(), Settings::default()).is_err());
        assert!(!missing.exists());
    }
}
