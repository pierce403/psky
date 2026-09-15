//! Bounded, read-only checks of existing Hypersnap HTTP APIs.
//!
//! A successful response is evidence that one endpoint answered one request.
//! It is not evidence of finality, full history, replicated content, media
//! storage, FID custody, or a storage contract suitable for a PDS.
//!
//! The observed Hypersnap `0.13.5` `/v1/info` response does not identify its
//! network. An optional test FID permits a single retained cast to corroborate
//! the node's reported network. That value is not independently authenticated:
//! this crate does not verify Farcaster signatures or consensus.
//!
//! ```
//! use psky_hypersnap::{Network, PreflightClient, PreflightConfig};
//!
//! let config = PreflightConfig::new(
//!     vec!["https://haatz.quilibrium.com".to_owned()],
//!     Network::Mainnet,
//!     None,
//! )?;
//! let client = PreflightClient::new(config)?;
//! # Ok::<(), psky_hypersnap::ConfigError>(())
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::{fmt, str::FromStr, time::Duration};

use reqwest::{Client, StatusCode, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::{Host, Url};

/// Maximum number of explicitly configured endpoints.
pub const MAX_ENDPOINTS: usize = 8;
/// Default response body cap, including successful JSON responses.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// Maximum configurable response body cap.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Version whose HTTP response shape was inspected for this adapter.
pub const SUPPORTED_VERSION: &str = "0.13.5";

/// Farcaster's network identifier, as reported in message data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Farcaster mainnet, protobuf identifier 1.
    Mainnet,
    /// Farcaster testnet, protobuf identifier 2.
    Testnet,
    /// Farcaster development network, protobuf identifier 3.
    Devnet,
}

impl Network {
    fn from_message(value: &Value) -> Option<Self> {
        match (value.as_u64(), value.as_str()) {
            (Some(1), _) | (_, Some("FARCASTER_NETWORK_MAINNET")) => Some(Self::Mainnet),
            (Some(2), _) | (_, Some("FARCASTER_NETWORK_TESTNET")) => Some(Self::Testnet),
            (Some(3), _) | (_, Some("FARCASTER_NETWORK_DEVNET")) => Some(Self::Devnet),
            _ => None,
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Devnet => "devnet",
        })
    }
}

impl FromStr for Network {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "devnet" => Ok(Self::Devnet),
            _ => Err(ConfigError::new(
                "network must be mainnet, testnet, or devnet",
            )),
        }
    }
}

/// A validated configuration. Credentials and URL query strings are forbidden.
#[derive(Debug, Clone)]
pub struct PreflightConfig {
    endpoints: Vec<Url>,
    expected_network: Network,
    test_fid: Option<u64>,
    timeout: Duration,
    max_response_bytes: usize,
}

impl PreflightConfig {
    /// Validate a nonempty endpoint set, expected network, and optional test FID.
    ///
    /// Remote endpoints require HTTPS. HTTP is allowed only for literal
    /// loopback addresses or `localhost`, for operator-local nodes and tests.
    /// Paths, user information, fragments, and queries are rejected. This
    /// prevents accidentally exporting credentials or guessing proxy routes.
    pub fn new(
        endpoints: Vec<String>,
        expected_network: Network,
        test_fid: Option<u64>,
    ) -> Result<Self, ConfigError> {
        if endpoints.is_empty() || endpoints.len() > MAX_ENDPOINTS {
            return Err(ConfigError::new("configure between 1 and 8 endpoints"));
        }
        if test_fid == Some(0) {
            return Err(ConfigError::new("test FID must be greater than zero"));
        }
        let mut urls = Vec::with_capacity(endpoints.len());
        for input in endpoints {
            let endpoint = validate_endpoint(&input)?;
            if urls.contains(&endpoint) {
                return Err(ConfigError::new("duplicate endpoints are not allowed"));
            }
            urls.push(endpoint);
        }
        Ok(Self {
            endpoints: urls,
            expected_network,
            test_fid,
            timeout: Duration::from_secs(5),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        })
    }

    /// Set bounded per-request time and response-byte limits.
    ///
    /// The timeout includes reading the response body. The accepted range is
    /// 10 milliseconds through 30 seconds, and 1 through 1,048,576 body bytes.
    pub fn with_limits(
        mut self,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, ConfigError> {
        if !(Duration::from_millis(10)..=Duration::from_secs(30)).contains(&timeout) {
            return Err(ConfigError::new("request timeout must be 10ms through 30s"));
        }
        if max_response_bytes == 0 || max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(ConfigError::new(
                "response limit must be 1 through 1048576 bytes",
            ));
        }
        self.timeout = timeout;
        self.max_response_bytes = max_response_bytes;
        Ok(self)
    }

    /// Return the normalized endpoint URLs, which contain no credentials.
    pub fn endpoints(&self) -> impl Iterator<Item = &str> {
        self.endpoints.iter().map(Url::as_str)
    }
}

fn validate_endpoint(input: &str) -> Result<Url, ConfigError> {
    let endpoint = Url::parse(input).map_err(|_| ConfigError::new("invalid endpoint URL"))?;
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err(ConfigError::new(
            "endpoint URLs must not contain credentials",
        ));
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        return Err(ConfigError::new(
            "endpoint URLs must not contain queries or fragments",
        ));
    }
    if endpoint.path() != "/" {
        return Err(ConfigError::new("endpoint URL must use the root path"));
    }
    let loopback = match endpoint.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain("localhost")) => true,
        Some(Host::Domain(_)) => false,
        None => return Err(ConfigError::new("endpoint URL must have a host")),
    };
    match endpoint.scheme() {
        "https" => Ok(endpoint),
        "http" if loopback => Ok(endpoint),
        _ => Err(ConfigError::new(
            "remote endpoints require HTTPS; HTTP requires loopback",
        )),
    }
}

/// A configuration error containing only fixed diagnostic text.
///
/// The invalid input is never retained or included in the error message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    message: &'static str,
}

impl ConfigError {
    fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for ConfigError {}

/// Result of comparing a node response with the configured protocol/network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compatibility {
    /// Reported values match the configured and inspected values.
    Compatible,
    /// A reported value conflicts with the configured or inspected value.
    Incompatible,
    /// Insufficient response evidence to compare values.
    Unknown,
}

/// A fixed, exportable failure classification. Response bodies are not retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    /// The full request exceeded its configured deadline.
    Timeout,
    /// Connection, DNS, or TLS failed; internal error details are omitted.
    Transport,
    /// The server tried to redirect; redirects are never followed.
    Redirect,
    /// A 404 or 501 response indicates this route is unavailable.
    Unavailable,
    /// The route returned another unsuccessful status code.
    HttpStatus,
    /// The response body exceeded its configured limit.
    Oversized,
    /// The response was not valid JSON with the expected structure.
    Malformed,
}

/// Evidence about one request, without raw headers or response content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEvidence {
    /// Static route name, excluding the query string.
    pub route: String,
    /// HTTP status, when a response was received.
    pub status: Option<u16>,
    /// Bytes read before successful parsing or rejection.
    pub response_bytes: usize,
    /// Failure classification, or `None` when the JSON shape was accepted.
    pub failure: Option<Failure>,
}

/// Bounded node information returned by `/v1/info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Reported software version. This is not remote attestation.
    pub version: String,
    /// Number of data shards reported by the node.
    pub num_shards: u64,
    /// Reported total message count, if supplied.
    pub num_messages: Option<u64>,
}

/// A reported capacity limit. Counts do not establish future retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreLimit {
    /// Recognized Farcaster message store name.
    pub name: String,
    /// Reported message capacity.
    pub limit: u64,
    /// Reported current usage.
    pub used: u64,
}

/// Storage allocation reported by one node for the configured FID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageAllocation {
    /// Total reported storage units, without a claim about price or expiry.
    pub units: u64,
    /// Reported per-store message counts, not large-file byte capacity.
    pub limits: Vec<StoreLimit>,
}

/// Registry-event observation, not proof of present account authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityObservation {
    /// Number of returned registration or transfer events.
    pub registry_events: usize,
    /// Address in the latest returned registration or transfer event.
    ///
    /// This endpoint may omit history or lag the current chain state. No
    /// ownership challenge, chain verification, or authorization is performed.
    pub reported_custody: Option<String>,
    /// Always false. HTTP event data alone cannot authenticate the account.
    pub verified: bool,
}

/// Evidence obtained from one explicitly configured node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeReport {
    /// Validated endpoint, containing no URL credentials or query strings.
    pub endpoint: String,
    /// Inspected information response, when available and structurally valid.
    pub info: Option<NodeInfo>,
    /// Whether the reported version matches the inspected version.
    pub protocol: Compatibility,
    /// Whether a retained cast's reported network matches configuration.
    pub network: Compatibility,
    /// Network reported by the optional retained cast, if recognized.
    pub observed_network: Option<Network>,
    /// Reported allocation for the optional FID, if the route was available.
    pub storage: Option<StorageAllocation>,
    /// Unverified registry observations for the optional FID.
    pub authority: Option<AuthorityObservation>,
    /// Evidence for the individual read-only requests.
    pub requests: Vec<RequestEvidence>,
}

/// Aggregate, serializable result of the configured read-only preflight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightReport {
    /// Expected Farcaster network from operator configuration.
    pub expected_network: Network,
    /// Dedicated test FID, when one was configured.
    pub test_fid: Option<u64>,
    /// All nodes reported the inspected version and matching message network.
    ///
    /// This only compares reported values. It does not authorize writes, prove
    /// signatures, establish common chain history, or establish durability.
    pub compatible: bool,
    /// Always false until the storage and reconstruction gates are proved.
    pub ready_for_reconstruction: bool,
    /// Result for each configured endpoint, in configuration order.
    pub nodes: Vec<NodeReport>,
    /// Explicitly unproved requirements that must not be inferred from HTTP.
    pub limitations: Vec<String>,
}

/// A reusable HTTP client for read-only Hypersnap preflight.
#[derive(Debug, Clone)]
pub struct PreflightClient {
    config: PreflightConfig,
    client: Client,
}

impl PreflightClient {
    /// Build an HTTPS-verifying client with no redirects, proxies, or cookies.
    ///
    /// Disabling environment proxies makes the configured endpoint the direct
    /// destination and prevents accidental proxy-credential use. No API token,
    /// wallet key, browser cookie, or authorization header is accepted.
    pub fn new(config: PreflightConfig) -> Result<Self, ConfigError> {
        let client = Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.timeout)
            .redirect(Policy::none())
            .no_proxy()
            .user_agent("PurpleSky-preflight/0.1.0")
            .build()
            .map_err(|_| ConfigError::new("could not initialize HTTPS client"))?;
        Ok(Self { config, client })
    }

    /// Query the bounded endpoint set. This method never submits mutations.
    ///
    /// Requests are sequential to keep the preflight load small. Each endpoint
    /// gets one info request and, if a test FID is present and info succeeded,
    /// one retained-cast request with `pageSize=1`, one allocation request,
    /// and one registry-event request. There are no retries or pagination.
    pub async fn run(&self) -> PreflightReport {
        let mut nodes = Vec::with_capacity(self.config.endpoints.len());
        for endpoint in &self.config.endpoints {
            nodes.push(self.inspect_node(endpoint).await);
        }
        let compatible = nodes.iter().all(|node| {
            node.protocol == Compatibility::Compatible && node.network == Compatibility::Compatible
        });
        PreflightReport {
            expected_network: self.config.expected_network,
            test_fid: self.config.test_fid,
            compatible,
            ready_for_reconstruction: false,
            nodes,
            limitations: vec![
                "Node responses and message signatures are not independently verified.".into(),
                "Farcaster account authority is not verified; allocation is only node-reported."
                    .into(),
                "Common chain history, ordering, finality, and complete replay remain unproved."
                    .into(),
                "Arbitrary ATProto record storage and large-file byte storage remain unproved."
                    .into(),
            ],
        }
    }

    async fn inspect_node(&self, endpoint: &Url) -> NodeReport {
        let mut report = NodeReport {
            endpoint: endpoint.to_string(),
            info: None,
            protocol: Compatibility::Unknown,
            network: Compatibility::Unknown,
            observed_network: None,
            storage: None,
            authority: None,
            requests: Vec::new(),
        };
        let (value, mut evidence) = self.request(endpoint, "/v1/info", &[]).await;
        if let Some(value) = value {
            match parse_info(&value) {
                Some(info) => {
                    report.protocol = if info.version == SUPPORTED_VERSION {
                        Compatibility::Compatible
                    } else {
                        Compatibility::Incompatible
                    };
                    report.info = Some(info);
                }
                None => evidence.failure = Some(Failure::Malformed),
            }
        }
        report.requests.push(evidence);

        if let Some(fid) = self.config.test_fid.filter(|_| report.info.is_some()) {
            let (value, mut evidence) = self
                .request(
                    endpoint,
                    "/v1/castsByFid",
                    &[("fid", fid.to_string()), ("pageSize", "1".to_owned())],
                )
                .await;
            if let Some(value) = value {
                match parse_network(&value, fid) {
                    Ok(Some(network)) => {
                        report.observed_network = Some(network);
                        report.network = if network == self.config.expected_network {
                            Compatibility::Compatible
                        } else {
                            Compatibility::Incompatible
                        };
                    }
                    Ok(None) => {}
                    Err(()) => evidence.failure = Some(Failure::Malformed),
                }
            }
            report.requests.push(evidence);

            let (value, mut evidence) = self
                .request(
                    endpoint,
                    "/v1/storageLimitsByFid",
                    &[("fid", fid.to_string())],
                )
                .await;
            if let Some(value) = value {
                report.storage = parse_storage(&value);
                if report.storage.is_none() {
                    evidence.failure = Some(Failure::Malformed);
                }
            }
            report.requests.push(evidence);

            let (value, mut evidence) = self
                .request(
                    endpoint,
                    "/v1/onChainEventsByFid",
                    &[
                        ("fid", fid.to_string()),
                        ("event_type", "EVENT_TYPE_ID_REGISTER".to_owned()),
                    ],
                )
                .await;
            if let Some(value) = value {
                report.authority = parse_authority(&value, fid);
                if report.authority.is_none() {
                    evidence.failure = Some(Failure::Malformed);
                }
            }
            report.requests.push(evidence);
        }
        report
    }

    async fn request(
        &self,
        endpoint: &Url,
        route: &str,
        query: &[(&str, String)],
    ) -> (Option<Value>, RequestEvidence) {
        let mut evidence = RequestEvidence {
            route: route.to_owned(),
            status: None,
            response_bytes: 0,
            failure: None,
        };
        let mut url = endpoint.clone();
        url.set_path(route);
        let response = self.client.get(url).query(query).send().await;
        let mut response = match response {
            Ok(response) => response,
            Err(error) => {
                evidence.failure = Some(classify_transport(&error));
                return (None, evidence);
            }
        };
        let status = response.status();
        evidence.status = Some(status.as_u16());
        if !status.is_success() {
            evidence.failure = Some(if status.is_redirection() {
                Failure::Redirect
            } else if status == StatusCode::NOT_FOUND || status == StatusCode::NOT_IMPLEMENTED {
                Failure::Unavailable
            } else {
                Failure::HttpStatus
            });
            return (None, evidence);
        }
        if response
            .content_length()
            .is_some_and(|size| size > self.config.max_response_bytes as u64)
        {
            evidence.failure = Some(Failure::Oversized);
            return (None, evidence);
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    evidence.response_bytes = evidence.response_bytes.saturating_add(chunk.len());
                    if evidence.response_bytes > self.config.max_response_bytes {
                        evidence.failure = Some(Failure::Oversized);
                        return (None, evidence);
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(error) => {
                    evidence.failure = Some(classify_transport(&error));
                    return (None, evidence);
                }
            }
        }
        match serde_json::from_slice(&body) {
            Ok(value) => (Some(value), evidence),
            Err(_) => {
                evidence.failure = Some(Failure::Malformed);
                (None, evidence)
            }
        }
    }
}

fn classify_transport(error: &reqwest::Error) -> Failure {
    if error.is_timeout() {
        Failure::Timeout
    } else {
        Failure::Transport
    }
}

fn parse_info(value: &Value) -> Option<NodeInfo> {
    let version = value.get("version")?.as_str()?;
    // Retain only version-like text, never arbitrary server-controlled prose.
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-+_".contains(&byte))
    {
        return None;
    }
    let num_shards = value.get("numShards")?.as_u64()?;
    if num_shards == 0 {
        return None;
    }
    let db_stats = value.get("dbStats")?.as_object()?;
    let num_messages = match db_stats.get("numMessages") {
        Some(count) => Some(count.as_u64()?),
        None => None,
    };
    Some(NodeInfo {
        version: version.to_owned(),
        num_shards,
        num_messages,
    })
}

fn parse_network(value: &Value, fid: u64) -> Result<Option<Network>, ()> {
    let messages = value.get("messages").and_then(Value::as_array).ok_or(())?;
    if messages.is_empty() {
        return Ok(None);
    }
    if messages.len() != 1 {
        return Err(());
    }
    let data = messages[0].get("data").ok_or(())?;
    let reported_fid = data.get("fid").and_then(Value::as_u64).ok_or(())?;
    if reported_fid != fid {
        return Err(());
    }
    let network = data.get("network").and_then(Network::from_message);
    Ok(network)
}

fn parse_storage(value: &Value) -> Option<StorageAllocation> {
    let units = value.get("units")?.as_u64()?;
    let entries = value.get("limits")?.as_array()?;
    if entries.len() > 32 {
        return None;
    }
    let mut limits = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = entry.get("name")?.as_str()?;
        if !matches!(
            name,
            "CASTS"
                | "LINKS"
                | "REACTIONS"
                | "USER_DATA"
                | "VERIFICATIONS"
                | "USERNAME_PROOFS"
                | "STORAGE_LENDS"
        ) {
            return None;
        }
        if limits.iter().any(|limit: &StoreLimit| limit.name == name) {
            return None;
        }
        limits.push(StoreLimit {
            name: name.to_owned(),
            limit: entry.get("limit")?.as_u64()?,
            used: entry.get("used")?.as_u64()?,
        });
    }
    Some(StorageAllocation { units, limits })
}

fn parse_authority(value: &Value, fid: u64) -> Option<AuthorityObservation> {
    let events = value.get("events")?.as_array()?;
    if events.len() > 1024 {
        return None;
    }
    let mut latest = None;
    for event in events {
        if event.get("fid")?.as_u64()? != fid {
            return None;
        }
        let body = event.get("idRegisterEventBody")?;
        if !matches!(body.get("eventType")?.as_str()?, "Register" | "Transfer") {
            // Recovery-address changes cannot be interpreted as custody transfers.
            continue;
        }
        let address = body.get("to")?.as_str()?;
        if address.len() != 42
            || !address.starts_with("0x")
            || !address[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        let position = (
            event.get("blockNumber")?.as_u64()?,
            event.get("txIndex")?.as_u64()?,
            event.get("logIndex")?.as_u64()?,
        );
        if latest
            .as_ref()
            .is_none_or(|(previous, _)| &position > previous)
        {
            latest = Some((position, address.to_owned()));
        }
    }
    Some(AuthorityObservation {
        registry_events: events.len(),
        reported_custody: latest.map(|(_, address)| address),
        verified: false,
    })
}
