use crate::{
    AuthError, Challenge, Channel, ChannelStatus, ProofKind, SignedProof, VerifiedIdentity,
    WalletKind, message,
};
use reqwest::{Client, RequestBuilder, StatusCode, redirect::Policy};
use serde::Deserialize;
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use std::{net::IpAddr, time::Duration};
use url::{Position, Url};

// EVM runtime code can occupy 24 KiB, encoded as 48 KiB JSON hex. Keep the
// response bounded without rejecting valid deployed ERC-1271 contracts.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const REQUEST_TIMEOUT_SECONDS: u64 = 8;
const MAX_FINALIZED_AGE_SECONDS: u64 = 3600;
const ID_REGISTRY: &str = "0x00000000fc6c5f01fc30151999387bb99a9f489b";
const KEY_REGISTRY: &str = "0x00000000fc1237824fb747abde0ff18990e59b7e";

/// Fixed origins for one application and its upstream services.
///
/// URLs may contain operator-managed RPC credentials in their path, so this
/// struct deliberately does not implement `Debug`. HTTPS is mandatory except
/// loopback HTTP for local tests and development, including exact `localhost`.
#[derive(Clone)]
pub struct AuthConfig {
    /// Exact authority displayed in the signed SIWE message, including port.
    pub domain: String,
    /// Exact sign-in URI displayed to the user; must belong to `domain`.
    pub uri: String,
    /// Relay origin, normally `https://relay.farcaster.xyz`.
    pub relay_url: String,
    /// Optimism JSON-RPC URL. Must support finalized blocks and EIP-1898 reads.
    pub optimism_rpc_url: String,
}

/// Bounded relay and Optimism client. No proxy, redirects, cookies or logging.
#[derive(Clone)]
pub struct AuthClient {
    config: AuthConfig,
    client: Client,
    relay: Url,
    rpc: Url,
}

impl AuthConfig {
    /// Validate exact origin binding and upstream transport restrictions.
    pub fn validate(&self) -> Result<(), AuthError> {
        let uri = safe_url(&self.uri)?;
        let authority = &uri[Position::BeforeHost..Position::AfterPort];
        if self.domain != authority
            || self.domain.len() > 253
            || self.domain.is_empty()
            || !self
                .domain
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".:-".contains(&b))
        {
            return Err(AuthError::InvalidConfig);
        }
        let relay = safe_url(&self.relay_url)?;
        if relay.path() != "/" {
            return Err(AuthError::InvalidConfig);
        }
        safe_url(&self.optimism_rpc_url)?;
        Ok(())
    }
}

impl AuthClient {
    /// Construct a validated client with an eight-second per-request deadline.
    pub fn new(config: AuthConfig) -> Result<Self, AuthError> {
        config.validate()?;
        let relay = safe_url(&config.relay_url)?;
        let rpc = safe_url(&config.optimism_rpc_url)?;
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECONDS))
            .connect_timeout(Duration::from_secs(4))
            .user_agent("PurpleSky/0.1 Farcaster-Auth")
            .build()
            .map_err(|_| AuthError::InvalidConfig)?;
        Ok(Self {
            config,
            client,
            relay,
            rpc,
        })
    }

    /// Create a relay channel for a server-generated local challenge.
    ///
    /// This creates only an expiring relay record. It does not register a
    /// messaging signer, publish a cast or perform an on-chain transaction.
    pub async fn start(&self, challenge: &Challenge) -> Result<Channel, AuthError> {
        message::validate_challenge(challenge)?;
        let request = json!({
            "domain": self.config.domain,
            "siweUri": self.config.uri,
            "nonce": challenge.nonce,
            "notBefore": message::timestamp(challenge.created_at)?,
            "expirationTime": message::timestamp(challenge.expires_at)?,
            "acceptAuthAddress": true
        });
        let url = self
            .relay
            .join("v1/channel")
            .map_err(|_| AuthError::InvalidConfig)?;
        let (status, response) = self
            .send(
                self.client
                    .post(url)
                    .header("Content-Type", "application/json")
                    .body(request.to_string()),
            )
            .await?;
        if status != StatusCode::CREATED {
            return Err(AuthError::Unavailable);
        }
        #[derive(Deserialize)]
        struct Created {
            #[serde(rename = "channelToken")]
            token: String,
            url: String,
            nonce: String,
        }
        let created: Created =
            serde_json::from_slice(&response).map_err(|_| AuthError::InvalidRelayResponse)?;
        if created.nonce != challenge.nonce || !valid_channel(&created.token) {
            return Err(AuthError::InvalidRelayResponse);
        }
        validate_auth_url(&created.url, &created.token)?;
        Ok(Channel {
            channel_token: created.token,
            auth_url: created.url,
        })
    }

    /// Read a relay channel once. A completed read consumes the remote channel.
    /// The caller should cache the proof privately before attempting verification
    /// because a temporary RPC failure must not require another relay read.
    pub async fn status(&self, channel_token: &str) -> Result<ChannelStatus, AuthError> {
        if !valid_channel(channel_token) {
            return Err(AuthError::InvalidRelayResponse);
        }
        let url = self
            .relay
            .join("v1/channel/status")
            .map_err(|_| AuthError::InvalidConfig)?;
        let (status, response) = self
            .send(self.client.get(url).bearer_auth(channel_token))
            .await?;
        if status == StatusCode::UNAUTHORIZED {
            return Err(AuthError::ChannelExpired);
        }
        if !matches!(status, StatusCode::OK | StatusCode::ACCEPTED) {
            return Err(AuthError::Unavailable);
        }
        #[derive(Deserialize)]
        struct Status {
            state: String,
            message: Option<String>,
            signature: Option<String>,
        }
        let data: Status =
            serde_json::from_slice(&response).map_err(|_| AuthError::InvalidRelayResponse)?;
        match (status, data.state.as_str()) {
            (StatusCode::ACCEPTED, "pending") => Ok(ChannelStatus::Pending),
            (StatusCode::OK, "completed") => {
                let message = data.message.ok_or(AuthError::InvalidRelayResponse)?;
                let signature = data.signature.ok_or(AuthError::InvalidRelayResponse)?;
                if message.len() > message::MAX_MESSAGE_BYTES
                    || signature.len() > message::MAX_SIGNATURE_BYTES * 2 + 2
                {
                    return Err(AuthError::InvalidRelayResponse);
                }
                Ok(ChannelStatus::Completed(SignedProof { message, signature }))
            }
            _ => Err(AuthError::InvalidRelayResponse),
        }
    }

    /// Check message consent, signature, and registry authority at one finalized
    /// Optimism block. RPC URLs are operator trust roots, not cryptographic state
    /// proofs. This never accepts unsigned FIDs, names or custody from the relay.
    pub async fn verify(
        &self,
        proof: &SignedProof,
        challenge: &Challenge,
        now: u64,
    ) -> Result<VerifiedIdentity, AuthError> {
        let parsed = message::parse(proof, challenge, &self.config.domain, &self.config.uri, now)?;
        self.verify_authority(parsed, now, None).await
    }

    /// Revalidate private evidence for an existing credential, including the
    /// original contract signature and unchanged FID custody. This does not
    /// establish a new login or mint a new credential: the original challenge
    /// expiry is intentionally not reused as current consent. The caller must
    /// accept only its own previously persisted evidence and credential record.
    /// Finalized evidence must advance monotonically: a lower height or a
    /// different hash at the same height is an operational chain-evidence error.
    pub async fn recheck_identity(
        &self,
        identity: &VerifiedIdentity,
        proof: &SignedProof,
        now: u64,
    ) -> Result<VerifiedIdentity, AuthError> {
        let parsed = message::parse_authority(proof, &self.config.domain, &self.config.uri)?;
        if parsed.fid != identity.fid
            || format!("0x{}", hex::encode(parsed.message.address)) != identity.address
            || decode_hex(&identity.custody_address)?.len() != 20
        {
            return Err(AuthError::Unauthorized);
        }
        if identity.checked_at > now
            || identity.checked_block == 0
            || decode_hex(&identity.block_hash)?.len() != 32
        {
            return Err(AuthError::InvalidChainEvidence);
        }
        self.verify_authority(parsed, now, Some(identity)).await
    }

    async fn verify_authority(
        &self,
        parsed: message::ParsedProof,
        now: u64,
        expected_identity: Option<&VerifiedIdentity>,
    ) -> Result<VerifiedIdentity, AuthError> {
        let chain = self.rpc("eth_chainId", json!([])).await?;
        if quantity(chain.as_str().ok_or(AuthError::InvalidChainEvidence)?)? != 10 {
            return Err(AuthError::InvalidChainEvidence);
        }
        let block = self
            .rpc("eth_getBlockByNumber", json!(["finalized", false]))
            .await?;
        let number = quantity(field(&block, "number")?)?;
        let block_hash = field(&block, "hash")?.to_string();
        if decode_hex(&block_hash)?.len() != 32 {
            return Err(AuthError::InvalidChainEvidence);
        }
        let block_time = quantity(field(&block, "timestamp")?)?;
        if number == 0
            || block_time > now.saturating_add(60)
            || now.saturating_sub(block_time) > MAX_FINALIZED_AGE_SECONDS
        {
            return Err(AuthError::InvalidChainEvidence);
        }
        // Check monotonic evidence before any signature or registry verdict.
        // An out-of-date/forked provider must not cause credential revocation.
        if expected_identity.is_some_and(|previous| {
            number < previous.checked_block
                || (number == previous.checked_block
                    && !block_hash.eq_ignore_ascii_case(&previous.block_hash))
        }) {
            return Err(AuthError::InvalidChainEvidence);
        }
        let selector = json!({ "blockHash": block_hash, "requireCanonical": true });
        let address = format!("0x{}", hex::encode(parsed.message.address));
        let code = self.rpc("eth_getCode", json!([address, selector])).await?;
        let code = decode_hex(code.as_str().ok_or(AuthError::InvalidChainEvidence)?)?;
        let wallet_kind = if code.is_empty() {
            message::verify_eoa(&parsed)?;
            WalletKind::Eoa
        } else {
            if code.starts_with(&[0xef, 0x01, 0x00]) {
                return Err(AuthError::UnsupportedWallet);
            }
            let calldata = erc1271_calldata(&parsed.digest, &parsed.signature);
            let result = self.eth_call(&address, &calldata, &selector).await?;
            if result.len() != 32
                || result[..4] != [0x16, 0x26, 0xba, 0x7e]
                || result[4..].iter().any(|b| *b != 0)
            {
                return Err(AuthError::InvalidSignature);
            }
            WalletKind::Erc1271
        };
        let mut custody_call = function_selector("custodyOf(uint256)");
        append_word(&mut custody_call, parsed.fid);
        let custody = self.eth_call(ID_REGISTRY, &custody_call, &selector).await?;
        if custody.len() != 32 || custody[..12].iter().any(|b| *b != 0) {
            return Err(AuthError::InvalidChainEvidence);
        }
        if custody[12..].iter().all(|b| *b == 0) {
            return Err(AuthError::Unauthorized);
        }
        let custody_address = format!("0x{}", hex::encode(&custody[12..]));
        if expected_identity.is_some_and(|expected| expected.custody_address != custody_address) {
            return Err(AuthError::Unauthorized);
        }
        // Auth address keys are ABI-encoded 32-byte addresses, not raw 20 bytes.
        let auth_call = auth_key_calldata(parsed.fid, &parsed.message.address);
        let auth = self.eth_call(KEY_REGISTRY, &auth_call, &selector).await?;
        if auth.len() != 64 {
            return Err(AuthError::InvalidChainEvidence);
        }
        let key_state = word_u64(&auth[..32])?;
        let key_type = word_u64(&auth[32..])?;
        if key_state > 2 || key_type > u32::MAX as u64 {
            return Err(AuthError::InvalidChainEvidence);
        }
        let proof_kind = if key_state == 1 && key_type == 2 {
            ProofKind::AuthAddress
        } else {
            let custody_call = id_of_calldata(&parsed.message.address);
            let custody = self.eth_call(ID_REGISTRY, &custody_call, &selector).await?;
            if custody.len() != 32 {
                return Err(AuthError::InvalidChainEvidence);
            }
            if word_u64(&custody)? != parsed.fid || custody_address != address {
                return Err(AuthError::Unauthorized);
            }
            ProofKind::Custody
        };
        Ok(VerifiedIdentity {
            fid: parsed.fid,
            address,
            custody_address,
            wallet_kind,
            proof_kind,
            checked_block: number,
            block_hash,
            checked_at: now,
        })
    }

    async fn eth_call(&self, to: &str, data: &[u8], block: &Value) -> Result<Vec<u8>, AuthError> {
        let result = self
            .rpc(
                "eth_call",
                json!([{ "to": to, "data": format!("0x{}", hex::encode(data)) }, block]),
            )
            .await?;
        decode_hex(result.as_str().ok_or(AuthError::InvalidChainEvidence)?)
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value, AuthError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let (status, response) = self
            .send(
                self.client
                    .post(self.rpc.clone())
                    .header("Content-Type", "application/json")
                    .body(body.to_string()),
            )
            .await?;
        if status != StatusCode::OK {
            return Err(AuthError::Unavailable);
        }
        let value: Value =
            serde_json::from_slice(&response).map_err(|_| AuthError::InvalidChainEvidence)?;
        if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || value.get("id").and_then(Value::as_u64) != Some(1)
            || value.get("error").is_some()
        {
            return Err(AuthError::InvalidChainEvidence);
        }
        value
            .get("result")
            .cloned()
            .filter(|v| !v.is_null())
            .ok_or(AuthError::InvalidChainEvidence)
    }

    async fn send(&self, request: RequestBuilder) -> Result<(StatusCode, Vec<u8>), AuthError> {
        let mut response = request.send().await.map_err(|_| AuthError::Unavailable)?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err(AuthError::Unavailable);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| AuthError::Unavailable)? {
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(AuthError::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, bytes))
    }
}

fn safe_url(input: &str) -> Result<Url, AuthError> {
    if input.len() > 2048 {
        return Err(AuthError::InvalidConfig);
    }
    let url = Url::parse(input).map_err(|_| AuthError::InvalidConfig)?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    });
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || url.host_str().is_none()
        || input.contains('@')
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || input
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(AuthError::InvalidConfig);
    }
    Ok(url)
}

fn valid_channel(input: &str) -> bool {
    (8..=128).contains(&input.len())
        && input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

fn validate_auth_url(input: &str, token: &str) -> Result<(), AuthError> {
    if input.len() > 1024 {
        return Err(AuthError::InvalidRelayResponse);
    }
    let url = Url::parse(input).map_err(|_| AuthError::InvalidRelayResponse)?;
    let query: Vec<_> = url.query_pairs().collect();
    if url.scheme() != "https"
        || !matches!(url.host_str(), Some("farcaster.xyz" | "warpcast.com"))
        || url.path() != "/~/siwf"
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || query.len() != 1
        || query[0].0 != "channelToken"
        || query[0].1 != token
    {
        return Err(AuthError::InvalidRelayResponse);
    }
    Ok(())
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, AuthError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(AuthError::InvalidChainEvidence)
}

fn quantity(input: &str) -> Result<u64, AuthError> {
    let digits = input
        .strip_prefix("0x")
        .ok_or(AuthError::InvalidChainEvidence)?;
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return Err(AuthError::InvalidChainEvidence);
    }
    u64::from_str_radix(digits, 16).map_err(|_| AuthError::InvalidChainEvidence)
}

fn decode_hex(input: &str) -> Result<Vec<u8>, AuthError> {
    hex::decode(
        input
            .strip_prefix("0x")
            .ok_or(AuthError::InvalidChainEvidence)?,
    )
    .map_err(|_| AuthError::InvalidChainEvidence)
}

fn word_u64(word: &[u8]) -> Result<u64, AuthError> {
    if word.len() != 32 || word[..24].iter().any(|v| *v != 0) {
        return Err(AuthError::InvalidChainEvidence);
    }
    Ok(u64::from_be_bytes(
        word[24..]
            .try_into()
            .map_err(|_| AuthError::InvalidChainEvidence)?,
    ))
}

fn append_word(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&[0; 24]);
    output.extend_from_slice(&value.to_be_bytes());
}

fn function_selector(signature: &str) -> Vec<u8> {
    Keccak256::digest(signature.as_bytes())[..4].to_vec()
}

fn id_of_calldata(address: &[u8; 20]) -> Vec<u8> {
    let mut data = function_selector("idOf(address)");
    data.extend_from_slice(&[0; 12]);
    data.extend_from_slice(address);
    data
}

fn auth_key_calldata(fid: u64, address: &[u8; 20]) -> Vec<u8> {
    let mut data = function_selector("keyDataOf(uint256,bytes)");
    append_word(&mut data, fid);
    append_word(&mut data, 64);
    append_word(&mut data, 32);
    data.extend_from_slice(&[0; 12]);
    data.extend_from_slice(address);
    data
}

fn erc1271_calldata(digest: &[u8; 32], signature: &[u8]) -> Vec<u8> {
    let mut data = function_selector("isValidSignature(bytes32,bytes)");
    data.extend_from_slice(digest);
    append_word(&mut data, 64);
    append_word(&mut data, signature.len() as u64);
    data.extend_from_slice(signature);
    data.resize(data.len() + (32 - signature.len() % 32) % 32, 0);
    data
}
