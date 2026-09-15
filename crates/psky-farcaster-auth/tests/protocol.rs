//! Loopback protocol fixtures. No live identity, wallet or external service is used.

use k256::ecdsa::SigningKey;
use psky_farcaster_auth::{
    AuthClient, AuthConfig, AuthError, Challenge, ChannelStatus, ProofKind, SignedProof, WalletKind,
};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use std::sync::{Arc, Mutex};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

const NOW: u64 = 1_770_000_000;
const FID: u64 = 8531;
const ADDRESS: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";
const TOKEN: &str = "synthetic-channel-0123456789";
const BLOCK_HASH: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

fn stamp(value: u64) -> String {
    OffsetDateTime::from_unix_timestamp(value as i64)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

fn challenge() -> Challenge {
    Challenge {
        nonce: "0123456789ABCDEF0123456789ABCDEF".into(),
        created_at: NOW,
        expires_at: NOW + 300,
    }
}

fn proof() -> SignedProof {
    let challenge = challenge();
    let message = format!(
        "pds.example wants you to sign in with your Ethereum account:\n{ADDRESS}\n\nFarcaster Auth\n\nURI: https://pds.example/onboard\nVersion: 1\nChain ID: 10\nNonce: {}\nIssued At: {}\nExpiration Time: {}\nNot Before: {}\nResources:\n- farcaster://fid/{FID}",
        challenge.nonce,
        stamp(NOW),
        stamp(NOW + 300),
        stamp(NOW)
    );
    let mut key = [0; 32];
    key[31] = 1;
    let key = SigningKey::from_bytes((&key).into()).unwrap();
    let input = format!("\x19Ethereum Signed Message:\n{}{message}", message.len());
    let (signature, recovery) = key
        .sign_digest_recoverable(Keccak256::new_with_prefix(input.as_bytes()))
        .unwrap();
    let mut signature = signature.to_bytes().to_vec();
    signature.push(recovery.to_byte() + 27);
    SignedProof {
        message,
        signature: format!("0x{}", hex::encode(signature)),
    }
}

fn config(base: &str) -> AuthConfig {
    AuthConfig {
        domain: "pds.example".into(),
        uri: "https://pds.example/onboard".into(),
        relay_url: base.into(),
        optimism_rpc_url: format!("{base}/rpc"),
    }
}

type Handler = dyn Fn(&str, &str, Value) -> (u16, Value) + Send + Sync;

struct Mock {
    url: String,
    task: JoinHandle<()>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn mock(handler: impl Fn(&str, &str, Value) -> (u16, Value) + Send + Sync + 'static) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handler: Arc<Handler> = Arc::new(handler);
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let handler = handler.clone();
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                let mut buffer = [0; 4096];
                let (headers_end, content_length) = loop {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&buffer[..read]);
                    assert!(bytes.len() < 65536);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                        let content_length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(|v| v.parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        break (end + 4, content_length);
                    }
                };
                while bytes.len() < headers_end + content_length {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&buffer[..read]);
                }
                let headers = std::str::from_utf8(&bytes[..headers_end]).unwrap();
                let path = headers.split_whitespace().nth(1).unwrap();
                let value = serde_json::from_slice(&bytes[headers_end..]).unwrap_or(Value::Null);
                let (status, body) = handler(path, headers, value);
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    Mock { url, task }
}

#[derive(Clone)]
struct Chain {
    chain_id: String,
    block_number: u64,
    block_timestamp: u64,
    block_hash: String,
    code: String,
    auth_key: bool,
    custody: String,
    owner_fid: u64,
    signature_valid: bool,
    rpc_error: bool,
    calls: Vec<Value>,
}

impl Default for Chain {
    fn default() -> Self {
        Self {
            chain_id: "0xa".into(),
            block_number: 256,
            block_timestamp: NOW - 60,
            block_hash: BLOCK_HASH.into(),
            code: "0x".into(),
            auth_key: false,
            custody: ADDRESS.to_lowercase(),
            owner_fid: FID,
            signature_valid: true,
            rpc_error: false,
            calls: Vec::new(),
        }
    }
}

fn selector(signature: &str) -> String {
    hex::encode(&Keccak256::digest(signature.as_bytes())[..4])
}
fn word(number: u64) -> String {
    format!("{number:064x}")
}

async fn rpc_mock(state: Arc<Mutex<Chain>>) -> Mock {
    mock(move |path, _, request| {
        assert_eq!(path, "/rpc");
        let mut state = state.lock().unwrap();
        state.calls.push(request.clone());
        if state.rpc_error { return (200, json!({"jsonrpc":"2.0", "id":1,"error":{"code":-1,"message":"UPSTREAM SECRET MUST NOT LEAK"}})); }
        let result = match request["method"].as_str().unwrap() {
            "eth_chainId" => json!(state.chain_id),
            "eth_getBlockByNumber" => {
                assert_eq!(request["params"], json!(["finalized", false]));
                json!({"number":format!("0x{:x}",state.block_number), "hash":state.block_hash, "timestamp":format!("0x{:x}", state.block_timestamp)})
            }
            "eth_getCode" => {
                assert_eq!(request["params"][0], json!(ADDRESS.to_lowercase()));
                assert_eq!(request["params"][1], json!({"blockHash":state.block_hash,"requireCanonical":true}));
                json!(state.code)
            }
            "eth_call" => {
                assert_eq!(request["params"][1], json!({"blockHash":state.block_hash,"requireCanonical":true}));
                let data = request["params"][0]["data"].as_str().unwrap();
                let signature = &data[2..10];
                if signature == selector("custodyOf(uint256)") {
                    assert_eq!(request["params"][0]["to"], "0x00000000fc6c5f01fc30151999387bb99a9f489b");
                    assert_eq!(&data[10..], word(FID));
                    json!(format!("0x{}{}", "0".repeat(24), &state.custody[2..]))
                } else if signature == selector("keyDataOf(uint256,bytes)") {
                    assert_eq!(request["params"][0]["to"], "0x00000000fc1237824fb747abde0ff18990e59b7e");
                    assert_eq!(&data[10..], format!("{}{}{}{}{}", word(FID), word(64), word(32), "0".repeat(24), ADDRESS[2..].to_lowercase()));
                    json!(if state.auth_key { format!("0x{}{}", word(1), word(2)) } else { format!("0x{}{}", word(0), word(0)) })
                } else if signature == selector("idOf(address)") {
                    assert_eq!(&data[10..], format!("{}{}", "0".repeat(24), ADDRESS[2..].to_lowercase()));
                    json!(format!("0x{}", word(state.owner_fid)))
                } else if signature == "1626ba7e" {
                    let signed = proof();
                    let expected_digest = Keccak256::digest(format!("\x19Ethereum Signed Message:\n{}{}", signed.message.len(), signed.message));
                    assert_eq!(&data[10..74], hex::encode(expected_digest));
                    assert_eq!(&data[74..138], word(64));
                    assert_eq!(&data[138..202], word(65));
                    assert_eq!(&data[202..332], &signed.signature[2..]);
                    assert_eq!(data.len(), 2 + 4 * 2 + 32 * 2 * 6);
                    json!(format!("0x{}{}", if state.signature_valid { "1626ba7e" } else { "ffffffff" }, "0".repeat(56)))
                } else { panic!("unexpected contract selector") }
            }
            _ => panic!("unexpected RPC method"),
        };
        (200, json!({"jsonrpc":"2.0", "id":1, "result":result}))
    }).await
}

#[test]
fn config_rejects_credentials_insecure_origins_and_mismatched_binding() {
    for url in [
        "http://example.com",
        "https://user:password@example.com",
        "https://@example.com",
        "https://example.com?secret=1",
        "https://example.com/#secret",
        "file:///tmp/token",
        "https://example.com\n",
    ] {
        let mut item = config("https://relay.farcaster.xyz");
        item.optimism_rpc_url = url.into();
        assert_eq!(item.validate(), Err(AuthError::InvalidConfig));
    }
    let mut item = config("https://relay.farcaster.xyz/path");
    assert_eq!(item.validate(), Err(AuthError::InvalidConfig));
    item = config("https://relay.farcaster.xyz");
    item.domain = "other.example".into();
    assert_eq!(item.validate(), Err(AuthError::InvalidConfig));
    item = config("https://relay.farcaster.xyz");
    item.domain = "pds.example:443".into();
    assert_eq!(item.validate(), Err(AuthError::InvalidConfig));
}

#[test]
fn exact_localhost_http_is_allowed_but_lookalikes_are_not() {
    let item = AuthConfig {
        domain: "localhost:8787".into(),
        uri: "http://localhost:8787/account".into(),
        relay_url: "http://localhost:9".into(),
        optimism_rpc_url: "http://localhost:9".into(),
    };
    assert_eq!(item.validate(), Ok(()));
    for host in ["localhost.evil", "evil-localhost", "localhost."] {
        let mut invalid = item.clone();
        invalid.optimism_rpc_url = format!("http://{host}:9");
        assert_eq!(invalid.validate(), Err(AuthError::InvalidConfig));
        invalid = item.clone();
        invalid.domain = format!("{host}:8787");
        invalid.uri = format!("http://{host}:8787/account");
        assert_eq!(invalid.validate(), Err(AuthError::InvalidConfig));
    }
}

#[tokio::test]
async fn channel_creation_binds_all_signed_fields_and_only_auth_permission() {
    let server = mock(|path, headers, body| {
        assert_eq!(path, "/v1/channel"); assert!(headers.starts_with("POST "));
        assert_eq!(body, json!({"domain":"pds.example", "siweUri":"https://pds.example/onboard", "nonce":challenge().nonce,"notBefore":stamp(NOW), "expirationTime":stamp(NOW+300), "acceptAuthAddress":true}));
        (201, json!({"channelToken":TOKEN,"url":format!("https://farcaster.xyz/~/siwf?channelToken={TOKEN}"),"nonce":challenge().nonce}))
    }).await;
    let client = AuthClient::new(config(&server.url)).unwrap();
    let channel = client.start(&challenge()).await.unwrap();
    assert_eq!(channel.channel_token, TOKEN);
    assert_eq!(
        channel.auth_url,
        format!("https://farcaster.xyz/~/siwf?channelToken={TOKEN}")
    );
}

#[tokio::test]
async fn relay_auth_url_must_be_known_wallet_exact_path_and_same_capability() {
    for url in [
        format!("https://evil.example/~/siwf?channelToken={TOKEN}"),
        format!("javascript:alert('{TOKEN}')"),
        format!(
            "https://farcaster.xyz/~/siwf?channelToken={TOKEN}&redirectUrl=https://evil.example"
        ),
        "https://farcaster.xyz/~/siwf?channelToken=other".into(),
    ] {
        let server = mock(move |_, _, _| {
            (
                201,
                json!({"channelToken":TOKEN,"url":url,"nonce":challenge().nonce}),
            )
        })
        .await;
        let client = AuthClient::new(config(&server.url)).unwrap();
        assert_eq!(
            client.start(&challenge()).await.err(),
            Some(AuthError::InvalidRelayResponse)
        );
    }
}

#[tokio::test]
async fn relay_nonce_cannot_replace_server_challenge() {
    let server = mock(|_, _, _| (201, json!({"channelToken":TOKEN,"url":format!("https://farcaster.xyz/~/siwf?channelToken={TOKEN}"),"nonce":"differentnonce123456"}))).await;
    assert_eq!(
        AuthClient::new(config(&server.url))
            .unwrap()
            .start(&challenge())
            .await
            .err(),
        Some(AuthError::InvalidRelayResponse)
    );
}

#[tokio::test]
async fn relay_status_uses_bearer_and_distinguishes_pending_completed() {
    for (code, state) in [(202, "pending"), (200, "completed")] {
        let server = mock(move |path, headers, _| {
            assert_eq!(path, "/v1/channel/status");
            assert!(headers.to_lowercase().contains(&format!("authorization: bearer {TOKEN}")));
            (code, json!({"state":state,"message":proof().message,"signature":proof().signature,"fid":999999,"custody":"UNTRUSTED"}))
        }).await;
        let result = AuthClient::new(config(&server.url))
            .unwrap()
            .status(TOKEN)
            .await
            .unwrap();
        match (code, result) {
            (202, ChannelStatus::Pending) => {}
            (200, ChannelStatus::Completed(value)) => assert_eq!(value.message, proof().message),
            _ => panic!("wrong channel status"),
        }
    }
}

#[tokio::test]
async fn relay_malformed_and_expired_responses_fail_closed() {
    for (status, body, expected) in [
        (
            401,
            json!({"secret":"sensitive"}),
            AuthError::ChannelExpired,
        ),
        (
            202,
            json!({"state":"completed"}),
            AuthError::InvalidRelayResponse,
        ),
        (
            200,
            json!({"state":"completed"}),
            AuthError::InvalidRelayResponse,
        ),
        (500, json!({"error":"sensitive"}), AuthError::Unavailable),
    ] {
        let server = mock(move |_, _, _| (status, body.clone())).await;
        let error = AuthClient::new(config(&server.url))
            .unwrap()
            .status(TOKEN)
            .await
            .err()
            .unwrap();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("sensitive"));
    }
}

#[tokio::test]
async fn oversized_body_fails_closed() {
    let server =
        mock(|_, _, _| (202, json!({"state":"pending","padding":"x".repeat(65536)}))).await;
    assert_eq!(
        AuthClient::new(config(&server.url))
            .unwrap()
            .status(TOKEN)
            .await
            .err(),
        Some(AuthError::Unavailable)
    );
}

#[tokio::test]
async fn custody_eoa_verification_pins_every_rpc_read_to_finalized_hash() {
    let state = Arc::new(Mutex::new(Chain::default()));
    let server = rpc_mock(state.clone()).await;
    let identity = AuthClient::new(config(&server.url))
        .unwrap()
        .verify(&proof(), &challenge(), NOW + 1)
        .await
        .unwrap();
    assert_eq!(identity.fid, FID);
    assert_eq!(identity.address, ADDRESS.to_lowercase());
    assert_eq!(identity.custody_address, ADDRESS.to_lowercase());
    assert_eq!(identity.proof_kind, ProofKind::Custody);
    assert_eq!(identity.wallet_kind, WalletKind::Eoa);
    assert_eq!(identity.checked_block, 256);
    assert_eq!(identity.block_hash, BLOCK_HASH);
    assert_eq!(state.lock().unwrap().calls.len(), 6);
}

#[tokio::test]
async fn active_type_two_auth_key_does_not_need_custody_signature() {
    let state = Arc::new(Mutex::new(Chain {
        auth_key: true,
        owner_fid: 0,
        custody: "0x2222222222222222222222222222222222222222".into(),
        ..Chain::default()
    }));
    let server = rpc_mock(state.clone()).await;
    let identity = AuthClient::new(config(&server.url))
        .unwrap()
        .verify(&proof(), &challenge(), NOW + 1)
        .await
        .unwrap();
    assert_eq!(identity.proof_kind, ProofKind::AuthAddress);
    assert_eq!(state.lock().unwrap().calls.len(), 5);
}

#[tokio::test]
async fn unauthorized_signer_cannot_claim_a_real_fid() {
    let state = Arc::new(Mutex::new(Chain {
        owner_fid: 0,
        ..Chain::default()
    }));
    let server = rpc_mock(state).await;
    assert_eq!(
        AuthClient::new(config(&server.url))
            .unwrap()
            .verify(&proof(), &challenge(), NOW + 1)
            .await
            .err(),
        Some(AuthError::Unauthorized)
    );
}

#[tokio::test]
async fn wrong_chain_stale_block_and_invalid_hash_fail_closed() {
    for state in [
        Chain {
            chain_id: "0x1".into(),
            ..Chain::default()
        },
        Chain {
            block_timestamp: NOW - 3601,
            ..Chain::default()
        },
        Chain {
            block_timestamp: NOW + 100,
            ..Chain::default()
        },
        Chain {
            block_hash: "0x00".into(),
            ..Chain::default()
        },
    ] {
        let server = rpc_mock(Arc::new(Mutex::new(state))).await;
        assert_eq!(
            AuthClient::new(config(&server.url))
                .unwrap()
                .verify(&proof(), &challenge(), NOW + 1)
                .await
                .err(),
            Some(AuthError::InvalidChainEvidence)
        );
    }
}

#[tokio::test]
async fn rpc_errors_do_not_expose_upstream_details() {
    let server = rpc_mock(Arc::new(Mutex::new(Chain {
        rpc_error: true,
        ..Chain::default()
    })))
    .await;
    let error = AuthClient::new(config(&server.url))
        .unwrap()
        .verify(&proof(), &challenge(), NOW + 1)
        .await
        .err()
        .unwrap();
    assert_eq!(error, AuthError::InvalidChainEvidence);
    assert!(!format!("{error:?} {error}").contains("SECRET"));
}

#[tokio::test]
async fn deployed_erc1271_contract_must_return_exact_magic() {
    for valid in [true, false] {
        let state = Arc::new(Mutex::new(Chain {
            code: "0x6000".into(),
            signature_valid: valid,
            ..Chain::default()
        }));
        let server = rpc_mock(state).await;
        let result = AuthClient::new(config(&server.url))
            .unwrap()
            .verify(&proof(), &challenge(), NOW + 1)
            .await;
        if valid {
            assert_eq!(result.unwrap().wallet_kind, WalletKind::Erc1271);
        } else {
            assert_eq!(result.err(), Some(AuthError::InvalidSignature));
        }
    }
}

#[tokio::test]
async fn eip7702_delegated_account_is_explicitly_unsupported() {
    let server = rpc_mock(Arc::new(Mutex::new(Chain {
        code: format!("0xef0100{}", "11".repeat(20)),
        ..Chain::default()
    })))
    .await;
    assert_eq!(
        AuthClient::new(config(&server.url))
            .unwrap()
            .verify(&proof(), &challenge(), NOW + 1)
            .await
            .err(),
        Some(AuthError::UnsupportedWallet)
    );
}

#[tokio::test]
async fn recheck_preserves_authority_but_does_not_replay_expired_login() {
    let state = Arc::new(Mutex::new(Chain::default()));
    let server = rpc_mock(state).await;
    let client = AuthClient::new(config(&server.url)).unwrap();
    let identity = client
        .verify(&proof(), &challenge(), NOW + 1)
        .await
        .unwrap();
    let fresh = client
        .recheck_identity(&identity, &proof(), NOW + 400)
        .await
        .unwrap();
    assert_eq!(fresh.checked_at, NOW + 400);
    assert_eq!(
        client.verify(&proof(), &challenge(), NOW + 400).await.err(),
        Some(AuthError::InvalidChallenge)
    );
}

#[tokio::test]
async fn finalized_height_rollback_is_operational_not_revocation() {
    let state = Arc::new(Mutex::new(Chain::default()));
    let server = rpc_mock(state.clone()).await;
    let client = AuthClient::new(config(&server.url)).unwrap();
    let identity = client
        .verify(&proof(), &challenge(), NOW + 1)
        .await
        .unwrap();
    {
        let mut chain = state.lock().unwrap();
        chain.block_number = 255;
        // Even if this stale state would deny authority, do not reach that
        // verdict and permanently revoke the user's credentials.
        chain.owner_fid = 0;
    }
    assert_eq!(
        client
            .recheck_identity(&identity, &proof(), NOW + 2)
            .await
            .err(),
        Some(AuthError::InvalidChainEvidence)
    );
    assert_eq!(state.lock().unwrap().calls.len(), 8);
}

#[tokio::test]
async fn finalized_same_height_fork_is_operational_not_revocation() {
    let state = Arc::new(Mutex::new(Chain::default()));
    let server = rpc_mock(state.clone()).await;
    let client = AuthClient::new(config(&server.url)).unwrap();
    let identity = client
        .verify(&proof(), &challenge(), NOW + 1)
        .await
        .unwrap();
    {
        let mut chain = state.lock().unwrap();
        chain.block_hash = format!("0x{}", "22".repeat(32));
        chain.owner_fid = 0;
    }
    assert_eq!(
        client
            .recheck_identity(&identity, &proof(), NOW + 2)
            .await
            .err(),
        Some(AuthError::InvalidChainEvidence)
    );
    assert_eq!(state.lock().unwrap().calls.len(), 8);
}

#[tokio::test]
async fn finalized_evidence_can_advance_to_a_new_block_hash() {
    let state = Arc::new(Mutex::new(Chain::default()));
    let server = rpc_mock(state.clone()).await;
    let client = AuthClient::new(config(&server.url)).unwrap();
    let identity = client
        .verify(&proof(), &challenge(), NOW + 1)
        .await
        .unwrap();
    {
        let mut chain = state.lock().unwrap();
        chain.block_number = 257;
        chain.block_hash = format!("0x{}", "22".repeat(32));
    }
    let fresh = client
        .recheck_identity(&identity, &proof(), NOW + 2)
        .await
        .unwrap();
    assert_eq!(fresh.checked_block, 257);
    assert_eq!(fresh.block_hash, format!("0x{}", "22".repeat(32)));
}

#[tokio::test]
async fn local_clock_rollback_is_operational_not_revocation() {
    let state = Arc::new(Mutex::new(Chain::default()));
    let server = rpc_mock(state.clone()).await;
    let client = AuthClient::new(config(&server.url)).unwrap();
    let identity = client
        .verify(&proof(), &challenge(), NOW + 1)
        .await
        .unwrap();
    assert_eq!(
        client
            .recheck_identity(&identity, &proof(), NOW)
            .await
            .err(),
        Some(AuthError::InvalidChainEvidence)
    );
    assert_eq!(state.lock().unwrap().calls.len(), 6);
}

#[tokio::test]
async fn fid_transfer_invalidates_auth_address_even_if_key_remains_registered() {
    let state = Arc::new(Mutex::new(Chain {
        auth_key: true,
        ..Chain::default()
    }));
    let server = rpc_mock(state.clone()).await;
    let client = AuthClient::new(config(&server.url)).unwrap();
    let identity = client
        .verify(&proof(), &challenge(), NOW + 1)
        .await
        .unwrap();
    state.lock().unwrap().custody = "0x2222222222222222222222222222222222222222".into();
    assert_eq!(
        client
            .recheck_identity(&identity, &proof(), NOW + 2)
            .await
            .err(),
        Some(AuthError::Unauthorized)
    );
}

#[tokio::test]
async fn revoked_auth_key_invalidates_credentials() {
    let state = Arc::new(Mutex::new(Chain {
        auth_key: true,
        owner_fid: 0,
        ..Chain::default()
    }));
    let server = rpc_mock(state.clone()).await;
    let client = AuthClient::new(config(&server.url)).unwrap();
    let identity = client
        .verify(&proof(), &challenge(), NOW + 1)
        .await
        .unwrap();
    state.lock().unwrap().auth_key = false;
    assert_eq!(
        client
            .recheck_identity(&identity, &proof(), NOW + 2)
            .await
            .err(),
        Some(AuthError::Unauthorized)
    );
}

#[tokio::test]
async fn changed_contract_signature_policy_invalidates_credentials() {
    let state = Arc::new(Mutex::new(Chain {
        code: "0x6000".into(),
        ..Chain::default()
    }));
    let server = rpc_mock(state.clone()).await;
    let client = AuthClient::new(config(&server.url)).unwrap();
    let identity = client
        .verify(&proof(), &challenge(), NOW + 1)
        .await
        .unwrap();
    state.lock().unwrap().signature_valid = false;
    assert_eq!(
        client
            .recheck_identity(&identity, &proof(), NOW + 2)
            .await
            .err(),
        Some(AuthError::InvalidSignature)
    );
}

#[tokio::test]
async fn persisted_evidence_cannot_be_rebound_to_another_identity() {
    let server = rpc_mock(Arc::new(Mutex::new(Chain::default()))).await;
    let client = AuthClient::new(config(&server.url)).unwrap();
    let mut identity = client
        .verify(&proof(), &challenge(), NOW + 1)
        .await
        .unwrap();
    identity.fid += 1;
    assert_eq!(
        client
            .recheck_identity(&identity, &proof(), NOW + 2)
            .await
            .err(),
        Some(AuthError::Unauthorized)
    );
}

#[tokio::test]
async fn bad_consent_is_rejected_without_any_network_calls() {
    let server = mock(|_, _, _| panic!("invalid proof triggered a network request")).await;
    let client = AuthClient::new(config(&server.url)).unwrap();
    let mut wrong = proof();
    wrong.message = wrong
        .message
        .replace("pds.example wants", "evil.example wants");
    assert_eq!(
        client.verify(&wrong, &challenge(), NOW + 1).await.err(),
        Some(AuthError::InvalidMessage)
    );
}

#[tokio::test]
async fn rpc_envelope_requires_matching_id_and_jsonrpc_version() {
    for body in [
        json!({"jsonrpc":"2.0", "id":2, "result":"0xa"}),
        json!({"jsonrpc":"1.0", "id":1, "result":"0xa"}),
        json!({"jsonrpc":"2.0", "id":1, "result":null}),
        json!({"jsonrpc":"2.0", "id":1, "result":"0x0a"}),
    ] {
        let server = mock(move |_, _, _| (200, body.clone())).await;
        let client = AuthClient::new(config(&server.url)).unwrap();
        assert_eq!(
            client.verify(&proof(), &challenge(), NOW + 1).await.err(),
            Some(AuthError::InvalidChainEvidence)
        );
    }
}

#[tokio::test]
async fn response_redirect_cannot_forward_relay_bearer() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_url = format!("http://{}/stolen", target.local_addr().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", listener.local_addr().unwrap());
    let source = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 8192];
        assert!(stream.read(&mut buffer).await.unwrap() > 0);
        let reply = format!(
            "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(reply.as_bytes()).await.unwrap();
    });
    let client = AuthClient::new(config(&relay_url)).unwrap();
    assert_eq!(
        client.status(TOKEN).await.err(),
        Some(AuthError::Unavailable)
    );
    source.await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), target.accept())
            .await
            .is_err()
    );
}
