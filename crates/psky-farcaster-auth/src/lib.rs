//! Farcaster sign-in without trusting relay profile metadata.
//!
//! The relay supplies a signed SIWE message, not an authenticated identity.
//! Verification checks the exact local challenge, then an Ethereum signature
//! and the Farcaster registries on Optimism at one finalized block. It accepts
//! EOA and deployed ERC-1271 wallets, using either custody or an active type-2
//! authentication address. An Ed25519 messaging signer is a separate permission.
//!
//! The caller owns challenge generation, one-time consumption, rate limits,
//! account policy and persistence. A completed relay read consumes its channel;
//! retain the returned proof privately before doing retryable RPC verification.
//! No channel, proof or client implements `Debug`. Signed proofs can be stored
//! as private credential evidence for later contract-signature rechecks.
//!
//! Protocol source: [Farcaster Auth at ae3dffd](https://github.com/farcasterxyz/auth-monorepo/tree/ae3dffd339a161bcbed870cf0f3cd36b756b94b2).
//! SIWE parsing uses the pinned Spruce parser with an exact round-trip check to
//! reject its permissive blank-line handling. Counterfactual ERC-6492 and
//! EIP-7702 delegated-account signatures are not supported and fail closed.

mod client;
mod message;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use client::{AuthClient, AuthConfig};

/// Maximum lifetime of a local sign-in challenge, in seconds.
pub const MAX_CHALLENGE_SECONDS: u64 = 600;

/// Server-generated challenge state. Keep the nonce private until handing off
/// the login link, and atomically consume a challenge at most once on success.
#[derive(Clone)]
pub struct Challenge {
    /// A cryptographically random alphanumeric value, 16 to 128 characters.
    pub nonce: String,
    /// Creation time as Unix seconds.
    pub created_at: u64,
    /// Expiration as Unix seconds, at most ten minutes after creation.
    pub expires_at: u64,
}

/// The secret channel and validated Farcaster sign-in URL.
///
/// Both fields are sensitive: the URL includes the channel capability. Never
/// log them or place them in persistent browser storage.
pub struct Channel {
    /// Relay bearer capability. Keep on the server.
    pub channel_token: String,
    /// HTTPS link for the user's Farcaster client.
    pub auth_url: String,
}

/// A relay response. Completion alone does not establish identity.
pub enum ChannelStatus {
    /// The user's client has not returned a proof.
    Pending,
    /// An untrusted proof which must be independently verified.
    Completed(SignedProof),
}

/// Untrusted signed message returned by the relay. Keep it out of logs.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedProof {
    /// Exact UTF-8 SIWE message bytes represented as a string.
    pub message: String,
    /// Hex-encoded signature with a `0x` prefix.
    pub signature: String,
}

/// Farcaster registry permission used for a verified login.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    /// The signing address owned this FID at the checked block.
    Custody,
    /// The signing address was an active type-2 authentication key.
    AuthAddress,
}

/// Ethereum signature verification used for this identity.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalletKind {
    /// An externally owned account using an ERC-191 secp256k1 signature.
    Eoa,
    /// A deployed contract accepting the signature through ERC-1271.
    Erc1271,
}

/// Minimal identity evidence after signature and registry verification.
///
/// No usernames or profiles from the relay are trusted. A later custody/key
/// change can invalidate this authority; credentials need revocation policy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// Positive Farcaster identifier, limited to the JavaScript safe range.
    pub fid: u64,
    /// Lowercase Ethereum address whose SIWE proof was checked.
    pub address: String,
    /// FID custody snapshot; changes invalidate existing credential evidence.
    pub custody_address: String,
    /// Signature verification method used for this address.
    pub wallet_kind: WalletKind,
    /// Registry permission proven for the signing address.
    pub proof_kind: ProofKind,
    /// Optimism finalized block number used for all registry reads.
    pub checked_block: u64,
    /// Hash of the same finalized Optimism block.
    pub block_hash: String,
    /// Verification time, in Unix seconds.
    pub checked_at: u64,
}

/// Fixed errors safe to display. Transport URLs, request bodies, channel tokens
/// and untrusted upstream error messages are never included.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    /// The application supplied an invalid or unsafe configuration.
    #[error("invalid Farcaster authentication configuration")]
    InvalidConfig,
    /// The local challenge is invalid or has expired.
    #[error("Farcaster sign-in challenge expired or invalid")]
    InvalidChallenge,
    /// The relay response was absent, malformed or inconsistent.
    #[error("Farcaster relay returned an invalid response")]
    InvalidRelayResponse,
    /// The relay no longer recognizes the channel.
    #[error("Farcaster sign-in channel expired or was already consumed")]
    ChannelExpired,
    /// A bounded request failed or timed out.
    #[error("Farcaster authentication service is unavailable; retry shortly")]
    Unavailable,
    /// The signed message does not match the application challenge.
    #[error("Farcaster sign-in message does not match this challenge")]
    InvalidMessage,
    /// Ethereum signature verification failed.
    #[error("Farcaster sign-in signature is invalid")]
    InvalidSignature,
    /// An unsupported contract-wallet signature was supplied.
    #[error("this Farcaster wallet signature type is not supported")]
    UnsupportedWallet,
    /// RPC chain, block identity or response format was unsafe.
    #[error("Optimism identity verification returned invalid chain evidence")]
    InvalidChainEvidence,
    /// The valid signer has no current Farcaster authority for the claimed FID.
    #[error("signing address is not authorized for this Farcaster identity")]
    Unauthorized,
}
