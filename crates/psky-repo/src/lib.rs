//! Deterministic, bounded ATProto repository construction for offline experiments.
//!
//! This crate builds ordinary v3 commits, an ATProto Merkle Search Tree (MST),
//! and CARv1 exports. It has no Hypersnap persistence, identity resolution,
//! authorization, production key storage, or publication policy. The caller
//! supplies the DID, revision, records, and signing key. Revisions must come
//! from the canonical publication policy, never a worker's replay-time clock.
//!
//! The MST is rebuilt from a sorted map on every commit. This keeps this small
//! experiment auditable; it is not the incremental algorithm a full PDS needs.
//! Tests use the [ATProto reference implementation's MST vectors][vectors].
//!
//! ```
//! use psky_repo::{RecordSet, RepoSigner, Repository};
//! use serde_json::json;
//!
//! let mut records = RecordSet::new();
//! records.put("app.bsky.feed.post/3jzfcijpj2z2a", &json!({
//!     "$type": "app.bsky.feed.post",
//!     "text": "Hello PurpleSky",
//!     "createdAt": "2026-09-15T00:00:00Z"
//! }))?;
//! // Public fixture key only. Never use this key for a real account.
//! let signer = RepoSigner::from_bytes([1; 32])?;
//! let repo = Repository::build(
//!     "did:plc:abcdefghijklmnopqrstuvwx", "3jzfcijpj2z2a", &records, &signer,
//! )?;
//! repo.verify(&signer.public_key_sec1())?;
//! let car = repo.to_car()?;
//! assert!(!car.is_empty());
//! # Ok::<(), psky_repo::Error>(())
//! ```
//!
//! [vectors]: https://github.com/bluesky-social/atproto/blob/2e1787c2bf5bd47b55c3df930d688bb40b5ae63d/packages/repo/tests/mst.test.ts

mod car;
mod mst;
mod syntax;

use base64::{
    alphabet,
    engine::{
        general_purpose::{GeneralPurpose, GeneralPurposeConfig},
        DecodePaddingMode,
    },
    Engine,
};
pub use cid::Cid;
use ipld_core::ipld::Ipld;
use k256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Maximum encoded record size accepted by this in-memory prototype.
pub const MAX_RECORD_BYTES: usize = 1_000_000;
/// Maximum number of records in one prototype repository.
pub const MAX_RECORDS: usize = 100_000;
/// Maximum combined canonical record bytes in one in-memory projection (16 MiB).
///
/// Repository construction copies records and adds tree/commit blocks, so this
/// bounds the input payload rather than the process's entire resident memory.
pub const MAX_TOTAL_RECORD_BYTES: usize = 16 * 1024 * 1024;
/// Maximum nesting of JSON/IPLD values accepted before serialization.
pub const MAX_RECORD_DEPTH: usize = 64;

// ATProto permits omitted padding, while requiring RFC4648's standard alphabet.
// Keep trailing-bit validation strict so alternate bit patterns cannot silently
// decode to the same bytes. JSON itself need not have a unique representation.
const ATPROTO_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(false),
);

/// Validation, encoding, or verification failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A record path is not a normalized collection and record key.
    #[error("invalid repository path: {0}")]
    InvalidPath(String),
    /// A DID or revision failed syntax validation.
    #[error("invalid commit metadata: {0}")]
    InvalidMetadata(String),
    /// A record does not use the supported ATProto data-model subset.
    #[error("invalid record: {0}")]
    InvalidRecord(String),
    /// The bounded prototype cannot safely accept this input size.
    #[error("repository limit exceeded: {0}")]
    Limit(&'static str),
    /// DAG-CBOR serialization or parsing failed.
    #[error("DAG-CBOR error: {0}")]
    Cbor(String),
    /// A key or signature is invalid.
    #[error("invalid signing key or signature")]
    Signature,
    /// A repository block or structure failed verification.
    #[error("repository verification failed: {0}")]
    Verification(String),
}

/// An encoded immutable record and its SHA-256 DAG-CBOR CID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    cid: Cid,
    bytes: Vec<u8>,
}

impl Record {
    /// Content identifier of the canonical record bytes.
    pub fn cid(&self) -> Cid {
        self.cid
    }

    /// Canonical DAG-CBOR bytes, suitable for a CAR block.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A disposable materialized record map, sorted by repository path.
///
/// This is local projection state, not a persistence or mutation admission API.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordSet {
    records: BTreeMap<String, Record>,
    encoded_bytes: usize,
}

impl RecordSet {
    /// Create an empty projection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a record using canonical DAG-CBOR encoding.
    ///
    /// `$type` must match the path's collection. Basic data-model validation
    /// rejects floats, integers outside JavaScript's safe range, excessive
    /// nesting, and malformed `$link`/`$bytes` wrappers. Links require CIDv1,
    /// raw or DAG-CBOR codec, SHA-256, and canonical lowercase base32 strings.
    /// Bytes use standard RFC4648 base64, with optional padding. These rules
    /// follow the [data model](https://atproto.com/specs/data-model).
    /// This method does not replace
    /// collection-specific Lexicon validation. A failed put never mutates state.
    pub fn put(&mut self, path: &str, value: &Value) -> Result<Cid, Error> {
        syntax::path(path)?;
        let collection = path.split_once('/').expect("validated path").0;
        if value.get("$type").and_then(Value::as_str) != Some(collection) {
            return Err(Error::InvalidRecord(
                "$type must match the collection".into(),
            ));
        }
        if !self.records.contains_key(path) && self.len() >= MAX_RECORDS {
            return Err(Error::Limit("record count"));
        }
        let mut budget = MAX_RECORD_BYTES;
        let ipld = json_to_ipld(value, 0, &mut budget)?;
        let bytes = encode(&ipld)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(Error::Limit("encoded record bytes"));
        }
        let replaced_bytes = self
            .records
            .get(path)
            .map_or(0, |record| record.bytes.len());
        let encoded_bytes = self.encoded_bytes - replaced_bytes + bytes.len();
        if encoded_bytes > MAX_TOTAL_RECORD_BYTES {
            return Err(Error::Limit("aggregate record bytes"));
        }
        let cid = cid_for(&bytes);
        self.records.insert(path.into(), Record { cid, bytes });
        self.encoded_bytes = encoded_bytes;
        Ok(cid)
    }

    /// Remove a record. Returns false if it was already absent.
    pub fn delete(&mut self, path: &str) -> Result<bool, Error> {
        syntax::path(path)?;
        if let Some(record) = self.records.remove(path) {
            self.encoded_bytes -= record.bytes.len();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Look up one materialized record by path.
    pub fn get(&self, path: &str) -> Option<&Record> {
        self.records.get(path)
    }

    /// Iterate over all paths and records in lexical order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Record)> {
        self.records
            .iter()
            .map(|(path, record)| (path.as_str(), record))
    }

    /// Number of materialized records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the projection has no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Combined encoded bytes, counting every stored path even for identical CIDs.
    pub fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }
}

/// Local secp256k1 signer for the offline harness.
///
/// Uses RustCrypto's RFC6979 deterministic ECDSA and normalizes low-S output.
/// Identical metadata, state, and key produce identical signed commit CIDs.
/// This type deliberately has no `Debug` or secret export implementation.
/// A production protected signer and durable publication policy are separate work.
pub struct RepoSigner(SigningKey);

impl RepoSigner {
    /// Import a private scalar. All-zero and out-of-range scalars fail.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        SigningKey::from_bytes((&bytes).into())
            .map(Self)
            .map_err(|_| Error::Signature)
    }

    /// Return the compressed SEC1 public key, with no secret key material.
    pub fn public_key_sec1(&self) -> Vec<u8> {
        self.0
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    fn sign(&self, bytes: &[u8]) -> Vec<u8> {
        // Signer hashes once using SHA-256. Passing a digest here would hash twice.
        let signature: Signature = self.0.sign(bytes);
        signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .to_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct UnsignedCommit {
    did: String,
    version: u64,
    data: Cid,
    rev: String,
    prev: Option<Cid>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SignedCommit {
    did: String,
    version: u64,
    data: Cid,
    rev: String,
    prev: Option<Cid>,
    #[serde(with = "serde_bytes")]
    sig: Vec<u8>,
}

impl SignedCommit {
    fn unsigned(&self) -> UnsignedCommit {
        UnsignedCommit {
            did: self.did.clone(),
            version: self.version,
            data: self.data,
            rev: self.rev.clone(),
            prev: self.prev,
        }
    }
}

/// An immutable signed repository snapshot and all blocks for a full CAR export.
#[derive(Clone, Debug)]
pub struct Repository {
    commit: SignedCommit,
    root: Cid,
    records: RecordSet,
    blocks: BTreeMap<Cid, Vec<u8>>,
}

impl Repository {
    /// Build one v3 commit, with `prev: null`, from fully specified inputs.
    ///
    /// Syntax is checked but DID ownership, revision freshness and monotonicity,
    /// mutation finality, and authority to publish are the caller's responsibility.
    /// Accepts `did:plc`, hostname-only `did:web`, and explicit localhost
    /// development DIDs (including a canonical `%3A` port suffix).
    pub fn build(
        did: &str,
        rev: &str,
        records: &RecordSet,
        signer: &RepoSigner,
    ) -> Result<Self, Error> {
        syntax::metadata(did, rev)?;
        let mut blocks = BTreeMap::new();
        let mapping: BTreeMap<String, Cid> =
            records.iter().map(|(p, r)| (p.into(), r.cid)).collect();
        let data = mst::build(&mapping, &mut blocks)?;
        for (_, record) in records.iter() {
            blocks.insert(record.cid, record.bytes.clone());
        }
        let unsigned = UnsignedCommit {
            did: did.into(),
            version: 3,
            data,
            rev: rev.into(),
            prev: None,
        };
        let signature = signer.sign(&encode(&unsigned)?);
        let commit = SignedCommit {
            did: unsigned.did,
            version: 3,
            data,
            rev: unsigned.rev,
            prev: None,
            sig: signature,
        };
        let bytes = encode(&commit)?;
        let root = cid_for(&bytes);
        blocks.insert(root, bytes);
        Ok(Self {
            commit,
            root,
            records: records.clone(),
            blocks,
        })
    }

    /// Signed commit CID, also the CAR's single root.
    pub fn root(&self) -> Cid {
        self.root
    }

    /// Deterministic MST root CID.
    pub fn mst_root(&self) -> Cid {
        self.commit.data
    }

    /// Explicit revision of this snapshot.
    pub fn revision(&self) -> &str {
        &self.commit.rev
    }

    /// Account DID associated with this snapshot.
    pub fn did(&self) -> &str {
        &self.commit.did
    }

    /// The records contained in this snapshot.
    pub fn records(&self) -> &RecordSet {
        &self.records
    }

    /// Retrieve a block by its CID.
    pub fn block(&self, cid: &Cid) -> Option<&[u8]> {
        self.blocks.get(cid).map(Vec::as_slice)
    }

    /// Number of distinct commit, tree, and record blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Export a full CARv1, with commit first and then deterministic CID order.
    ///
    /// Arbitrary block order is valid in CARv1. The newer optional streaming
    /// order is not implemented. Referenced blobs are outside this repository.
    pub fn to_car(&self) -> Result<Vec<u8>, Error> {
        car::export(self.root, &self.blocks)
    }

    /// Check every block hash, the low-S signature, and canonical MST mapping.
    ///
    /// This is an internal consistency check, not independent interoperability
    /// evidence or DID resolution. Supply the trusted account public key.
    pub fn verify(&self, public_key_sec1: &[u8]) -> Result<(), Error> {
        for (cid, bytes) in &self.blocks {
            if cid_for(bytes) != *cid {
                return Err(Error::Verification("block hash mismatch".into()));
            }
        }
        let commit_bytes = self
            .block(&self.root)
            .ok_or_else(|| Error::Verification("missing commit".into()))?;
        let commit: SignedCommit = decode(commit_bytes)?;
        syntax::metadata(&commit.did, &commit.rev)?;
        if commit.version != 3 || commit.prev.is_some() || encode(&commit)? != commit_bytes {
            return Err(Error::Verification(
                "invalid commit schema or encoding".into(),
            ));
        }
        let key = VerifyingKey::from_sec1_bytes(public_key_sec1).map_err(|_| Error::Signature)?;
        let sig = Signature::from_slice(&commit.sig).map_err(|_| Error::Signature)?;
        if sig.normalize_s().is_some() {
            return Err(Error::Signature);
        }
        key.verify(&encode(&commit.unsigned())?, &sig)
            .map_err(|_| Error::Signature)?;
        let mapping: BTreeMap<String, Cid> = self
            .records
            .iter()
            .map(|(p, r)| (p.into(), r.cid))
            .collect();
        let mut expected_blocks = BTreeMap::new();
        if mst::build(&mapping, &mut expected_blocks)? != commit.data {
            return Err(Error::Verification("MST root mismatch".into()));
        }
        for (cid, bytes) in expected_blocks {
            if self.block(&cid) != Some(bytes.as_slice()) {
                return Err(Error::Verification("missing or incorrect MST block".into()));
            }
        }
        for (_, record) in self.records.iter() {
            if self.block(&record.cid) != Some(record.bytes.as_slice()) {
                return Err(Error::Verification("missing record block".into()));
            }
        }
        Ok(())
    }
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    serde_ipld_dagcbor::to_vec(value).map_err(|e| Error::Cbor(e.to_string()))
}

fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, Error> {
    serde_ipld_dagcbor::from_slice(bytes).map_err(|e| Error::Cbor(e.to_string()))
}

fn cid_for(bytes: &[u8]) -> Cid {
    let hash = cid::multihash::Multihash::<64>::wrap(0x12, &Sha256::digest(bytes))
        .expect("SHA-256 is 32 bytes");
    Cid::new_v1(0x71, hash)
}

fn json_to_ipld(value: &Value, depth: usize, budget: &mut usize) -> Result<Ipld, Error> {
    if depth > MAX_RECORD_DEPTH {
        return Err(Error::Limit("record nesting"));
    }
    let charge = match value {
        Value::String(s) => s.len() + 1,
        _ => 1,
    };
    *budget = budget
        .checked_sub(charge)
        .ok_or(Error::Limit("record bytes"))?;
    Ok(match value {
        Value::Null => Ipld::Null,
        Value::Bool(v) => Ipld::Bool(*v),
        Value::String(v) => Ipld::String(v.clone()),
        Value::Number(v) => {
            let integer = v
                .as_i64()
                .filter(|n| (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(n))
                .ok_or_else(|| {
                    Error::InvalidRecord("only safe signed JSON integers are supported".into())
                })?;
            Ipld::Integer(integer.into())
        }
        Value::Array(values) => Ipld::List(
            values
                .iter()
                .map(|v| json_to_ipld(v, depth + 1, budget))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(values) => {
            if let Some(link) = values.get("$link") {
                if values.len() != 1 {
                    return Err(Error::InvalidRecord(
                        "$link wrapper has extra fields".into(),
                    ));
                }
                let encoded = link
                    .as_str()
                    .ok_or_else(|| Error::InvalidRecord("$link must be a CID string".into()))?;
                if encoded.len() > 128 {
                    return Err(Error::InvalidRecord("$link CID is too long".into()));
                }
                *budget = budget
                    .checked_sub(encoded.len())
                    .ok_or(Error::Limit("record bytes"))?;
                let cid: Cid = encoded
                    .parse()
                    .map_err(|_| Error::InvalidRecord("invalid $link CID".into()))?;
                if cid.version() != cid::Version::V1
                    || !matches!(cid.codec(), 0x55 | 0x71)
                    || cid.hash().code() != 0x12
                    || cid.hash().size() != 32
                    || cid.to_string() != encoded
                {
                    return Err(Error::InvalidRecord(
                        "$link must be canonical base32 CIDv1 with raw or DAG-CBOR codec and SHA-256".into(),
                    ));
                }
                return Ok(Ipld::Link(cid));
            }
            if let Some(bytes) = values.get("$bytes") {
                if values.len() != 1 {
                    return Err(Error::InvalidRecord(
                        "$bytes wrapper has extra fields".into(),
                    ));
                }
                let encoded = bytes
                    .as_str()
                    .ok_or_else(|| Error::InvalidRecord("$bytes must be base64".into()))?;
                *budget = budget
                    .checked_sub(encoded.len())
                    .ok_or(Error::Limit("record bytes"))?;
                return Ok(Ipld::Bytes(
                    ATPROTO_BASE64
                        .decode(encoded)
                        .map_err(|_| Error::InvalidRecord("invalid base64".into()))?,
                ));
            }
            let mut map = BTreeMap::new();
            for (k, v) in values {
                *budget = budget
                    .checked_sub(k.len())
                    .ok_or(Error::Limit("record bytes"))?;
                map.insert(k.clone(), json_to_ipld(v, depth + 1, budget)?);
            }
            Ipld::Map(map)
        }
    })
}

#[cfg(test)]
mod tests;
