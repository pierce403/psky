//! Deterministic fixture replay, with no live-network or account authority claim.
//!
//! Two worker directories receive independently reconstructed CAR files. The
//! shared source is a versioned **test fixture**, never a substitute for the
//! required Farcaster storage. The fixture key is public test material.

use std::{fs, path::Path};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use psky_repo::{RecordSet, RepoSigner, Repository};

/// Non-resolving test identity. It is never registered with PLC.
pub const FIXTURE_DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";

/// First fixed revision. Never generated using a replay-time clock.
pub const FIRST_REV: &str = "3lcyfmqxq2k22";

/// Second fixed revision in the fixture's canonical order.
pub const SECOND_REV: &str = "3lcyfmqxq2k23";

/// Machine-readable results of a local experiment, not a live-network proof.
#[derive(Debug, Clone, Serialize)]
pub struct LabReport {
    /// Explicit evidence boundary for callers and the console.
    pub mode: &'static str,
    /// Never true for this fixture experiment.
    pub network_proof: bool,
    /// Repository identity shared by both simulated workers.
    pub did: &'static str,
    /// SHA-256 of byte-identical first-revision CAR exports.
    pub first_car_sha256: String,
    /// SHA-256 after the second mutation and reconstruction on A.
    pub second_car_sha256: String,
    /// Number of self-verified exports compared. The external verifier is separate.
    pub exports_checked: usize,
    /// Dependency on public test material, not a production signer.
    pub signer: &'static str,
}

/// Build synthetic text records. The fixture source is immutable and public.
pub fn fixture_records(second: bool) -> Result<RecordSet> {
    let mut records = RecordSet::new();
    records.put(
        "app.bsky.feed.post/3lcyfmqxq2k22",
        &json!({
            "$type": "app.bsky.feed.post",
            "text": "PurpleSky offline reconstruction fixture.",
            "createdAt": "2026-09-15T00:00:00Z"
        }),
    )?;
    if second {
        records.put(
            "app.bsky.feed.post/3lcyfmqxq2k23",
            &json!({
                "$type": "app.bsky.feed.post",
                "text": "A second fixture mutation, reconstructed on another worker.",
                "createdAt": "2026-09-15T00:00:01Z"
            }),
        )?;
    }
    Ok(records)
}

/// Produce a verified CAR entirely from fixtures and a public test signing key.
pub fn fixture_car(second: bool) -> Result<Vec<u8>> {
    let signer = RepoSigner::from_bytes([7; 32])?;
    let records = fixture_records(second)?;
    let repo = Repository::build(
        FIXTURE_DID,
        if second { SECOND_REV } else { FIRST_REV },
        &records,
        &signer,
    )?;
    repo.verify(&signer.public_key_sec1())?;
    Ok(repo.to_car()?)
}

/// Run a bounded replay experiment in a newly created directory.
///
/// Existing paths are rejected, so a mistyped output cannot overwrite user
/// data. Four exports are generated from independent record sets and compared
/// byte-for-byte. SHA-256 digests are written to `report.json`.
pub fn run(output: &Path) -> Result<LabReport> {
    fs::create_dir(output)
        .context("lab output must be a new directory under an existing parent")?;
    for worker in ["worker-a", "worker-b"] {
        fs::create_dir(output.join(worker))?;
    }
    let a_first = fixture_car(false)?;
    fs::write(output.join("worker-a/rev-1.car"), &a_first)?;
    // B does not read A's output; it replays the source into a fresh record set.
    let b_first = fixture_car(false)?;
    ensure!(a_first == b_first, "first revision diverged");
    fs::write(output.join("worker-b/rev-1.car"), &b_first)?;
    let b_second = fixture_car(true)?;
    fs::write(output.join("worker-b/rev-2.car"), &b_second)?;
    let a_second = fixture_car(true)?;
    ensure!(a_second == b_second, "second revision diverged");
    ensure!(a_first != a_second, "second mutation did not change export");
    fs::write(output.join("worker-a/rev-2.car"), &a_second)?;
    let signer = RepoSigner::from_bytes([7; 32])?;
    fs::write(
        output.join("public-key.hex"),
        hex::encode(signer.public_key_sec1()),
    )?;
    let report = LabReport {
        mode: "offline-fixture",
        network_proof: false,
        did: FIXTURE_DID,
        first_car_sha256: hex::encode(Sha256::digest(&a_first)),
        second_car_sha256: hex::encode(Sha256::digest(&a_second)),
        exports_checked: 4,
        signer: "public fixture key; no protected signer or FID authorization",
    };
    fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_replay_is_byte_identical_and_revision_changes_export() {
        assert_eq!(fixture_car(false).unwrap(), fixture_car(false).unwrap());
        assert_ne!(fixture_car(false).unwrap(), fixture_car(true).unwrap());
    }

    #[test]
    fn two_empty_worker_directories_get_matching_exports() {
        let parent = tempfile::tempdir().unwrap();
        let output = parent.path().join("proof");
        let report = run(&output).unwrap();
        assert!(!report.network_proof);
        assert_eq!(report.exports_checked, 4);
        for revision in [1, 2] {
            assert_eq!(
                fs::read(output.join(format!("worker-a/rev-{revision}.car"))).unwrap(),
                fs::read(output.join(format!("worker-b/rev-{revision}.car"))).unwrap()
            );
        }
    }

    #[test]
    fn existing_directory_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("keep"), "original").unwrap();
        assert!(run(dir.path()).is_err());
        assert_eq!(
            fs::read_to_string(dir.path().join("keep")).unwrap(),
            "original"
        );
    }
}
