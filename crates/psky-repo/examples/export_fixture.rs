//! Export a reproducible repository with a public fixture key for JS interop.
//! Usage: cargo run -p psky-repo --example export_fixture -- /tmp/fixture.car

use psky_repo::{RecordSet, RepoSigner, Repository};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("pass the destination .car path")?;
    let mut records = RecordSet::new();
    // Multiple layers and shared prefixes exercise tree traversal in the reader.
    for n in 0..40 {
        records.put(
            &format!("app.bsky.feed.post/post{n}"),
            &json!({
                "$type": "app.bsky.feed.post",
                "text": format!("PurpleSky offline fixture {n}"),
                "createdAt": "2026-09-15T00:00:00Z"
            }),
        )?;
    }
    records.put(
        "app.bsky.actor.profile/self",
        &json!({
            "$type": "app.bsky.actor.profile", "displayName": "PurpleSky fixture"
        }),
    )?;
    let signer = RepoSigner::from_bytes([1; 32])?;
    let repo = Repository::build(
        "did:plc:abcdefghijklmnopqrstuvwx",
        "3jzfcijpj2z2a",
        &records,
        &signer,
    )?;
    repo.verify(&signer.public_key_sec1())?;
    std::fs::write(&path, repo.to_car()?)?;
    let public_key_hex: String = signer
        .public_key_sec1()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!(
        "{}",
        json!({
            "evidence": "offline_fixture_only", "car": path,
            "did": repo.did(), "revision": repo.revision(),
            "commit": repo.root().to_string(), "mst": repo.mst_root().to_string(),
            "records": repo.records().len(), "blocks": repo.block_count(),
            "public_key_sec1_hex": public_key_hex
        })
    );
    Ok(())
}
