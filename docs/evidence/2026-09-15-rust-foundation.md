# Rust foundation validation, 2026-09-15

Scope: offline repository interoperability, bounded read-only Hypersnap access,
and a local development console. The live reconstruction PoC is not complete.

## Reproduce

Use the pinned Rust toolchain and committed dependency lockfiles:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
mkdir -p tmp
cargo run --locked -p psky -- lab --output tmp/new-proof
npm ci --ignore-scripts --prefix crates/psky-repo/interop
node scripts/verify-lab.mjs tmp/new-proof
```

The proof directory must be new. Output contains public synthetic records and
a public fixture key. No network write or real-account credential is involved.

## Repository results

Workers A and B are isolated record-set constructions and output directories
within one local process, not two independently deployed network nodes. B does
not read A's output. The official TypeScript verifier runs separately and
checks each exported CAR using a caller-supplied public key.

| Revision | Records | Commit CID on both workers |
| --- | ---: | --- |
| `3lcyfmqxq2k22` | 1 | `bafyreigvsvripzz7rcl52i3ej55g3sa3c63gdltls6kjsytt2uxxe6tofi` |
| `3lcyfmqxq2k23` | 2 | `bafyreibg7htal3n3dunwbbmypl3jnrp42a34jigh6buxfgoit5cz2urfeq` |

CAR SHA-256:

- First revision: `76e7707cc324ff904c9a0f121780469d83c575d7eb6a842bfe6767986df00a44`.
- Second revision: `80b81e9f0c55f825f3c3656f4c77fb64a34186424977358f0194d290fc4ae662`.

All four exports passed `@atproto/repo@0.10.14` verification with
`@atproto/crypto@0.5.5`. The independent implementation validated block CIDs,
commit signatures, record decoding, and the rebuilt MST. Negative controls
rejected altered bytes, missing records, truncation, a wrong DID, and a wrong
verification key. A separate 41-record fixture also passed; reproduction is
in the [interop runbook](../../crates/psky-repo/interop/README.md).

## Test coverage

- Official MST reference roots, including empty and multi-layer trees.
- Canonical DAG-CBOR encoding, deterministic signing, required commit fields,
  malformed keys, tampered blocks, and deletion from current exports.
- Property tests for insertion order, update/delete replay, and Unicode text.
- Record path, revision, DID, byte, depth, and content-link validation.
- Hypersnap request bounds, malformed responses, incompatible networks/versions,
  redirects, streaming limits, timeouts, and credential redaction.
- Console authentication, Host/Origin checks, listener separation, fixture-only
  exports, token file permissions, and output-overwrite protection.
- Black-box CLI startup, invalid configuration, secret-free errors, and SIGTERM.
- Rustdoc examples compiled and run by the test suite.

Formatting, strict Clippy, tests, and strict rustdoc generation passed locally.
The final local run passed 72 unit/integration tests and two rustdoc examples.
The [Rust workflow](../../.github/workflows/rust.yml) repeats these checks plus
independent verification and uploads the generated API reference. Consult the
workflow run for remote CI status; this document does not infer it from local
results.

## Live read-only adapter result

The Rust preflight command queried `https://haatz.quilibrium.com` with FID 8531.
It reported version `0.13.5`, matching reported mainnet message data, four
storage units, and 4,813 of 20,000 cast slots used. All four implemented GETs
returned HTTP 200. The report sets `ready_for_reconstruction: false` and marks
custody as unverified. See the [source and HTTP evidence](2026-09-15-hypersnap-preflight.md).

## Local console result

Started the actual CLI with a restricted token file and separate listeners.
Authenticated status, preflight, and offline reconstruction returned HTTP 200.
Foreign-origin access returned 403; the production readiness endpoint returned
503. The browser rendered the console and the empty-token control prevented
submission. Authenticated actions were exercised over HTTP, not by entering a
secret into browser automation.

## Remaining gate

No Farcaster login, signed network write, live two-node recovery, protected
signer, complete PDS, or stock Bluesky login has been demonstrated. The
[storage report](../storage-feasibility.md) identifies the missing contract and
operational requirements. Offline fixtures are not a substitute for that proof.
