# Getting started

Requirements: the pinned Rust toolchain in `rust-toolchain.toml`. Node.js is
needed only for the independent ATProto verification check described below.

## Build and test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

## Read-only network preflight

```sh
cargo run -p psky -- preflight \
  --endpoint https://haatz.quilibrium.com \
  --network mainnet --fid 8531
```

The FID was resolved from deanpierce.eth during the initial assessment. This
command reads public node/account information and never submits a message.
Node URLs and versions are observations, not permanent availability promises.
See the [dated preflight evidence](evidence/2026-09-15-hypersnap-preflight.md).

Exit status 0 means the configured responses passed the implemented
compatibility checks. Status 2 means at least one check was incompatible,
unavailable, or unknown. Neither status establishes the storage contract.

## Offline reconstruction

```sh
mkdir -p tmp
cargo run -p psky -- lab --output tmp/reconstruction-1
```

The output directory must not already exist. The command reconstructs two
revisions independently on A and B, verifies signatures, compares CAR bytes,
and writes four CAR files, a public test key, and a JSON report.

This is a fixture experiment. Both workers replay synthetic records using a
public test key. No FID is authenticated, no DID is registered, and no content
is written to Hypersnap. It exercises repository correctness while the live
storage requirements remain unresolved.

Independently verify all four exports with the pinned official ATProto library:

```sh
npm ci --ignore-scripts --prefix crates/psky-repo/interop
node scripts/verify-lab.mjs tmp/reconstruction-1
```

The verifier checks signatures, CIDs, record decoding, and an independently
rebuilt MST. It also checks that corrupt, truncated, wrong-DID, and incomplete
exports fail. A larger 41-record fixture is described in the
[interoperability runbook](../crates/psky-repo/interop/README.md).

## Local console

```sh
cargo run -p psky -- serve \
  --data-dir tmp/node-a \
  --endpoint https://haatz.quilibrium.com --fid 8531 \
  --serve-fixture
```

Open <http://127.0.0.1:8788>. Obtain the token with
`cargo run --quiet -p psky -- admin-token --data-dir tmp/node-a`, then paste it
into Connect. It stays in tab memory. Never put it in a URL, chat, or repository.
Configure endpoints and all implemented node settings in the console. Saved
settings win over startup flags on later starts. Only listener changes need a
restart. Preflight and offline reconstruction run as tracked background actions.
See the [management runbook](management.md) and [agent API guide](../llms.txt).

The public development listener is <http://127.0.0.1:8787>. `/health` reports
process availability; `/ready` returns 503 because this is not a ready PDS.
With fixture export enabled in Configuration (or `--serve-fixture` on first
start), this endpoint exports the documented fixture:

```text
/xrpc/com.atproto.sync.getRepo?did=did:plc:aaaaaaaaaaaaaaaaaaaaaaaa
```

All production writes are unavailable. A second worker can run with different
ports and `--data-dir tmp/node-b`. Do not configure a real account's DID to
point at this development server.

Stop with Ctrl-C or SIGTERM. In-flight operator actions finish before shutdown.
Local settings and the admin token persist. Reports and logs reset on restart;
lab artifact directories persist. No network content is deleted by stopping or
rerunning the application.
