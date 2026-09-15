# PurpleSky developer documentation

Start with [getting started](getting-started.md), then read the
[implementation boundaries](architecture.md) and
[storage feasibility report](storage-feasibility.md).
The [feature tracker](../FEATURES.md) describes the complete roadmap.
The [management runbook](management.md) covers the localhost control panel;
[llms.txt](../llms.txt) documents the same API for operator-authorized agents.
The [account guide](authentication.md) covers Farcaster sign-in, app passwords,
session tests, and the remaining public-client gates.

## Documentation from code

Rustdoc generates the API reference from Rust `//!` module comments and `///`
item comments. Public APIs document inputs, invariants, and limitations.
Runnable examples are tested with the normal test suite.

```sh
cargo doc --workspace --no-deps
cargo test --workspace --doc
```

Open `target/doc/psky/index.html` for the operator library,
`target/doc/psky_repo/index.html` for repository primitives, and
`target/doc/psky_hypersnap/index.html` for node preflight,
`target/doc/psky_farcaster_auth/index.html` for SIWF verification, and
`target/doc/psky_credentials/index.html` for private credentials and sessions.
Generated HTML is a build artifact, not hand-maintained source.

CI builds the reference with warnings treated as errors and uploads it as a
downloadable artifact. It does not replace the proposal site at psky.org.

## Evidence

Network observations, fixture output, independent verification, and CI results
have different scopes. Each file under [evidence](evidence/) names the scope it
supports. No local fixture result proves live FID authority, durable network
storage, a protected publishing signer, or the full stock Bluesky app experience.
