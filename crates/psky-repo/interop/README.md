# Independent repository verification

This checks offline Rust exports using the official ATProto TypeScript
implementation. It does not contact Hypersnap, resolve a DID, or prove a PDS.

From the repository root:

```sh
cargo run -p psky-repo --example export_fixture -- /tmp/psky-fixture.car
npm ci --ignore-scripts --prefix crates/psky-repo/interop
node crates/psky-repo/interop/verify.mjs /tmp/psky-fixture.car \
  did:plc:abcdefghijklmnopqrstuvwx \
  031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f \
  41
```

The example uses public fixture private bytes `[1; 32]`. The key is not suitable
for a real account. The verification command takes only a public key, supplied
by the caller as the trust anchor. It never treats a key inside a CAR as trusted.

The verifier checks block hashes and the v3 commit signature, reads every record,
rebuilds the MST using the independent implementation, and runs negative controls
for tampering, truncation, the wrong DID, the wrong key, and missing record blocks. Dependency
versions and integrity hashes are pinned in `package-lock.json`. Node is required
only for this development check; the Rust service does not use it.

## Primitive selection and vectors

The prototype uses `serde_ipld_dagcbor` and `cid` for encoding and identifiers,
and RustCrypto `k256` for deterministic low-S signing. It rebuilds the MST from
a sorted map rather than importing an entire PDS implementation. This is small
and deterministic but scales worse than an incremental MST.

The Rust tests include known MST roots from
[`bluesky-social/atproto` at `2e1787c2`](https://github.com/bluesky-social/atproto/blob/2e1787c2bf5bd47b55c3df930d688bb40b5ae63d/packages/repo/tests/mst.test.ts),
which is distributed under MIT or Apache-2.0. The vectors cover empty trees,
single entries, root trimming, insertion across two layers, and required empty
intermediate nodes. The implementation follows the
[repository specification](https://atproto.com/specs/repository) and
[cryptography specification](https://atproto.com/specs/cryptography).
