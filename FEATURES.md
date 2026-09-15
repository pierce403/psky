# PurpleSky Features

PurpleSky is a Rust implementation of one logical ATProto PDS backed by
Hypersnap, with replaceable workers and a localhost management console.

This file follows [FEATURES.md](https://features.md/). Each feature declares
`planned`, `in-progress`, or `stable`, testable properties, and acceptance checks.
The first Rust tools are in progress. The existing proposal website does
not demonstrate PDS functionality. Checked criteria must link to reproducible
evidence; a passing mock does not establish public-network interoperability.

## Agreed scope

- Use existing Hypersnap nodes without changing their software or protocol.
- Use Farcaster as the account authentication authority. Issue revocable ATProto
  app passwords when needed by the stock Bluesky client.
- All initial PurpleSky workers and the protected signer are operated by one
  operator. Independent operators and threshold signing are later research.
- Keep cast content and large-file bytes on the Farcaster/Hypersnap network.
  Small supporting metadata may need separate shared persistence, with its
  contents and recovery requirements documented before adoption.
- Local databases, indexes, MSTs, and CAR caches may be disposable materialized
  state. Losing a worker must not lose an acknowledged mutation.
- Prove reconstruction across two workers before building full client support.
- Preserve normal ATProto DIDs, repository signatures, records, and APIs.
- Implement the server in Rust. Serve the management UI on loopback separately
  from the public PDS API. UI technology remains an implementation choice.

## Storage boundary and unresolved gate

Hypersnap's existing message schema is not a general-purpose block store. Its
documented retention can prune messages. Farcaster media references do not by
themselves prove storage or recovery of the referenced bytes.

F-001 must establish a concrete supported representation and recovery policy.
Do not silently replace network storage with a PurpleSky content database,
external object store, or a modified Hypersnap node. If existing nodes cannot
meet a requirement, record the failed requirement and bring back the smallest
necessary design decision. A metadata-only shortcut cannot contain the entire
post body or media bytes under another name.

Text is sufficient for the first reconstruction proof. Large-file storage is
a separate required gate before media support or a claim of full PDS operation.
No bulk payload encoding into public casts until its protocol validity, feed
visibility, capacity, and operator-approved test scope are established.

## Delivery order

| Phase | Features | Exit condition |
| --- | --- | --- |
| 0. Feasibility | F-001, F-002 | Supported storage contract and bounded test network/account selected |
| 1. Reconstruction PoC | F-003 through F-008 | A writes, empty B reconstructs, independent verifier accepts, B writes, A catches up |
| 2. Failure proof | F-009 | Concurrent requests, retries, crashes, and stale workers preserve one published history |
| 3. Stock client | F-010 through F-012 | Farcaster-authorized test account uses stock Bluesky and interacts with an ordinary account |
| 4. Data lifecycle | F-013 through F-015 | Media, recovery, and migration work without violating the storage boundary |
| 5. Operations | F-016 | Repeatable installation, upgrades, monitoring, and recovery drills |
| Later research | F-017 | Separate designs and evidence before expanding trust or protocol semantics |

## Features

### F-001: Unmodified Hypersnap storage contract
- **Stability**: in-progress
- **Evidence**: [Source assessment and live read-only checks](docs/storage-feasibility.md). Native cast storage exists; arbitrary record mapping, recovery after pruning, and media-byte storage remain unresolved. No write proof.
- **Description**: Establish whether existing Hypersnap nodes can support the proposed PDS persistence model.
- **Properties**:
  - Pin node versions, network identity, endpoints, accepted message types, and API behavior.
  - Specify the representation of post content, arbitrary ATProto records, deletes, updates, and reconstruction metadata.
  - Inventory size limits, per-FID allocation, costs, pruning, historical access, ordering, finality, and node trust assumptions.
  - Distinguish submission acceptance, canonical inclusion, and recoverable publication.
  - Choose event projection only if supported by the measured substrate. No generic append-only log capability is assumed.
- **Test Criteria**:
  - [ ] A bounded test payload is accepted through an existing supported message path and retrieved through another node.
  - [ ] Exact content bytes and identifiers round-trip without relying on the submitting worker's disk.
  - [x] Document how current state is reconstructed after pruning or compaction, or record the blocking gap. [Gap analysis](docs/storage-feasibility.md)
  - [ ] Determine whether ordering is per account, shard, or network and define a usable publication order.
  - [ ] Publish the supported data mapping and unsupported cases with node versions and read/write evidence.

### F-002: Network and test-account configuration
- **Stability**: in-progress
- **Evidence**: [Read-only preflight](docs/evidence/2026-09-15-hypersnap-preflight.md). deanpierce.eth resolves to FID 8531; this is the user's account, not a provisioned disposable test identity. No signing authority is established.
- **Description**: Make the first experiment reproducible and bounded.
- **Properties**:
  - Configure a named network and explicit endpoint set; never mix incompatible histories.
  - Use a dedicated test FID and a fresh ATProto identity before attempting migration of a real account.
  - Record authorized write limits and any storage or identity costs before paid operations.
  - Keep credentials out of config exports, logs, fixtures, and Git.
- **Test Criteria**:
  - [ ] Read-only preflight reports reachability, network/version compatibility, account authority, and storage allocation.
  - [ ] Incompatible endpoints fail configuration rather than silently failing over across networks.
  - [ ] A documented command runs the bounded experiment with explicit test configuration.

### F-003: Rust service foundation
- **Stability**: in-progress
- **Evidence**: [Build and test procedure](docs/getting-started.md), [implementation validation](docs/evidence/2026-09-15-rust-foundation.md). Three crates; production auth and protected signing remain absent.
- **Description**: Provide a runnable worker with clear protocol boundaries.
- **Properties**:
  - Separate modules for Hypersnap access, projection, ATProto repositories, identity/auth, signing, public APIs, and admin APIs.
  - Local caches have schema versions and can be rebuilt from the declared recovery sources.
  - Public and admin listeners have separate bind addresses and access policies.
  - Dependency selection includes review of existing Rust ATProto primitives against official test vectors.
- **Test Criteria**:
  - [ ] Two workers start with isolated local data directories and the same logical service configuration.
  - [ ] Invalid configuration produces actionable errors without exposing secrets.
  - [ ] Formatting, linting, focused tests, and a documented build succeed in CI.
  - [ ] Graceful shutdown preserves recovery progress and does not acknowledge unfinished writes.

### F-004: Farcaster authority and DID binding
- **Stability**: in-progress
- **Evidence**: [Authentication implementation and validation](docs/authentication.md). SIWF signatures and finalized authority are verified; one hostname-level did:web account is supported. Live user consent and public resolution remain unproven.
- **Description**: Bind a proven Farcaster account to a standard ATProto identity.
- **Properties**:
  - Start with a hostname-level did:web and a stable public PDS service endpoint. Add did:plc provisioning and rotation separately.
  - Verify current FID authority; an associated wallet address or messaging signer alone does not grant account-management authority.
  - Define allowed custody/delegation proofs, challenge expiry, domain binding, replay prevention, and binding uniqueness.
  - Separate FID authentication, operational repository signing, and DID rotation authority.
  - Define transfer, key revocation, recovery, and reauthorization behavior before enabling them.
- **Test Criteria**:
  - [ ] The test user proves FID authority and obtains a verifiable FID-to-DID binding.
  - [ ] Wrong-account, expired, replayed, and wrong-domain proofs are rejected across workers.
  - [ ] DID resolution returns the intended service and repository verification key.
  - [ ] Unavailable or stale authority data cannot grant new privileges.

### F-005: Canonical mutation and projection model
- **Stability**: in-progress
- **Evidence**: [Repository tests and independent verifier](crates/psky-repo/interop/README.md). Canonical repository encoding and fixture reconstruction work; no live mutation mapping or ordering policy exists yet.
- **Description**: Map accepted shared state into one repository history per DID.
- **Properties**:
  - Depends on F-001's proven representation, not a fictional Hypersnap mutation API.
  - Define versioned envelopes or mappings, stable record keys, original record bytes, revisions, and commit boundaries.
  - Resolve expected-head preconditions and conflicting operations in canonical order.
  - Retries have durable identities across workers; replay never invents new timestamps or record keys.
  - Preserve ATProto-only fields through the approved storage mapping or explicitly reject unsupported records.
- **Test Criteria**:
  - [ ] Identical input history produces identical record CIDs, MST roots, and revisions on A and B.
  - [ ] Create, update, and delete have documented deterministic results.
  - [ ] Unknown mapping versions stop publication with an actionable error.
  - [ ] Repeated requests through another worker apply once and return the original result.

### F-006: Protected signing and publication
- **Stability**: planned
- **Description**: Produce standard signed ATProto commits from canonical state.
- **Properties**:
  - One operator-controlled protected signer initially holds operational repo keys separately from public workers.
  - Sign only authorized canonical transitions after the selected finality condition.
  - Retain signed artifacts and publication metadata through an explicit shared recovery mechanism.
  - Workers at one publication watermark serve the same signed commit CID, not just the same MST root.
  - A crash between signing and publication cannot create competing acknowledged results.
- **Test Criteria**:
  - [ ] An independent ATProto implementation verifies each published commit against the DID key.
  - [ ] Unauthorized or conflicting signing requests are rejected.
  - [ ] Signer restart returns the original published artifact for a retried transition.
  - [ ] Worker disk loss does not require the original worker or expose a repo private key.

### F-007: Two-worker reconstruction proof
- **Stability**: in-progress
- **Evidence**: [Offline foundation results](docs/evidence/2026-09-15-rust-foundation.md). All live-network acceptance checks remain unchecked; fixture replay is not the PoC.
- **Description**: Demonstrate the core claim before implementing a complete PDS.
- **Properties**:
  - One test FID/DID, two isolated Rust workers, existing Hypersnap endpoints, and one protected signer.
  - Acknowledged post content is recovered from network storage; any shared metadata dependency is listed explicitly.
  - Serve a standard com.atproto.sync.getRepo CAR export.
- **Test Criteria**:
  - [ ] Submit a text post through A and observe its canonical inclusion and publication.
  - [ ] Start B with empty projection state while A is unavailable.
  - [ ] B recovers records and serves a CAR accepted by an unmodified independent ATProto verifier.
  - [ ] A and B agree on record CIDs, MST root, revision, and signed commit CID at the same watermark.
  - [ ] Submit a second mutation through B; restart A and verify it serves the resulting canonical head.
  - [ ] Save exact commands, versions, network references, redacted logs, CARs, hashes, and verifier output as linked evidence.

### F-008: Localhost management console
- **Stability**: in-progress
- **Evidence**: [Management runbook](docs/management.md), [agent API](llms.txt), [validation](docs/evidence/2026-09-15-management.md), [router tests](crates/psky/src/server.rs), [settings tests](crates/psky/src/settings.rs). Saved configuration, peer health, tracked actions and bounded diagnostics run; no production cache rebuild or signer management is implemented.
- **Description**: Inspect and operate a node from a local browser during the PoC.
- **Properties**:
  - Bind admin routes to loopback by default and keep them off the public API listener.
  - Require local admin authentication and protect state changes against CSRF and DNS rebinding.
  - Show configured peers, sync lag, publication watermark, account binding, signer availability, and recent errors.
  - Provide explicit controls for preflight and cache reconstruction, with progress and cancellation semantics.
  - Never show private keys or authentication tokens in diagnostics or exports.
  - Configure implemented node settings through a revisioned API and browser form, with no manual file edits.
  - Mark pending listener changes and historical observations explicitly.
  - Publish an agent guide for authentication, configuration, logs, actions, and safe debugging.
- **Test Criteria**:
  - [ ] The console reports the actual A/B reconstruction progress and matching published head.
  - [x] Unauthenticated, foreign-origin, and invalid-Host management requests fail. [Router tests](crates/psky/src/server.rs)
  - [x] Admin routes are unreachable through the public listener. [Router tests](crates/psky/src/server.rs)
  - [x] Settings survive restart; invalid or stale edits cannot silently replace them. [Settings tests](crates/psky/src/settings.rs)
  - [x] Peer checks distinguish freshness, duplicate peers, and compatibility from reconstruction readiness. [Preflight tests](crates/psky-hypersnap/tests/preflight.rs)
  - [x] Accepted actions survive client disconnect; overlap is rejected and shutdown drains work. [Router tests](crates/psky/src/server.rs)
  - [x] Node event logs are bounded and available through authenticated cursor reads. [Journal](crates/psky/src/journal.rs)
  - [ ] Cache rebuild requires an explicit action and does not delete network data or signing material.

### F-009: Concurrency and failure correctness
- **Stability**: planned
- **Description**: Preserve one history under retries, outages, and concurrent requests.
- **Properties**:
  - Define read consistency, write acknowledgment, request timeouts, and reconciliation after uncertain outcomes.
  - Stale workers catch up, forward, wait, or fail rather than claiming an outdated head is current.
  - Per-DID preconditions, deduplication, and publication state survive worker changes.
- **Test Criteria**:
  - [ ] Simultaneous writes through A/B produce one documented canonical outcome.
  - [ ] A timeout after inclusion followed by a retry does not duplicate a record.
  - [ ] Crashes before inclusion, after inclusion, after signing, and after publication recover correctly.
  - [ ] Partitioned workers do not publish competing heads or falsely acknowledge durable writes.
  - [ ] Unavailable history or corrupt recovery data produces a visible failure rather than fabricated state.

### F-010: Stock Bluesky authentication
- **Stability**: in-progress
- **Evidence**: [Authentication implementation and validation](docs/authentication.md). The official password-session SDK passes against a local fixture account. This is not a live Farcaster login or a working stock-app timeline.
- **Description**: Let an unmodified Bluesky client access a Farcaster-authorized account.
- **Properties**:
  - Farcaster login authorizes issuance and revocation of scoped ATProto app passwords.
  - Store credential verifiers and session metadata privately, with expiry and shared revocation policy.
  - Implement the required standard session endpoints and service authentication.
  - Add standard ATProto OAuth separately; do not assume a particular Bluesky release supports it.
- **Test Criteria**:
  - [ ] A named stock Bluesky version logs in to the custom PDS with an issued app password.
  - [ ] Session refresh and logout work; revoked credentials fail on both workers.
  - [ ] FID transfer or authority revocation follows the documented session invalidation policy.
  - [ ] Authentication rate limits and secret redaction are verified.

### F-011: ATProto API and sync compatibility
- **Stability**: planned
- **Description**: Expose the standard PDS surface needed for native participation.
- **Properties**:
  - Maintain an endpoint compatibility matrix covering account discovery, repository reads/writes, sync, blobs, and service auth.
  - Preserve Lexicon validation, AT URIs, CIDs, batch atomicity, and expected-state preconditions.
  - Provide a resumable logical subscribeRepos stream with consistent cursors across worker changes.
  - Handle identity/account events and recovery when a cursor is outside retained history.
- **Test Criteria**:
  - [ ] Profile, post, follow, reply, update, and delete work through an independent client.
  - [ ] A standard relay consumes and verifies the stream and exported repository.
  - [ ] Stream resumption through another worker has no unexplained gaps or competing events.
  - [ ] Invalid records and unsupported endpoints return explicit protocol errors.

### F-012: Public Bluesky participation
- **Stability**: planned
- **Description**: Verify the user-visible experience through the existing Bluesky ecosystem.
- **Properties**:
  - Use a stable public HTTPS PDS endpoint, working DID/handle resolution, and configured AppView proxying.
  - Treat public relay discovery and AppView ingestion as external dependencies to verify.
  - Keep the localhost console private and preserve the proposal website at psky.org.
- **Test Criteria**:
  - [ ] A fresh test account logs in and displays its profile in the selected stock client.
  - [ ] Its post appears in the public AppView and is visible to an ordinary account.
  - [ ] Follow, mention, and reply work between PurpleSky and a conventional PDS account.
  - [ ] Switching workers preserves the DID, service endpoint, and account experience.

### F-013: Media and large-file network storage
- **Stability**: planned
- **Description**: Support ATProto blobs without moving canonical media bytes into a PurpleSky store.
- **Properties**:
  - First establish an existing, unmodified network mechanism that stores actual bytes, with explicit retention and access guarantees.
  - A cast containing an external media URL is insufficient evidence of Farcaster-hosted storage.
  - Specify upload limits, MIME handling, CID verification, retrieval, quotas, and deletion behavior.
  - Local blob caches are replaceable; small metadata may map references but may not hide canonical media storage.
- **Test Criteria**:
  - [ ] An uploaded image is recovered through another node after the uploading worker's cache is removed.
  - [ ] Returned bytes match the advertised CID and render in the stock client.
  - [ ] Missing, expired, oversized, and corrupted content have explicit outcomes.
  - [ ] If no suitable existing mechanism exists, document the blocker and obtain a revised storage decision before implementing a fallback.

### F-014: Retention, deletion, and full recovery
- **Stability**: planned
- **Description**: Make long-term availability and data lifecycle behavior explicit.
- **Properties**:
  - Inventory every durable dependency: content, signed commits, mappings, private metadata, sessions, and keys.
  - Authenticate recovery checkpoints and demonstrate the declared content-retention policy.
  - Distinguish removal from current ATProto state from erasure of historical network copies.
  - Define what survives worker loss versus loss of all operator infrastructure.
- **Test Criteria**:
  - [ ] Rebuild after the selected network's pruning or compaction conditions using the declared recovery sources.
  - [ ] Restore signer and private metadata from protected backups in a recovery drill.
  - [ ] Deleted records remain absent after reconstruction.
  - [ ] Console reports approaching capacity/retention limits and unrecoverable dependencies.

### F-015: Account import, export, and migration
- **Stability**: planned
- **Description**: Move accounts onto and off PurpleSky while retaining standard identity.
- **Properties**:
  - Preserve DID and supported records; verify blobs and handle control.
  - Import only data the approved storage mapping can preserve without loss.
  - Coordinate DID service/key updates and activation so one PDS remains authoritative.
  - Keep user-controlled identity recovery separate from operational repo keys.
- **Test Criteria**:
  - [ ] A disposable account migrates from a conventional PDS to PurpleSky and back with the same DID.
  - [ ] Imported content reconstructs on a fresh worker from approved shared sources.
  - [ ] Unsupported records, missing blobs, and insufficient storage block migration before cutover.
  - [ ] Export and documented recovery remain usable when the old worker is offline.

### F-016: Operator release and observability
- **Stability**: in-progress
- **Evidence**: [Development runbook and rustdoc](docs/README.md), [CI](.github/workflows/rust.yml). Production deployment, upgrade, and recovery procedures remain planned.
- **Description**: Package a repeatable, diagnosable single-operator deployment.
- **Properties**:
  - Document installation, public routing/TLS, private admin access, signer provisioning, and endpoint configuration.
  - Expose health, readiness, sync lag, publication lag, storage headroom, and failure metrics without secrets.
  - Version projection rules and local schemas; reject incompatible mixed-version workers.
  - Keep fixtures and simulation results distinct from live-network evidence.
- **Test Criteria**:
  - [ ] A clean machine follows the runbook to join and reconstruct the test account.
  - [ ] An upgrade and rollback preserve published commit identity and recovery ability.
  - [ ] Alerts identify stalled publication, signer failure, and insufficient network retention/capacity.
  - [ ] A release records dependency versions and passes the full documented interoperability/recovery procedure.

### F-017: Later protocol and trust research
- **Stability**: planned
- **Description**: Evaluate extensions after the single-operator implementation is proven.
- **Properties**:
  - Candidate work includes fenced signer failover, threshold signing, independently operated workers, and additional protocol views.
  - Farcaster-native/ATProto-native shared social operations require a separate semantics design.
  - No new DID method, Hypersnap changes, or public-network extension is implied by this roadmap.
- **Test Criteria**:
  - [ ] Each proposed expansion has a separate design covering trust, failure behavior, compatibility, and migration.
  - [ ] Signing changes produce ordinary ATProto signatures accepted by independent consumers.
  - [ ] Any change to the agreed storage or network constraints receives an explicit new decision.

## Immediate next run

The initial implementation and its limits are recorded in
[the foundation evidence](docs/evidence/2026-09-15-rust-foundation.md). Rustdoc
generates API documentation from code comments; CI runs tests, linting,
documentation checks, and independent ATProto CAR verification. Use the
[developer runbook](docs/getting-started.md) to reproduce it.

1. Complete F-001/F-002 preflight and record the concrete storage mapping and gaps.
2. If text-content persistence is viable, implement F-003 through F-008 as one bounded vertical slice.
3. Run F-007 with independent verification and retain reproducible evidence.
4. Exercise F-009 before beginning stock-client integration.
5. If a storage constraint fails, finish the useful read-only findings and return the exact decision needed. Do not report a local-only substitute as the PoC.

## Evidence and maintenance

Keep stable feature IDs. Update checkboxes and stability only when evidence supports
them. `in-progress` means implementation is underway; `stable` means the feature's
properties and acceptance checks are met for its stated scope, not that the whole
PDS is production-ready. Record remaining limitations alongside results.

Store reproducible procedures and redacted results under `docs/evidence/` when
implementation begins. Include commit/version identifiers, test conditions,
artifact hashes, expected results, and observed results. Never commit credentials.

## References

- [Project architecture](README.md)
- [FEATURES.md format](https://features.md/)
- [Hypersnap message schema](https://github.com/farcasterorg/hypersnap/blob/main/proto/definitions/message.proto)
- [Hypersnap retention](https://github.com/farcasterorg/hypersnap-docs-web/blob/master/src/appendix/retention.md)
- [ATProto repositories](https://atproto.com/specs/repository)
- [ATProto synchronization](https://atproto.com/specs/sync)
- [ATProto OAuth](https://atproto.com/specs/oauth)
- [ATProto migration](https://atproto.com/guides/account-migration)
