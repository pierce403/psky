# Current implementation

| Component | Implemented purpose | Not established |
| --- | --- | --- |
| `psky-hypersnap` | Bounded read-only node/account preflight | Authentication, canonical admission, durable recovery |
| `psky-repo` | Deterministic records, MST, signed v3 commit, CAR export | PDS lifecycle or network storage |
| `psky lab` | Independently reconstruct fixture state on A/B | Live two-worker PoC |
| `psky serve` | Loopback console, health, opt-in fixture export | Stock Bluesky login, production writes, firehose |

The implementation deliberately exposes the unresolved storage gate. It does
not create an alternative production content store. Before adding a live write
path, establish the mapping and durability contract in F-001 and define how a
fresh worker recovers from the approved network sources.

## Repository laboratory

Each fixture revision has fixed record paths, timestamps, and revision metadata.
Workers reconstruct fresh record sets and the same canonical repository bytes.
The test signer uses a documented public fixture key. Production signing needs
a separate protected service and recoverable signed-artifact publication.

The first harness compares exact CAR bytes in addition to signatures and CIDs.
It does not implement an accepted-mutation log or claim that fixture ordering
comes from Hypersnap. Concurrency, idempotency, recovery after pruning, and
fenced publication remain later work.

## Local console boundary

Public and admin routers are separate. Admin binding must be loopback. An
exact Host check rejects unexpected hostnames and ports; browser Origin and
Fetch Metadata checks reject foreign origins. Privileged routes require a
256-bit bearer token. Tokens are stored in a restricted local file and are
never returned by status or diagnostics. The HTML shell contains no secrets.

Only one operator action runs at a time. Preflight is read-only; reconstruction
creates a fresh output directory. No action deletes existing files. The console
uses ordinary HTML and JavaScript without a frontend dependency tree.

## Documentation

Rustdoc comments are the API documentation source. The `docs/` directory holds
runbooks, design boundaries, and reproducible evidence. Update documentation
and feature checks with the implementation they describe.
