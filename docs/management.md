# Node management

The console manages preflight, offline reconstruction and account login policy.
It is not an account dashboard for a working PDS. Production readiness remains
false even when peer checks and the local lab pass.

## Start and connect

```sh
cargo run -p psky -- serve --data-dir tmp/node-a
```

Open <http://127.0.0.1:8788>. In another local terminal, obtain the token:

```sh
cargo run --quiet -p psky -- admin-token --data-dir tmp/node-a
```

Paste it into Connect. It stays in tab memory, not browser storage. Disconnect
or reload to forget it. Never paste the token into an issue or AI conversation.
The command only reads an existing token; it cannot initialize an unknown node.

The console and [agent guide](../llms.txt) use the same management API. Fetch
`/llms.txt` from the management listener for its complete contract. This guide
requires no token but is still protected by local Host and Origin checks.

## Settings

All implemented runtime settings are available under Configuration: node name,
Hypersnap endpoints, expected network, public test FID, request timeout, response
size, block-delay threshold, fixture export, and both listener addresses.
No manual file editing is required.

Settings are saved as a private, revisioned document. Non-listener changes apply
immediately to subsequent actions. Changing either bind address requires a
normal process restart. The Runtime panel shows the sockets actually in use;
it does not display pending addresses as active. Saved settings take precedence
over bootstrap flags on subsequent starts.

Two tabs cannot silently overwrite each other's revisions. Reload saved settings
and reconcile edits after a conflict. Saving while an action runs returns Busy.
Successful saves invalidate old peer observations. The previous lab result is
retained with its configuration revision because it is an offline fixture.

`--data-dir` and starting/stopping the process remain local bootstrap controls.
There is no management shell, process-restart endpoint, token export endpoint,
or production signer configuration. Each process needs its own data directory.
Do not run two processes against the same settings file.

## Peer health

Add explicit endpoints and choose Check nodes. For the user's public account,
FID 8531 is a read-only observation target, not a dedicated write-test identity.

The console displays each node's reported version, peer ID, shard heights and
block delays, plus request errors. A successful HTTP response is reachability,
not compatibility. The supported version and a cast's reported network are
checked separately. Without a cast-network observation, compatibility is unknown.

Freshness requires all reported shards, including shard 0, with nonzero heights
and delays within the configured threshold. The default is 30 seconds. This is
a timestamp heuristic, not proof of complete history, signatures, finality, or
independent operation. Duplicate peer IDs cannot pass the distinct-peer check.
One healthy peer is enough to start live mapping and recovery tests. Two distinct
healthy peers are needed to prove independent-node replication and failover.

For a private remote node, an operator can run a local SSH forward, then add
the local endpoint in Configuration. For example, when the remote Hypersnap API
is bound to port 3381:

```sh
ssh -N -L 127.0.0.1:3381:127.0.0.1:3381 majin.x43.io
```

Add `http://127.0.0.1:3381`. PurpleSky does not create or manage SSH tunnels or
modify Hypersnap. An API that resets connections during snapshot import is not
yet a usable second live peer. Wait for API availability and check shard delay
after bootstrap. Do not expose the remote management port publicly.

## Actions and diagnostics

Preflight and reconstruction return an operation ID immediately and continue
if the browser disconnects. Status and activity refresh in the connected tab.
Only one action runs at a time. “Succeeded” means an operation produced its
report; read the report to learn whether its checks passed. No cancellation API
exists. Ctrl-C or SIGTERM drains accepted actions before shutdown.

The offline lab creates a new `lab-*` directory under the data directory.
The report includes that relative `artifact_dir`, hashes and evidence scope.
These local artifacts persist, are never automatically deleted, and are not
network-backed repositories. Download/cleanup APIs are not implemented; inspect
or remove only explicitly selected disposable outputs as the local operator.
Logs and operation history are bounded in memory: 200 events and 32 completed
actions. They reset on restart, as do cached reports. No raw remote response
bodies, tokens, request bodies, or signing material enter the event log.

Common problems:

- Cannot connect: check the actual startup address and local token. A saved
  listener change can move the console after restart.
- Forbidden: use the exact loopback host and port. Cross-origin browser access
  is intentionally rejected, even with the correct token.
- Stale settings: fetch the latest revision, compare changes, then save.
- Save failed: check data-directory permissions and free space. An uncertain
  durability error means the replacement published but directory sync failed;
  reread settings before retrying. Do not weaken private file permissions.
- Unhealthy peer: inspect check errors, version/network observations, duplicate
  IDs, and shard delays. Increasing thresholds does not repair synchronization.
- Public `/ready` returns 503: expected. `/health` only proves process liveness.

## Work still required

1. Obtain a recent healthy live node observation and an authorized test identity
   before any writes. Add a second synced node for replication/failover tests.
2. Specify and test native text-content mapping and exact recovery on unmodified
   Hypersnap, including ordering and pruning limits.
3. Implement protected repo signing and durable identity/publication metadata.
4. Prove A writes, empty B reconstructs, B writes, and A catches up. Verify all
   exports independently, then exercise retries, crashes and stale workers.
5. Complete live consent and public identity checks for the implemented
   [Farcaster login](authentication.md), then add stock-client social APIs.
6. Prove media-byte availability separately, then add installation, upgrades,
   backup/recovery drills, and production monitoring.

See [FEATURES.md](../FEATURES.md) for acceptance criteria. A nicer control panel
does not remove the storage gate.
