# Hypersnap preflight evidence, 2026-09-15

Scope: bounded read-only public HTTP and GitHub source inspection. Initial
HTTP observations were collected before `2026-09-15T15:35:32Z`; the same-day
source review continued afterward. No credentials, account writes, uploads, paid
operations, key registrations, or full-history scans were used.

This is a human-readable observation record. JSON below is deliberately
reduced to relevant fields unless labelled complete. It is not a captured
cryptographic transcript or proof of network finality. Counts and head
heights will change. No cast bodies are copied into this evidence file.

## Revision pins

| Repository | Inspected revision |
| --- | --- |
| [farcasterorg/hypersnap](https://github.com/farcasterorg/hypersnap/tree/3dc7df14068e8e5b56fcb31e8e41bb956dacf183) | `3dc7df14068e8e5b56fcb31e8e41bb956dacf183` |
| [farcasterorg/hypersnap-docs-web](https://github.com/farcasterorg/hypersnap-docs-web/tree/85fb17b4212fdb9a28ea1f01d656b6eed1d7b4ae) | `85fb17b4212fdb9a28ea1f01d656b6eed1d7b4ae` |
| [pierce403/quorum-desktop](https://github.com/pierce403/quorum-desktop/tree/ef6ae1974b36bec9498e54850415a07e88723458) | `ef6ae1974b36bec9498e54850415a07e88723458` |
| [QuilibriumNetwork/quorum-shared](https://github.com/QuilibriumNetwork/quorum-shared/tree/c00c61e099fe9e682c982bc952b4e712c7a4a576) | `c00c61e099fe9e682c982bc952b4e712c7a4a576` |
| [QuilibriumNetwork/quorum-mobile](https://github.com/QuilibriumNetwork/quorum-mobile/tree/d4fc312a12482da9bb2ba8c7f40f925541bde083) | `d4fc312a12482da9bb2ba8c7f40f925541bde083` |

`gh api repos/OWNER/REPO/commits/HEAD --jq .sha` obtained each revision.
`gh api -H 'Accept: application/vnd.github.raw+json'
'repos/OWNER/REPO/contents/PATH?ref=SHA'` read selected source files.

The desktop fork imports `HypersnapClient` from `@quilibrium/quorum-shared`
and uses the haatz host explicitly in
[`useFarcasterDesktop.ts`](https://github.com/pierce403/quorum-desktop/blob/ef6ae1974b36bec9498e54850415a07e88723458/src/components/farcaster/useFarcasterDesktop.ts).
Its package is linked locally; the inspected upstream shared revision is not
proof of the exact version installed alongside that desktop checkout.
The shared
[`DEFAULT_HYPERSNAP_BASE_URL`](https://github.com/QuilibriumNetwork/quorum-shared/blob/c00c61e099fe9e682c982bc952b4e712c7a4a576/src/farcaster/hypersnapClient.ts#L19)
is `https://haatz.quilibrium.com`. Mobile
[`hypersnapProvision.ts`](https://github.com/QuilibriumNetwork/quorum-mobile/blob/d4fc312a12482da9bb2ba8c7f40f925541bde083/services/farcaster/hypersnapProvision.ts)
uses the default shared client. No second Hypersnap endpoint was found in
these selected paths. `pierce403/quorum-mobile` returned GitHub HTTP 404.

## Public node info

Command:

```sh
curl --fail-with-body --max-time 25 -sS https://haatz.quilibrium.com/v1/info
```

HTTP 200. Complete response, reformatted:

```json
{
  "dbStats": {"numMessages":913726140,"numFidRegistrations":3351145,"approxSize":790034168303},
  "numShards":2,
  "shardInfos":[
    {"shardId":0,"maxHeight":45522872,"numMessages":12642452,"numFidRegistrations":0,"approxSize":52219300137,"blockDelay":1,"mempoolSize":0},
    {"shardId":1,"maxHeight":46181570,"numMessages":458349940,"numFidRegistrations":1675774,"approxSize":397083165071,"blockDelay":3,"mempoolSize":4294967295},
    {"shardId":2,"maxHeight":46016556,"numMessages":455376200,"numFidRegistrations":1675371,"approxSize":392951003232,"blockDelay":0,"mempoolSize":4294967295}
  ],
  "version":"0.13.5",
  "peer_id":"12D3KooWMYfkXiNcn9LifPkLYiHtGmXYnknYG1yFBD53rUseUMUc",
  "nextEngineVersionTimestamp":0
}
```

`numShards` excludes shard zero in this response. The response has no network
identifier or source commit. A large `mempoolSize` is retained as reported;
its meaning was not inferred.

The [public Hypersnap site](https://hypersnap.org/) also advertises
`http://209.97.147.208:3381/v1/info`. This command failed:

```sh
curl --fail-with-body --max-time 25 -sS http://209.97.147.208:3381/v1/info
```

Observed `curl` exit 28: connection timed out after 25,002 milliseconds.
This does not establish whether the remote service was down or whether
the network path was unavailable.

## Account resolution and retained-message read

```sh
curl --fail-with-body --max-time 25 -sS 'https://haatz.quilibrium.com/v1/fidByName?name=deanpierce.eth'
curl --fail-with-body --max-time 25 -sS 'https://haatz.quilibrium.com/v1/castsByFid?fid=8531&pageSize=1&reverse=true'
```

Both returned HTTP 200. Complete name response: `{"fid":8531}`.
Selected message fields:

```json
{
  "fid":8531,
  "type":"MESSAGE_TYPE_CAST_ADD",
  "network":"FARCASTER_NETWORK_MAINNET",
  "timestamp":179978655,
  "hash":"0xea18479c782aa4cf00ad05c32844ae4e8d3e8dd5",
  "hashScheme":"HASH_SCHEME_BLAKE3",
  "signatureScheme":"SIGNATURE_SCHEME_ED25519",
  "signer":"0xfd507b1f9028a2afb19c439c63a79c4e9f5303dd7f5fbc773deba2d7c5cf254e"
}
```

The wire response nests `fid`, `type`, `network`, `timestamp`, and
`castAddBody` under `messages[0].data`. Other listed fields belong to
`messages[0]`. The response also included a base64 signature, cast text,
parent cast, and `nextPageToken`. Neither signature nor chain inclusion was
independently verified. A separate initial schema probe for public FID 3
also returned one mainnet cast using `pageSize=1`.

Source detail: `/v1/castsByFid` calls gRPC `GetAllCastMessagesByFid` and may
return removes as well as adds. It reads legacy state, not the Hyper shadow
namespace. Do not require `castAddBody` merely to inspect message network.

## Storage allocation

```sh
curl --fail-with-body --max-time 25 -sS 'https://haatz.quilibrium.com/v1/storageLimitsByFid?fid=8531'
```

HTTP 200. The `limits` entries reported:

| `name` | `limit` | `used` |
| --- | ---: | ---: |
| `CASTS` | 20,000 | 4,813 |
| `LINKS` | 10,000 | 486 |
| `REACTIONS` | 10,000 | 10,000 |
| `USER_DATA` | 200 | 10 |
| `VERIFICATIONS` | 100 | 4 |
| `USERNAME_PROOFS` | 20 | 1 |
| `STORAGE_LENDS` | 4 | 0 |

Each also had `storeType`, `earliestTimestamp: 0`, and `earliestHash: []`.
The last entry's `storeType` was `None` despite a valid `STORAGE_LENDS` name.
Top-level fields:

```json
{
  "units":4,
  "unitDetails":[
    {"unitType":"UnitTypeLegacy","unitSize":4},
    {"unitType":"UnitType2024","unitSize":0},
    {"unitType":"UnitType2025","unitSize":0}
  ],
  "tier_subscriptions":[{"tier_type":"Pro","expires_at":1813381711}]
}
```

The Pro expiry is not evidence of storage-rent expiry. No reservation,
price lookup, purchase, or storage change occurred.

## Custody-event and signer reads

```sh
curl --fail-with-body --max-time 25 -sS 'https://haatz.quilibrium.com/v1/onChainEventsByFid?fid=8531&event_type=EVENT_TYPE_ID_REGISTER&pageSize=1'
curl --fail-with-body --max-time 25 -sS 'https://haatz.quilibrium.com/v1/signersByFid?fid=8531'
```

Both returned HTTP 200. The event route returned three records despite
`pageSize=1`; implementations must also bound response bytes. Each had
`type`, `chainId`, `blockNumber`, `blockHash`, `blockTimestamp`,
`transactionHash`, `logIndex`, `fid`, `idRegisterEventBody`, `txIndex`,
`version`, and `tier_purchase_event_body`.

| Block | Event | `idRegisterEventBody.to` |
| ---: | --- | --- |
| 111894598 | `Register` | `0x5a39365ab5b935b06ffcdcd3ea0a008e4493b3c2` |
| 125202835 | `Transfer` | `0xbb7b6cece12040eac590b1a282d097e08a476800` |
| 131507662 | `Transfer` | `0xe227cb4a6c6587a9c89a14c50b92db75eb7f277f` |

These are node-reported historical records, not an independently checked
current custody result. The merged signer response contained six entries:
three `SIGNER_SOURCE_ONCHAIN` and three `SIGNER_SOURCE_OFFCHAIN`, with
`gaslessSignerCount: 3`, `gaslessSignerLimit: 1000`, and
`currentUserNonce: 1787106471`. Off-chain entries included scopes and expiry
metadata. No private key was accessed and no account-control proof was made.

The initial guessed `/v1/onChainIdRegistryEventByFid?fid=3` path returned
HTTP 404. Use the verified event route above. The older
`/v1/onChainSignersByFid?fid=3&pageSize=1` path returned HTTP 200 but covers
on-chain signers only.

## Hyper retention source trace

To check the gap between the older retention documentation and shipped
code, the pinned Hypersnap source was cloned to a temporary review directory.
Its HEAD matched `3dc7df14068e8e5b56fcb31e8e41bb956dacf183`. No upstream code
was changed or executed. The following findings are source inspection,
not claims about haatz's deployed binary or data completeness.

| Source | Observed behavior |
| --- | --- |
| [`engine.rs:252`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/storage/store/engine.rs#L252) | Instantiates Hyper shadow stores |
| [`engine.rs:1335`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/storage/store/engine.rs#L1335) | Dual-writes supported types; shadow merge errors do not fail the block |
| [`engine.rs:952`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/storage/store/engine.rs#L952) | Revokes messages in Hyper state on signer revocation |
| [`hyper/mod.rs:28`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/hyper/mod.rs#L28) | Hyper context disables pruning |
| [`main.rs:94`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/main.rs#L94) | Starts a Hyper backfill from historical shard chunks |
| [`hyper/backfill.rs`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/hyper/backfill.rs) | Skips empty chunk ranges; can save progress after errors; completeness must be checked separately |
| [`server.rs:1863`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/network/server.rs#L1863) | gRPC cast lookup, cast listing, and all-message listing use legacy stores |
| [`http_server.rs:2907`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/network/http_server.rs#L2907) | HTTP `castsByFid` bridges to the legacy all-message handler |
| [`server.rs:3163`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/network/server.rs#L3163) | v2 cast-by-hash/FID handlers also read legacy stores; no Hyper fallback |
| [`api/mod.rs:576`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/api/mod.rs#L576) | Search backfill reads Hyper casts |
| [`api/http.rs:1489`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/api/http.rs#L1489) | Search emits hash, author, text, and formatted timestamp; cursor ignored; no original signed message |
| [`rpc.proto:19`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/proto/definitions/rpc.proto#L19) | Existing gRPC `GetBlocks` and `GetShardChunks` provide a candidate raw-history recovery path |
| [`bin/hyper.rs`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/bin/hyper.rs) | Hyper diff/audit/metrics CLI remains placeholder output |

The cast-store and engine source contain tests for retention after legacy
capacity pruning. They were inspected but not executed here. They do not
establish public API access, historical coverage, or recovery after loss of
an operator node. The separate `HyperEnvelope.payload` schema is not a user
storage API; the inspected builder emits an empty payload.

Operational gate: supply two reachable unmodified nodes with documented
canonical block/chunk retention and gRPC access, or demonstrate an existing
complete signed-message recovery interface. Then test exact-message retrieval
after legacy pruning and restart with verified block coverage. This is a
specific next experiment, not evidence that node changes are mandatory.

## What remains unproven

- Compatible operation through a second reachable independent node.
- A newly authorized cast submission and exact-byte retrieval on that node.
- Cryptographic verification of node-reported network and current authority.
- Canonical inclusion, finality, historical completeness, and retention policy.
- ATProto projection, standard signed CAR verification, and reconstruction
  after both worker cache loss and network pruning.
- Large-file byte storage and recovery through the Farcaster network.

These observations support a preflight implementation and a restricted text
mapping experiment. They do not mark the reconstruction PoC complete.
