# Unmodified Hypersnap storage feasibility

Status: investigated, not proven. Reviewed 2026-09-15. Covers F-001, F-002,
and the storage prerequisites for F-007, F-013, and F-014.

## Result

Native Farcaster casts provide a plausible text-only substrate. The public
node returns cast text, stable message hashes, and signed message metadata.
It does not provide a generic ATProto record, block, or media-byte store.
Neither a new-write round trip nor two independent node recovery has been
demonstrated. See the [read-only evidence](evidence/2026-09-15-hypersnap-preflight.md).

The first candidate is a restricted mapping from ordinary text casts to
`app.bsky.feed.post`. Keep the text in the cast and define the minimum shared
metadata needed for ATProto record keys, timestamps, projection versions,
publication order, and signed commits. Unsupported record fields must be
rejected until their representation is defined. This is a proposed mapping,
not permission to encode arbitrary repository data into public casts.

The outstanding decisions are a dedicated write-test identity and signer,
a second reachable node or an operator-run unmodified node, and an explicit
retention policy. Media remains a separate storage gate.

## Pinned references and live version

- Hypersnap source: [`3dc7df14068e8e5b56fcb31e8e41bb956dacf183`](https://github.com/farcasterorg/hypersnap/tree/3dc7df14068e8e5b56fcb31e8e41bb956dacf183).
- Hypersnap documentation: [`85fb17b4212fdb9a28ea1f01d656b6eed1d7b4ae`](https://github.com/farcasterorg/hypersnap-docs-web/tree/85fb17b4212fdb9a28ea1f01d656b6eed1d7b4ae).
- Public node: `https://haatz.quilibrium.com`, reporting `0.13.5`.

The inspected source revision and the deployed binary are different evidence.
The node exposes a version string, not a build SHA. Its correspondence to the
pinned source has not been independently established.

## Data mapping

| PurpleSky data | Existing representation | Constraint or remaining work |
| --- | --- | --- |
| Plain post text | Native `CAST_ADD` text | Candidate for a restricted projection; public Farcaster content |
| Post removal | `CAST_REMOVE` targeting the cast hash | Native removal differs from an ATProto record-key delete; keep explicit mapping metadata |
| Post update | No native in-place cast update | A remove plus new cast is not an atomic ATProto update; unsupported initially |
| Profile fields | Typed `USER_DATA_ADD` messages | Validate each field mapping; no arbitrary user-data namespace |
| Follows and reactions | Typed link/reaction messages | Semantics and identifiers differ; outside the first text proof |
| Arbitrary ATProto records | No general record message found | Unsupported until a lossless allowed representation is specified |
| ATProto keys, revisions, commit signatures | No native equivalent | Small shared metadata needs a defined recovery mechanism |
| Large-file bytes | No byte-storage message found | Cast embeds hold URLs or cast IDs; media gate unresolved |
| Private credentials and sessions | No suitable private network store | Separate protected metadata storage required |

The [message schema](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/proto/definitions/message.proto)
defines casts, reactions, links, verifications, user data, username proofs,
frame actions, link compaction, storage lending, and key lifecycle messages.
An enum entry is not by itself evidence that an operation is accepted by the
live network. Frame state and key metadata are not generic content-storage
interfaces.

The cast store uses remove-wins behavior, then timestamp and hash ordering
for conflicts. A different cast body produces a different hash. See the
[cast store](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/storage/store/account/cast_store.rs).

## Capacity and costs

The pinned [cast validator](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/core/validations/cast.rs)
counts UTF-8 bytes:

| Cast type | Text length | Additional condition |
| --- | --- | --- |
| `CAST` | At most 320 bytes | An otherwise empty cast is invalid |
| `LONG_CAST` | 321 through 1,024 bytes | Select the correct cast type |
| `TEN_K_CAST` | 1,025 through 10,000 bytes | Pro account required |

The same validator allows at most ten mentions and two embeds, or four embeds
for Pro accounts. These are source findings, not newly submitted boundary
tests. ATProto text constraints must also be checked independently.

Per-FID allocations are typed message counts, not an unlimited byte allowance.
The read of FID `8531` reported 20,000 casts allowed with 4,813 used, four
legacy storage units, and a Pro subscription. Reaction allocation was already
full at 10,000. These observations are specific to that account and instant.
Do not treat them as a reservation for PurpleSky. Current prices, rent expiry,
submission rate limits, and any cost of a fresh identity remain unmeasured.
No storage purchase, key registration, or network write was performed.

## Retention and recovery

The pinned [retention policy](https://github.com/farcasterorg/hypersnap-docs-web/blob/85fb17b4212fdb9a28ea1f01d656b6eed1d7b4ae/src/appendix/retention.md)
states that older live messages can be pruned when storage expires or its
allocation is exceeded. That document does not describe the Hyper shadow
storage found in current source, so it is insufficient by itself to assess
Hypersnap retention.

Four different things must be measured:

1. Live casts and other current account messages, subject to allocation rules.
2. Historical blocks and shard chunks, subject to node configuration.
3. Local event history, subject to its own retention window.
4. Hyper shadow state, whose availability and recovery interface need separate
   verification.

The pinned
[`ShardEngine`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/storage/store/engine.rs#L252)
creates shadow stores and applies supported message merges to them.
[`StateContext::Hyper`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/hyper/mod.rs#L28)
disables pruning. The source includes retention tests, but they were not run
in this review. Shadow writes are best-effort: merge errors do not fail the
canonical block. Semantic replacement/removal still applies, and signer
revocation also removes affected shadow messages. It is not an immutable
archive of every prior version.

The [backfill](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/hyper/backfill.rs)
replays locally retained shard chunks into shadow stores. It skips missing
chunk ranges and records progress despite individual merge or commit errors.
A completion checkpoint therefore does not establish complete history.

The pinned HTTP and gRPC cast read handlers use legacy stores, with no Hyper
fallback. The v2 cast lookup and cast-by-FID implementation also uses legacy
stores. Search backfill does read Hyper casts, but the search response returns
selected text fields, omits the signed original message, ignores the supplied
cursor, and is not a complete history interface. See
[`server.rs`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/network/server.rs#L1863),
[`api/mod.rs`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/api/mod.rs#L576),
and [`api/http.rs`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/api/http.rs#L1489).

One unmodified-node candidate is to retain canonical blocks and shard chunks,
then recover original messages through the existing gRPC `GetBlocks` and
`GetShardChunks` methods. Their schemas include the network/block metadata and
original messages. This needs reachable gRPC endpoints, verified historical
coverage, a trusted validator set, and an actual replay/recovery test. It
does not require a new node message type. No public gRPC endpoint or complete
block range was verified in this run.

At the pinned source revision,
[`PruningConfig`](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/cfg.rs)
defaults to no configured block-retention duration and three days of event
retention. The [pruning job](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/jobs/block_pruning.rs)
can remove old blocks and shard chunks when configured. These defaults do not
establish either public node's actual policy. The whitepaper's historical
one-week example is not the current configuration default.

A live-state scan can reconstruct retained posts. It cannot recover missing
post bodies, deleted historical versions, or the exact sequence of earlier
signed ATProto commits from metadata alone. A missing source message must
stop reconstruction of the affected published state. Silent omission would
turn data loss into a new repository state.

For the bounded proof, reserve sufficient storage and fail when a referenced
cast is absent. For long-term recovery, first test two unmodified nodes with
retained canonical blocks, recording exactly which ranges survive restart
and bootstrap. Hyper shadow storage alone does not close the public recovery
API gap. Keeping bodies in a separate PurpleSky database would violate the
current scope.

## Ordering and publication

The [routing implementation](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/mempool/routing.rs)
assigns ordinary account messages to a shard by hashing the FID. Storage
lending and gasless key changes route to shard zero. The
[Snapchain design](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/site/docs/pages/whitepaper.mdx)
describes ordered shard blocks and a coordinating block chain.

Use committed block/shard position and the message hash when defining a
publication order. A cast timestamp, HTTP arrival order, or pagination cursor
is not proof of canonical inclusion. The particular historical API, proof
verification, shard mapping, and completeness rules still need implementation
and live validation.

The [submit implementation](https://github.com/farcasterorg/hypersnap/blob/3dc7df14068e8e5b56fcb31e8e41bb956dacf183/src/network/server.rs)
simulates the message, enqueues it in the mempool, and returns after the
mempool result. It does not wait for a committed block. PurpleSky must keep
these stages distinct:

1. Submitted and admitted to the mempool.
2. Observed in the selected canonical network state.
3. Recoverable through the agreed independent node and retention sources.
4. Authorized ATProto commit signed and its publication metadata persisted.

Only the final stage can satisfy a successful durable PDS write response.
Two nodes returning the same cast provide useful recovery evidence but do
not alone establish the validator trust model or historical completeness.

## Identity and endpoint findings

Both the examined Quorum desktop fork and the upstream shared client use
`https://haatz.quilibrium.com`. The mobile signer code uses that shared
client. This discovers one endpoint, not multiple independent nodes.
The other public endpoint inspected, `http://209.97.147.208:3381`, timed out.

Public lookup resolves `deanpierce.eth` to FID `8531`. This is an existing
account, not the fresh test identity called for by F-002. Its public records
may be read for preflight; the lookup does not prove custody, provide a
signing key, or authorize changing that account.

`/v1/info` has no network field. A retained message reports
`FARCASTER_NETWORK_MAINNET`, which is node-reported evidence, not independent
network verification. Current account authority also requires more than
reading historical registration events. Use the merged `/v1/signersByFid`
surface when inspecting messaging keys: the older on-chain-only route omits
gasless keys. Messaging authority and account custody remain separate.

## Media finding

The inspected Quorum mobile
[video service](https://github.com/QuilibriumNetwork/quorum-mobile/blob/d4fc312a12482da9bb2ba8c7f40f925541bde083/services/farcaster/videoUpload.ts)
requests an authenticated upload from `client.farcaster.xyz`, uploads to a
returned TUS URL, and embeds the resulting URL in a cast. The source shows
a client media service dependency, not Hypersnap storage of the file bytes.
Its actual hosting, retention, portability, and account requirements were
not tested. No upload was attempted.

That existing client path may inform a later storage choice. It does not
satisfy the current requirement that another Hypersnap node recover the
original media bytes after cache loss.

## Next proof

- Configure a dedicated FID and an authorized, revocable messaging signer.
- Obtain two reachable compatible nodes, recording peer IDs and trust policy.
- Select one ordinary short text cast with no extra ATProto fields.
- Define the shared metadata schema and the exact commit/publication boundary.
- Submit once through A, verify inclusion, then retrieve the original signed
  message through B while A is unavailable.
- Rebuild and independently verify the same ATProto repository on both workers.
- Test retries, missing history, and failure between signing and publication.
- Keep F-001/F-007 incomplete until the network write, independent retrieval,
  signed CAR verification, and recovery evidence actually exist.
