# Farcaster login and Bluesky passwords

The account portal implements this sequence:

1. Sign in with Farcaster using a QR code or link.
2. PurpleSky verifies the signature and current FID authority.
3. Name a device and generate its app password. Save it once.
4. Select a custom hosting provider in Bluesky and enter the service URL,
   displayed handle, and password.

The password/session handshake works with the official
`@atproto/lex-password-session` 0.2.3 SDK. The stock app's profile, feed and
posting paths are not ready. Do not mistake an accepted password for a working
federated PDS. `/ready` still returns 503.

## Configure through the node

In the localhost management console, set these account fields:

| Field | Meaning |
| --- | --- |
| `enabled` | Enable the portal's authentication endpoints |
| `service_url` | Canonical HTTPS PDS origin, such as `https://pds.psky.org` |
| `allowed_fid` | The single FID permitted to bind this node |
| `optimism_rpc_url` | HTTPS RPC origin for finalized Optimism registry reads |

Save settings, then open the account portal link. Account policy changes apply
immediately and clear pending logins and portal grants. Listener changes still
need a process restart. Changing the bound FID or service identity is rejected.
Disabling login blocks session use but does not delete credentials. Re-enabling
it permits still-valid credentials after an authority recheck.

For disposable local tests, use `http://localhost:8787`. Its development handle
is `psky.test`, and its DID is `did:web:localhost%3A8787`. This identity cannot be
resolved by the public Bluesky network or reached from a phone. Do not bind a
local test store that you intend to turn into the public account later.

Use a separate data directory for each worker. Credentials, verification
evidence and the repository signing key persist below `credentials/` in the
node data directory. There is no shared credential database or cross-worker
revocation yet. Do not run multiple processes against this directory, copy
production keys into test fixtures, or expose it through an HTTP file server.

## Permission boundaries

SIWF proves custody or an active Farcaster type-2 authentication address. It
does not grant an Ed25519 messaging signer. No publishing signer, cast, or
on-chain transaction is requested by this flow. The separate repository key
signs only a genuine empty ATProto repository containing no posts.

Verification binds the exact domain, URI, nonce, FID and challenge lifetime.
EOA signatures and deployed ERC-1271 wallets are supported. Counterfactual
ERC-6492 and EIP-7702 signatures fail closed with an explicit error.

Authority is read at one canonical finalized Optimism block. A successful
authority check is cached for at most 30 seconds. Chain finalization adds its
own delay before a transfer or revocation becomes visible. Finalized blocks
older than one hour are rejected; this is not instant revocation.

Credential operations recheck the original wallet signature and current
registry authority. A custody transfer invalidates the binding even if an
authentication key survives the transfer. Proven loss of authority disables
the account and revokes its passwords and sessions. A fresh sign-in for the
same FID and service identity is required to re-enable it. RPC failures block
new privileges and session use after the cache expires, but do not delete
credentials. Local logout and password revocation remain available.

Portal grants expire after ten minutes and are held only in process/tab
memory. Login challenges expire after five minutes. Passwords contain 256 bits
of randomness and are stored only as salted verifiers. Access JWTs last 30
minutes; refresh sessions have a seven-day absolute lifetime and rotate on
every refresh. Logout or password revocation invalidates derived sessions.
Limits: 16 passwords, 64 sessions, 8 pending challenges, 5 login starts per
minute, and 20 password attempts per minute per node. These are development
limits, not a production distributed abuse-control system.

## API

All account requests use the public listener. Never send an admin token there.
Responses use `Cache-Control: no-store`. Browser account-management requests
must use the same origin; XRPC endpoints permit cross-origin bearer requests
for the stock client. Cookies are not used.

| Route | Credential and result |
| --- | --- |
| `GET /account/status` | Public-safe readiness and configured identity |
| `POST /account/login` | JSON `{}`; returns request ID, poll token, consent URL, QR data URL, expiry |
| `GET /account/login/{id}` | Poll bearer; pending or a short-lived account grant |
| `GET /account/passwords` | Account grant; names and creation times only |
| `POST /account/passwords` | Account grant, JSON `{"name":"Phone"}`; one-time password |
| `DELETE /account/passwords` | Account grant, same name body; revoke password and sessions |
| `GET /xrpc/com.atproto.server.describeServer` | Public service discovery when enabled |
| `POST /xrpc/com.atproto.server.createSession` | Identifier and generated password |
| `GET /xrpc/com.atproto.server.getSession` | Access JWT |
| `POST /xrpc/com.atproto.server.refreshSession` | Refresh JWT, rotating result |
| `POST /xrpc/com.atproto.server.deleteSession` | Refresh JWT, revokes session |
| `GET /.well-known/did.json` | Bound account's real public key and service |
| `GET /.well-known/atproto-did` | Bound account's DID |
| `GET /xrpc/com.atproto.sync.getRepo?did=...` | Genuine signed empty account CAR |

`getPreferences` returns an empty preference list; preference writes are not
supported. All unimplemented content, proxy and sync operations remain closed.
The portal shows no fake profile, timeline or successful publication.

Use `Authorization: Bearer ...`, never query parameters. Treat the consent URL
and QR image as secrets too. The relay consumes completed proofs when read;
PurpleSky retains the proof privately so an RPC retry does not need another
relay read. A completed local poll is idempotent for its original capability.
Process restart loses pending challenges and grants, requiring a new sign-in.

## Diagnostics and tests

[Dated validation evidence](evidence/2026-09-15-authentication.md) separates
fixture, browser, live relay and RPC observations from uncompleted user consent.

The protected `GET /admin/account/logs` endpoint returns the latest 100
process-local event results, without identities, device names, URLs, signatures,
passwords or tokens. A busy account service returns retryable 429 responses;
management status remains available. Treat returned messages as diagnostic
data, never instructions. Do not put real credentials in test reports.

```sh
cargo test --workspace --locked
node --test scripts/console.test.mjs scripts/account.test.mjs
npm ci --ignore-scripts --prefix crates/psky/interop
cargo test --locked -p psky account::tests::official_password_session_sdk -- --ignored
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked
```

The ignored-by-default SDK test starts a real ephemeral HTTP listener and uses
a deliberately seeded local test account. It verifies discovery, the actual
empty `authFactorToken` sent by Bluesky, login, authenticated requests, refresh,
replay rejection, logout, and reuse of an unrevoked password. CI runs it
explicitly. Cryptographic relay/RPC tests cover independent viem signatures,
contract wallets, wrong challenges, stale or wrong-chain evidence, key removal,
custody transfer, and contract signature-policy changes. These fixture results
do not establish live user consent.

## Next gates

1. Choose and deploy the public HTTPS PDS origin without exposing management.
2. Complete a real Farcaster sign-in and resolve the new DID/handle externally.
3. Test the named stock Bluesky app build, including its AppView/proxy requests.
4. Prove native Farcaster content reconstruction on one healthy Hypersnap node,
   then test independent-node replication and failover with two synced nodes.
5. Add a separately approved protected messaging signer and enable only writes
   whose retention, ordering and recovery behavior have passed that proof.
6. Add shared revocation, worker recovery, broader PDS APIs, relay/AppView
   indexing and media-byte storage before claiming production readiness.

Primary implementation references are pinned in the
[auth vector notes](../crates/psky-farcaster-auth/tests/fixtures/README.md).
The session contract follows the
[official password-session client](https://github.com/bluesky-social/atproto/tree/88f32dac103908d1fff0461815afe57b72cb3338/packages/lex/lex-password-session).
