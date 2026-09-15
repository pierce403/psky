# Authentication validation, 2026-09-15

Scope: the Farcaster consent and ATProto password-session implementation.
No live FID has been bound. No signer was approved and no cast or transaction
was submitted. Full stock-app login and federation are not claimed.

## Verified

- Rust cryptographic fixtures verify independent viem SIWF signatures, EOA and
  deployed ERC-1271 wallets, exact challenge binding, finalized registry reads,
  FID transfer, auth-key removal, contract policy changes and block rollback.
- Credential tests exercise private persistence, random-password verifiers,
  strict JWT validation, refresh replay rejection, logout, revocation and
  stable signed empty repositories.
- Account HTTP tests exercise origin/Host separation, CORS, secret redaction,
  bounded guesses, transient grants, configuration changes and restart behavior.
- The official `@atproto/lex-password-session` 0.2.3 passed against a real
  ephemeral HTTP listener with a deliberately seeded test account. It covered
  discovery, the stock client's empty auth-factor field, login, session reads,
  refresh, replay rejection, logout and password reuse.
- Both browser-script suites passed, covering secret clearing, stale requests,
  grant expiry, unsafe URLs, QR rendering, clipboard fallback and revocation.
- The real browser rendered the account portal and new management fields.
  The unconfigured portal correctly disabled sign-in and reported pending
  storage proof. No browser warning/error logs were observed on that page.
- A separate disposable node used its management API to configure login. One
  real relay channel was created, its QR generated, and polling returned
  `pending`. The node remained unbound and `/ready` returned 503. The test
  process was stopped; the unsigned relay challenge expires on its own.
- Read-only calls confirmed that the default Optimism endpoint accepts
  finalized, hash-pinned registry requests. This is availability evidence, not
  evidence that the user's live wallet proof succeeds.

## Reproduce

Use the commands in [the account guide](../authentication.md#diagnostics-and-tests).
The SDK test is ignored by the default Rust run because it needs npm packages;
CI installs the pinned package and runs the test explicitly. Generated Rustdoc
is checked with warnings treated as errors.

The running development node retains its original settings with login disabled.
It was not silently bound to a disposable localhost DID. Choose the public
service identity before approving the real Farcaster login.

## Remaining gates

Public HTTPS deployment, external DID/handle resolution, actual user consent,
the stock Bluesky app's social/API requests, AppView/indexing, Farcaster-backed
content reconstruction, protected publishing and cross-worker revocation remain
separate acceptance tests.
