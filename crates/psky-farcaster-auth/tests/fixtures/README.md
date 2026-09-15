# Authentication test vector

`siwf-eoa.json` was generated independently with viem 2.56.0
`createSiweMessage` and `privateKeyToAccount(...).signMessage`.
The private scalar is the public test value `1`, never a user's wallet key.
The message is expired and only used with a deterministic test clock.

Parameters:

- Domain: `pds.example`
- URI: `https://pds.example/onboard`
- Statement: `Farcaster Auth`
- Chain: Optimism, `10`
- Nonce: `0123456789ABCDEF0123456789ABCDEF`
- Issued at and not before: Unix `1770000000`
- Expiration: Unix `1770000300`
- Resource: `farcaster://fid/8531`

The vector tests the signed message and address only. Registry authorization
for this FID is simulated by the separate loopback RPC tests.

Protocol references:

- [Official Farcaster verifier](https://github.com/farcasterxyz/auth-monorepo/blob/ae3dffd339a161bcbed870cf0f3cd36b756b94b2/packages/auth-client/src/messages/verify.ts)
- [Official registry connector](https://github.com/farcasterxyz/auth-monorepo/blob/ae3dffd339a161bcbed870cf0f3cd36b756b94b2/packages/auth-client/src/clients/ethereum/viemConnector.ts)
- [Official relay channel behavior](https://github.com/farcasterxyz/auth-monorepo/blob/ae3dffd339a161bcbed870cf0f3cd36b756b94b2/apps/relay/src/handlers.ts)
- [SIWE specification](https://eips.ethereum.org/EIPS/eip-4361)
- [ERC-1271 specification](https://eips.ethereum.org/EIPS/eip-1271)

Live checks are not part of `cargo test`. Creating a relay channel requires a
user-triggered login. Completing a login requires approval in the user's
Farcaster app. Tests never approve a signer, submit a cast or send a transaction.
