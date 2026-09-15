// Independent offline interoperability check using the official ATProto repo package.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { formatDidKey } from '@atproto/crypto';
import {
  blocksToCarFile,
  cidForRecord,
  MemoryBlockstore,
  MST,
  readCarWithRoot,
  Repo,
  verifyRepoCar,
} from '@atproto/repo';

const [path, did, publicKeyHex, count] = process.argv.slice(2);
if (!path || !did || !/^(02|03)[0-9a-f]{64}$/.test(publicKeyHex ?? '') || !/^\d+$/.test(count ?? '')) {
  throw new Error('Usage: node verify.mjs <repo.car> <did> <compressed-sec1-public-key-hex> <record-count>');
}
const bytes = new Uint8Array(await readFile(path));
const didKey = formatDidKey('ES256K', Buffer.from(publicKeyHex, 'hex'));
const verified = await verifyRepoCar(bytes, did, didKey);
const car = await readCarWithRoot(bytes); // The reader verifies every block CID.
const repo = await Repo.load(new MemoryBlockstore(car.blocks), car.root);
assert.equal(repo.version, 3);
assert.equal(repo.commit.prev, null);
assert.equal(repo.commit.sig.byteLength, 64);
assert.equal(verified.creates.length, Number(count));

// Rebuild a second MST using the independent incremental implementation.
let rebuilt = await MST.create(new MemoryBlockstore());
const paths = [];
for await (const record of repo.walkRecords()) {
  assert.equal(record.record.$type, record.collection);
  assert.equal((await cidForRecord(record.record)).toString(), record.cid.toString());
  const key = `${record.collection}/${record.rkey}`;
  rebuilt = await rebuilt.add(key, record.cid);
  paths.push(key);
}
assert.equal(paths.length, Number(count));
assert.equal((await rebuilt.getPointer()).toString(), repo.commit.data.toString());

// These negative controls ensure the verifier is not just decoding the file.
await assert.rejects(() => verifyRepoCar(bytes, 'did:web:wrong.example', didKey));
const wrongPublicKey = Buffer.from(publicKeyHex, 'hex');
wrongPublicKey[0] ^= 1; // Negating the SEC1 point produces a different valid key.
await assert.rejects(() => verifyRepoCar(bytes, did, formatDidKey('ES256K', wrongPublicKey)));
const corrupt = bytes.slice();
corrupt[corrupt.length - 1] ^= 1;
await assert.rejects(() => verifyRepoCar(corrupt, did, didKey));
await assert.rejects(() => verifyRepoCar(bytes.subarray(0, bytes.length - 7), did, didKey));
if (verified.creates.length > 0) {
  const incomplete = await readCarWithRoot(bytes);
  incomplete.blocks.delete(verified.creates[0].cid);
  const missing = await blocksToCarFile(incomplete.root, incomplete.blocks);
  await assert.rejects(() => verifyRepoCar(missing, did, didKey));
}

console.log(JSON.stringify({
  evidence: 'offline_fixture_only',
  verifier: '@atproto/repo@0.10.14',
  crypto: '@atproto/crypto@0.5.5',
  did: repo.did,
  revision: repo.commit.rev,
  commit: car.root.toString(),
  mst: repo.commit.data.toString(),
  records: paths.length,
  checks: ['block CIDs', 'commit signature', 'required prev null', 'record decoding',
    'independent MST rebuild', 'wrong DID rejected', 'wrong key rejected', 'tamper rejected',
    'truncation rejected', 'missing record rejected'],
}, null, 2));
