// Verify all four local-worker exports using the pinned official ATProto library.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const output = process.argv[2];
if (!output) throw new Error('Usage: node scripts/verify-lab.mjs <lab-output-directory>');
const report = JSON.parse(readFileSync(join(output, 'report.json'), 'utf8'));
assert.equal(report.mode, 'offline-fixture');
assert.equal(report.network_proof, false);
const publicKey = readFileSync(join(output, 'public-key.hex'), 'utf8').trim();
const verifier = fileURLToPath(new URL('../crates/psky-repo/interop/verify.mjs', import.meta.url));
const results = [];
for (const revision of [1, 2]) {
  for (const worker of ['worker-a', 'worker-b']) {
    const car = resolve(output, worker, `rev-${revision}.car`);
    const result = JSON.parse(execFileSync(process.execPath, [verifier, car, report.did, publicKey, String(revision)], {encoding: 'utf8'}));
    assert.equal(result.revision, revision === 1 ? '3lcyfmqxq2k22' : '3lcyfmqxq2k23');
    results.push({worker, ...result});
  }
  const [a, b] = results.slice(-2);
  assert.equal(a.commit, b.commit);
  assert.equal(a.mst, b.mst);
  assert.equal(a.revision, b.revision);
}
console.log(JSON.stringify({scope: 'offline-fixture-only', exports_verified: 4, results}, null, 2));
