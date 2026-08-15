// Measures the size of an Appendix-A-shaped verification bundle (JSON
// encoding) built from REAL v2 vector data (G-09 seal + G-15 batch path),
// with representative sizes for the chain-proof members (L1 receipt proof,
// OpenTimestamps proof). Canonical CBOR is smaller; JSON is the upper bound.
// Run: node measure_bundle.mjs
import { readFileSync } from 'node:fs';

const v2 = JSON.parse(readFileSync(new URL('./SEAL_test_vectors_v2.json', import.meta.url), 'utf8'));
const vecs = Array.isArray(v2.vectors) ? v2.vectors : Object.values(v2.vectors ?? v2);
const find = id => vecs.find(v => String(v.id).includes(id));
const g9 = find('G-09'), g15 = find('G-15');

const h32 = c => '0x' + c.repeat(64);
const batchPath = g15.path ?? g15.proof ?? g15.inclusionPath;
const path14 = Array.from({ length: 14 }, (_, i) => batchPath[i % batchPath.length]);

const bundle = {
  schemaVersion: 1,
  seal: g9.fields ?? g9,
  commitmentPreimage: g9.fields ?? g9,
  signatures: [{ sigMethodId: 1, sig: g9.signature?.serialized ?? g9.signature }],
  batchPath,
  logInclusion: { leafIndex: 1234, path: path14 },
  checkpoints: [{ l2Header: h32('ab'), l1Header: h32('cd'), receiptProof: Array.from({ length: 6 }, () => h32('ef')) }],
  otsProof: '0x' + '12'.repeat(640), // typical OTS proof ~0.5-1 kB
  renewalPaths: [],
  lifecycle: null,
  policySnapshot: { id: 'baseline-v1', hash: h32('77') },
  fingerprintSet: [],
  chunkSpec: null,
};

const ecdsaOnly = JSON.stringify(bundle).length;
bundle.signatures.push({ sigMethodId: 3, sig: '0x' + '00'.repeat(3309) }); // ML-DSA-65 sig, hex-encoded
const withMldsa = JSON.stringify(bundle).length;

console.log('bundle JSON (ECDSA only):', (ecdsaOnly / 1024).toFixed(1), 'kB');
console.log('bundle JSON (+ML-DSA-65):', (withMldsa / 1024).toFixed(1), 'kB');
