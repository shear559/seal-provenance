// SEAL Phase-1 reference demo — regenerates every value in whitepaper
// Appendix D (D.1–D.6) and writes the machine-readable conformance vectors.
// Run: node seal_demo.mjs
import { writeFileSync } from 'node:fs';
import { ethers } from 'ethers';
import {
  SEAL_TYPE_STRING, exactHashOf, commitmentDigest, guidOf,
  signCommitment, recoverSigner,
} from './seal_encoding.mjs';

// ---- D.1 inputs (demo profile — never use this key in production) ----
const DOC = 'SEAL reference vector 001 — provenance, not truth: the artifact that was registered, attested by which key, and when.';
const DOC_BYTES = ethers.toUtf8Bytes(DOC);
const SIGNER_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'; // Hardhat/Anvil well-known account #1
const SIGNER = new ethers.Wallet(SIGNER_KEY).address;
const REGISTRY_ID = ethers.keccak256(ethers.toUtf8Bytes('SEAL/registry/demo/1'));
const DOMAIN = {
  chainId: 11155111, // Sepolia
  verifyingContract: '0x0000000000000000000000000000000000000001',
  registryId: REGISTRY_ID,
};
const Z32 = ethers.ZeroHash;
const Z20 = ethers.ZeroAddress;

const baseFields = {
  exactHashMethodId: 1, // keccak256
  exactHash: Z32,       // set per mode
  sealMode: 0,          // PUBLIC
  fingerprintRoot: Z32, // none (Phase-1)
  chunkRoot: Z32,       // none
  cid: '',              // nothing pinned in the demo
  cidProfile: 0,        // none
  issuer: Z20,
  documentId: 'DOC-001',
  prevGuid: Z32,
  declaredTime: 1750000000n,
  sigMethodId: 1,       // ECDSA-secp256k1 low-s
};

const out = { schema: 'SEAL/conformance/v1', typeString: SEAL_TYPE_STRING, domain: { name: 'SEAL', version: '1', ...DOMAIN }, vectors: [] };
const log = (k, v) => console.log(k.padEnd(18), v);

// ---- D.2 PUBLIC-mode seal ----
console.log('— D.2 PUBLIC-mode seal —');
const ehPub = exactHashOf(DOC_BYTES);
const pubFields = { ...baseFields, exactHash: ehPub };
const cPub = commitmentDigest(DOMAIN, pubFields);
const sigPub = signCommitment(SIGNER_KEY, cPub);
const gPub = guidOf(cPub, SIGNER);
log('docBytes', `${DOC_BYTES.length} B`);
log('exactHash', ehPub);
log('commitmentDigest', cPub);
log('signature', sigPub.serialized);
log('recoveredSigner', recoverSigner(cPub, sigPub.serialized) + (recoverSigner(cPub, sigPub.serialized) === SIGNER ? '  == signer ✓ (G3)' : '  MISMATCH ✗'));
log('guid', gPub);
out.vectors.push({ id: 'D2-public', mode: 'PUBLIC', document: DOC, fields: { ...pubFields, declaredTime: '1750000000' }, exactHash: ehPub, commitmentDigest: cPub, signature: sigPub, signer: SIGNER, guid: gPub });

// ---- D.3 tamper-evidence ----
console.log('\n— D.3 tamper-evidence (G1) —');
const TAMPERED = DOC.replace('001', '00l');
const ehTam = exactHashOf(ethers.toUtf8Bytes(TAMPERED));
log('tamperedHash', ehTam);
log('integrity', ehTam === ehPub ? 'BROKEN ✗' : 'failed (mismatch detected) ✓');
out.vectors.push({ id: 'D3-tamper', document: TAMPERED, exactHash: ehTam, expectIntegrity: 'failed' });

// ---- D.4 cross-chain replay rejection ----
console.log('\n— D.4 cross-chain replay (R11 / Theorem 3) —');
const cMainnet = commitmentDigest({ ...DOMAIN, chainId: 1 }, pubFields);
const recReplay = recoverSigner(cMainnet, sigPub.serialized);
log('replayRecovered', recReplay + (recReplay !== SIGNER ? '  != signer → attestation fails ✓' : '  REPLAYED ✗'));
out.vectors.push({ id: 'D4-replay', replayChainId: 1, recovered: recReplay, expect: 'attestation-fail' });

// ---- D.5 CONFIDENTIAL-mode + dictionary experiment ----
console.log('\n— D.5 CONFIDENTIAL mode (G2 / Theorem 2) —');
const SALT = '0x3bda72745501f8387ce518bb053bb6e699d52ae5ee4e491b28c7172ea4ae3e10';
const ehConf = exactHashOf(DOC_BYTES, SALT);
const confFields = { ...baseFields, exactHash: ehConf, sealMode: 1 };
const cConf = commitmentDigest(DOMAIN, confFields);
const sigConf = signCommitment(SIGNER_KEY, cConf);
const gConf = guidOf(cConf, SIGNER);
log('salt', SALT);
log('exactHash', ehConf);
log('commitmentDigest', cConf);
log('guid', gConf);
out.vectors.push({ id: 'D5-confidential', mode: 'CONFIDENTIAL', salt: SALT, fields: { ...confFields, declaredTime: '1750000000' }, exactHash: ehConf, commitmentDigest: cConf, signature: sigConf, signer: SIGNER, guid: gConf });

// Dictionary attack: 100,000 candidates "Form 17 — applicant: user{i}"
console.log('\nDictionary attack, 100,000 candidates:');
const TARGET_I = 54321;
const target = `Form 17 — applicant: user${TARGET_I}`;
const unsaltedTarget = exactHashOf(ethers.toUtf8Bytes(target));
let found = -1; const t0 = process.hrtime.bigint();
for (let i = 0; i < 100000; i++) {
  if (exactHashOf(ethers.toUtf8Bytes(`Form 17 — applicant: user${i}`)) === unsaltedTarget) { found = i; break; }
}
const dtMs = Number(process.hrtime.bigint() - t0) / 1e6;
log('vs UNSALTED', `target identified at i = ${found} (${(dtMs / 1000).toFixed(2)} s)`);
const saltedTarget = exactHashOf(ethers.toUtf8Bytes(target), SALT);
let confs = 0;
for (let i = 0; i < 100000; i++) {
  if (exactHashOf(ethers.toUtf8Bytes(`Form 17 — applicant: user${i}`)) === saltedTarget) confs++;
}
log('vs SALTED', `${confs} matches — trial commitments cannot be formed without the salt`);
out.vectors.push({ id: 'D5-dictionary', candidates: 100000, unsaltedFoundAt: found, unsaltedSeconds: +(dtMs / 1000).toFixed(2), saltedConfirmations: confs });

// ---- D.6 determinism ----
console.log('\n— D.6 determinism —');
const cPub2 = commitmentDigest(DOMAIN, pubFields);
log('recomputed', cPub2 === cPub ? 'bit-exact ✓' : 'NON-DETERMINISTIC ✗');

writeFileSync(new URL('./SEAL_test_vectors.json', import.meta.url), JSON.stringify(out, null, 2));
console.log('\nWrote SEAL_test_vectors.json');
