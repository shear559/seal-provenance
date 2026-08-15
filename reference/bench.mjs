// SEAL client-side microbenchmarks — whitepaper Appendix D.7.
// Measures, on THIS machine, the costs a SEAL client actually pays.
// Run: node bench.mjs   → bench_report.json + console table.
import { writeFileSync, readFileSync } from 'node:fs';
import os from 'node:os';
import { ethers } from 'ethers';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  exactHashOf, commitmentDigest, signCommitment, recoverSigner,
} from './seal_encoding.mjs';

// ---------------- environment ---------------------------------------------
const ethersVersion = JSON.parse(readFileSync(
  new URL('./node_modules/ethers/package.json', import.meta.url), 'utf8')).version;
const environment = {
  node: process.version,
  ethers: ethersVersion,
  noblePostQuantum: JSON.parse(readFileSync(
    new URL('./node_modules/@noble/post-quantum/package.json', import.meta.url),
    'utf8')).version,
  platform: `${os.platform()} ${os.arch()}`,
  cpu: os.cpus()[0].model,
  note: 'single-threaded Node.js main thread; pure-JS crypto (ethers + @noble), no native addons, no workers',
};

// ---------------- fixtures (same demo profile as the vectors) --------------
const KEY1 = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const DOMAIN = {
  chainId: 11155111,
  verifyingContract: '0x0000000000000000000000000000000000000001',
  registryId: ethers.keccak256(ethers.toUtf8Bytes('SEAL/registry/demo/1')),
};
const Z32 = ethers.ZeroHash;
const DOC_BYTES = ethers.toUtf8Bytes(
  'חותם דיגיטלי — אבטחה קריפטוגרפית מקצועית.');
const baseFields = {
  exactHashMethodId: 1, exactHash: Z32, sealMode: 0,
  fingerprintRoot: Z32, chunkRoot: Z32, cid: '', cidProfile: 0,
  issuer: ethers.ZeroAddress, documentId: 'BENCH-001', prevGuid: Z32,
  declaredTime: 1750000000n, sigMethodId: 1,
};

const nowMs = () => Number(process.hrtime.bigint()) / 1e6;
function meanMs(fn, iters) {
  const t0 = nowMs();
  for (let i = 0; i < iters; i++) fn(i);
  return (nowMs() - t0) / iters;
}

const results = {};

// ---- 1. commitment construction (file hash + EIP-712 digest) --------------
{
  const ITERS = 1000;
  // warm-up
  meanMs((i) => commitmentDigest(DOMAIN, {
    ...baseFields, exactHash: exactHashOf(DOC_BYTES), declaredTime: BigInt(i) }), 50);
  const ms = meanMs((i) => {
    const eh = exactHashOf(DOC_BYTES);
    commitmentDigest(DOMAIN, { ...baseFields, exactHash: eh,
      declaredTime: 1750000000n + BigInt(i) }); // vary a field — no memoization
  }, ITERS);
  results.commitmentConstruction = {
    iterations: ITERS, inputBytes: DOC_BYTES.length, msPerOp: +ms.toFixed(4),
    opsPerSec: Math.round(1000 / ms),
  };
}

// ---- 2/3. ECDSA sign + recover --------------------------------------------
{
  const ITERS = 50;
  const digests = Array.from({ length: ITERS }, (_, i) =>
    commitmentDigest(DOMAIN, { ...baseFields, exactHash: exactHashOf(DOC_BYTES),
      declaredTime: 1750001000n + BigInt(i) }));
  meanMs((i) => signCommitment(KEY1, digests[i % ITERS]), 10); // warm-up
  const msSign = meanMs((i) => signCommitment(KEY1, digests[i]), ITERS);
  const sigs = digests.map(d => signCommitment(KEY1, d).serialized);
  meanMs((i) => recoverSigner(digests[i % ITERS], sigs[i % ITERS]), 10); // warm-up
  const msRec = meanMs((i) => recoverSigner(digests[i], sigs[i]), ITERS);
  results.ecdsaSign = { iterations: ITERS, msPerOp: +msSign.toFixed(4),
    opsPerSec: Math.round(1000 / msSign) };
  results.ecdsaRecover = { iterations: ITERS, msPerOp: +msRec.toFixed(4),
    opsPerSec: Math.round(1000 / msRec) };
}

// ---- 4. ML-DSA-65 keygen / sign / verify ----------------------------------
{
  const ITERS = 20;
  const seeds = Array.from({ length: ITERS }, (_, i) =>
    ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes(`SEAL/bench/seed/${i}`))));
  const msgs = Array.from({ length: ITERS }, (_, i) =>
    ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes(`SEAL/bench/msg/${i}`))));
  ml_dsa65.keygen(seeds[0]); // warm-up
  const msKeygen = meanMs((i) => ml_dsa65.keygen(seeds[i]), ITERS);
  const keys = seeds.map(s => ml_dsa65.keygen(s));
  const msSign = meanMs((i) =>
    ml_dsa65.sign(msgs[i], keys[i].secretKey, { extraEntropy: false }), ITERS);
  const sigs = msgs.map((m, i) =>
    ml_dsa65.sign(m, keys[i].secretKey, { extraEntropy: false }));
  const msVerify = meanMs((i) =>
    ml_dsa65.verify(sigs[i], msgs[i], keys[i].publicKey), ITERS);
  results.mlDsa65 = {
    iterations: ITERS,
    keygenMsPerOp: +msKeygen.toFixed(3),
    signMsPerOp: +msSign.toFixed(3),
    verifyMsPerOp: +msVerify.toFixed(3),
    sizes: { publicKeyBytes: keys[0].publicKey.length,
             secretKeyBytes: keys[0].secretKey.length,
             signatureBytes: sigs[0].length, seedBytes: 32 },
  };
}

// ---- 5. dictionary-attack throughput --------------------------------------
{
  const TRIALS = 100000;
  const t0 = nowMs();
  for (let i = 0; i < TRIALS; i++)
    exactHashOf(ethers.toUtf8Bytes(`Form 17 — applicant: user${i}`));
  const dt = nowMs() - t0;
  results.dictionaryAttack = {
    trials: TRIALS, totalSeconds: +(dt / 1000).toFixed(3),
    trialCommitmentsPerSec: Math.round(TRIALS / (dt / 1000)),
    note: 'keccak256 trial commitments an attacker can form against an UNSALTED hash; CONFIDENTIAL-mode salts make each trial infeasible without the salt',
  };
}

// ---- 6. Merkle batching table ----------------------------------------------
{
  // Same tree rule as the v2 vectors: parent = keccak256(left || right),
  // fixed order, odd node promoted unchanged.
  function merkleRoot(leaves) {
    let level = leaves;
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i + 1 < level.length; i += 2)
        next.push(ethers.keccak256(ethers.concat([level[i], level[i + 1]])));
      if (level.length % 2 === 1) next.push(level[level.length - 1]);
      level = next;
    }
    return level[0];
  }
  const rows = [];
  for (const N of [1, 10, 100, 1000, 10000]) {
    const leaves = Array.from({ length: N }, (_, i) =>
      ethers.keccak256(ethers.toUtf8Bytes(`SEAL/bench/leaf/${i}`)));
    merkleRoot(leaves); // warm-up
    const t0 = nowMs();
    merkleRoot(leaves);
    const buildMs = nowMs() - t0;
    rows.push({
      N,
      buildMs: +buildMs.toFixed(3),
      anchorBytesPerSeal: +(32 / N).toFixed(4),
      proofLengthHashes: N === 1 ? 0 : Math.ceil(Math.log2(N)),
    });
  }
  results.merkleBatching = {
    treeRule: 'parent = keccak256(left || right), fixed left-right order, odd node promoted unchanged',
    rows,
  };
}

// ---------------- report ----------------------------------------------------
const report = { schema: 'SEAL/bench/v2', generatedAt: new Date().toISOString(),
                 environment, results };
writeFileSync(new URL('./bench_report.json', import.meta.url),
              JSON.stringify(report, null, 2));

console.log('SEAL client-side microbenchmarks');
console.log(`node ${environment.node} | ethers ${environment.ethers} | @noble/post-quantum ${environment.noblePostQuantum}`);
console.log(`${environment.platform} | ${environment.cpu}`);
console.log(environment.note, '\n');

console.table([
  { op: 'commitment construction (hash + EIP-712)', iters: 1000,
    'ms/op': results.commitmentConstruction.msPerOp,
    'ops/s': results.commitmentConstruction.opsPerSec },
  { op: 'ECDSA sign (secp256k1, RFC6979)', iters: 50,
    'ms/op': results.ecdsaSign.msPerOp, 'ops/s': results.ecdsaSign.opsPerSec },
  { op: 'ECDSA recover/verify', iters: 50,
    'ms/op': results.ecdsaRecover.msPerOp, 'ops/s': results.ecdsaRecover.opsPerSec },
  { op: 'ML-DSA-65 keygen', iters: 20, 'ms/op': results.mlDsa65.keygenMsPerOp,
    'ops/s': Math.round(1000 / results.mlDsa65.keygenMsPerOp) },
  { op: 'ML-DSA-65 sign (deterministic)', iters: 20,
    'ms/op': results.mlDsa65.signMsPerOp,
    'ops/s': Math.round(1000 / results.mlDsa65.signMsPerOp) },
  { op: 'ML-DSA-65 verify', iters: 20, 'ms/op': results.mlDsa65.verifyMsPerOp,
    'ops/s': Math.round(1000 / results.mlDsa65.verifyMsPerOp) },
]);

console.log(`ML-DSA-65 sizes: pk ${results.mlDsa65.sizes.publicKeyBytes} B, ` +
  `sk ${results.mlDsa65.sizes.secretKeyBytes} B, sig ${results.mlDsa65.sizes.signatureBytes} B`);
console.log(`Dictionary attack: ${results.dictionaryAttack.trialCommitmentsPerSec.toLocaleString()} ` +
  `trial commitments/s (${results.dictionaryAttack.trials.toLocaleString()} trials in ` +
  `${results.dictionaryAttack.totalSeconds} s)\n`);

console.table(results.merkleBatching.rows);
console.log('Wrote bench_report.json');
