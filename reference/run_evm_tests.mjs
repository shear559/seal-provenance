// SEAL reference registry — in-EVM conformance + behavior suite.
//
// Compiles SealRegistry.sol with solc-js (optimizer, 200 runs), deploys it on
// @ethereumjs/vm (chainId 11155111), and runs the 15 numbered assertions from
// the whitepaper test plan. The byte-for-byte conformance oracle is the
// NORMATIVE client encoder in seal_encoding.mjs (ethers TypedDataEncoder).
//
// Run: node run_evm_tests.mjs

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import solc from 'solc';
import { ethers } from 'ethers';
import { createVM, runTx } from '@ethereumjs/vm';
import { createLegacyTx } from '@ethereumjs/tx';
import { createCustomCommon, Mainnet, Hardfork } from '@ethereumjs/common';
import { createBlock } from '@ethereumjs/block';
import {
  createAccount,
  createAddressFromPrivateKey,
  hexToBytes,
  bytesToHex,
} from '@ethereumjs/util';

import {
  commitmentDigest as clientCommitmentDigest,
  guidOf as clientGuidOf,
  signCommitment,
} from './seal_encoding.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------- constants
const CHAIN_ID = 11155111n;
const HARDFORK = Hardfork.Cancun;
const OPTIMIZER_RUNS = 200;
const SEAL_FEE = 10n ** 14n; // 0.0001 ETH
const ZERO32 = '0x' + '00'.repeat(32);
const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

const vectors = JSON.parse(readFileSync(join(__dir, 'SEAL_test_vectors.json'), 'utf8'));
const REGISTRY_ID = vectors.domain.registryId;
const D2 = vectors.vectors.find((v) => v.id === 'D2-public');

// Well-known Hardhat dev keys (never used on real networks).
const KEYS = {
  deployer: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', // #0
  signer1: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d', // #1 (vectors signer)
  signer2: '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a', // #2
};

// ------------------------------------------------------------------ compile
console.log('== compile ==');
const source = readFileSync(join(__dir, 'SealRegistry.sol'), 'utf8');
const solcInput = {
  language: 'Solidity',
  sources: { 'SealRegistry.sol': { content: source } },
  settings: {
    optimizer: { enabled: true, runs: OPTIMIZER_RUNS },
    // viaIR required: the 13-field Seal712 hashStruct (typehash + 12 fields,
    // 2 of them keccak'd strings) exceeds the legacy pipeline's stack depth.
    viaIR: true,
    evmVersion: 'cancun',
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
  },
};
const solcOut = JSON.parse(solc.compile(JSON.stringify(solcInput)));
const solcVersion = solc.version();
let warningCount = 0;
for (const e of solcOut.errors ?? []) {
  if (e.severity === 'error') {
    console.error(e.formattedMessage);
    process.exit(1);
  }
  warningCount++;
  console.warn('WARNING:', e.formattedMessage);
}
console.log(`solc ${solcVersion} | optimizer runs ${OPTIMIZER_RUNS} | warnings: ${warningCount}`);

const artifact = solcOut.contracts['SealRegistry.sol'].SealRegistry;
const abi = artifact.abi;
const bytecode = '0x' + artifact.evm.bytecode.object;
const iface = new ethers.Interface(abi);

// --------------------------------------------------------------------- VM
const common = createCustomCommon({ chainId: Number(CHAIN_ID) }, Mainnet, { hardfork: HARDFORK });
const vm = await createVM({ common });

const wallets = {};
for (const [name, pk] of Object.entries(KEYS)) {
  const priv = hexToBytes(pk);
  const address = createAddressFromPrivateKey(priv);
  wallets[name] = { priv, address, addressHex: ethers.getAddress(address.toString()), nonce: 0n };
  await vm.stateManager.putAccount(address, createAccount({ nonce: 0n, balance: 10n ** 21n }));
}

let blockNumber = 1n;
let timestamp = 1750000000n;

function nextBlock() {
  blockNumber += 1n;
  timestamp += 12n;
  return createBlock(
    { header: { number: blockNumber, timestamp, gasLimit: 30_000_000n, baseFeePerGas: 7n } },
    { common },
  );
}

async function sendTx(from, { to, data, value = 0n }) {
  const w = wallets[from];
  const tx = createLegacyTx(
    {
      nonce: w.nonce,
      gasPrice: 1_000_000_000n,
      gasLimit: 5_000_000n,
      to, // undefined => contract creation
      value,
      data,
    },
    { common },
  ).sign(w.priv);
  const block = nextBlock();
  const result = await runTx(vm, { tx, block, skipBlockGasLimitValidation: true });
  w.nonce += 1n;
  const reverted = result.execResult.exceptionError !== undefined;
  let revertError = null;
  if (reverted && result.execResult.returnValue?.length >= 4) {
    try {
      revertError = iface.parseError(bytesToHex(result.execResult.returnValue))?.name ?? null;
    } catch {
      revertError = null;
    }
  }
  return {
    result,
    reverted,
    revertError,
    gas: result.totalGasSpent,
    timestamp,
    logs: (result.execResult.logs ?? []).map(([addr, topics, logData]) => ({
      address: ethers.getAddress(bytesToHex(addr)),
      topics: topics.map((t) => bytesToHex(t)),
      data: bytesToHex(logData),
    })),
  };
}

async function callView(to, fn, args) {
  const res = await vm.evm.runCall({
    to,
    data: hexToBytes(iface.encodeFunctionData(fn, args)),
    gasLimit: 10_000_000n,
  });
  if (res.execResult.exceptionError) {
    throw new Error(`view ${fn} reverted: ${res.execResult.exceptionError.error}`);
  }
  return iface.decodeFunctionResult(fn, bytesToHex(res.execResult.returnValue));
}

// ----------------------------------------------------------- record helpers
const coder = ethers.AbiCoder.defaultAbiCoder();
const RECORD_TYPES = [
  'uint16', 'bytes32', 'uint8', 'bytes32', 'bytes32', 'string', 'uint8',
  'address', 'string', 'bytes32', 'uint64', 'uint16', 'address',
];

function fieldsFor(documentId) {
  return { ...D2.fields, documentId };
}

function encodeRecord(fields, signer) {
  return coder.encode(RECORD_TYPES, [
    fields.exactHashMethodId, fields.exactHash, fields.sealMode,
    fields.fingerprintRoot, fields.chunkRoot, fields.cid, fields.cidProfile,
    fields.issuer, fields.documentId, fields.prevGuid, fields.declaredTime,
    fields.sigMethodId, signer,
  ]);
}

function clientDigest(fields, verifyingContract) {
  return clientCommitmentDigest(
    { chainId: CHAIN_ID, verifyingContract, registryId: REGISTRY_ID },
    fields,
  );
}

// Builds (fields, record, digest, sig) for a signer key against the deployed registry.
function makeSeal(documentId, signerName, registryAddr) {
  const w = wallets[signerName];
  const fields = fieldsFor(documentId);
  const record = encodeRecord(fields, w.addressHex);
  const digest = clientDigest(fields, registryAddr);
  const sig = signCommitment(KEYS[signerName], digest);
  return { fields, record, digest, sig, signer: w.addressHex };
}

// --------------------------------------------------------------- assertions
const results = [];
function assert(num, label, cond, detail = '') {
  const ok = Boolean(cond);
  results.push({ num, label, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  [${String(num).padStart(2)}] ${label}${detail ? ` — ${detail}` : ''}`);
  return ok;
}

const gas = {};

// ------------------------------------------------------------------- deploy
console.log('\n== deploy ==');
const deployData = bytecode + coder.encode(['uint256', 'bytes32'], [SEAL_FEE, REGISTRY_ID]).slice(2);
const deployRes = await sendTx('deployer', { data: deployData });
if (deployRes.reverted || !deployRes.result.createdAddress) {
  console.error('deployment failed:', deployRes.result.execResult.exceptionError);
  process.exit(1);
}
const registry = deployRes.result.createdAddress;
const registryAddr = ethers.getAddress(registry.toString());
gas.deploy = Number(deployRes.gas);
console.log(`SealRegistry @ ${registryAddr} | hardfork ${HARDFORK} | chainId ${CHAIN_ID}`);
const [feeOnChain] = await callView(registry, 'sealFee', []);
if (feeOnChain !== SEAL_FEE) throw new Error('sealFee immutable mismatch');

console.log('\n== assertions ==');

// [1] commitmentDigest conformance (contract == ethers.TypedDataEncoder, deployed address).
const s1 = makeSeal(D2.fields.documentId, 'signer1', registryAddr); // exact D2 fields
const [digestOnChain] = await callView(registry, 'commitmentDigest', [s1.record]);
assert(1, 'commitmentDigest conformance (contract == client encoder)',
  digestOnChain === s1.digest, digestOnChain);

// [2] guidOf conformance.
const guid1 = clientGuidOf(s1.digest, s1.signer);
const [guidOnChain] = await callView(registry, 'guidOf', [s1.record]);
assert(2, 'guidOf conformance (contract == client guid)', guidOnChain === guid1, guidOnChain);

// [3] submitSeal accepts a valid seal and emits Sealed(guid, signer, exactHash, sealRecord).
const r3 = await sendTx('deployer', {
  to: registry,
  data: iface.encodeFunctionData('submitSeal', [s1.record, s1.sig.serialized]),
  value: SEAL_FEE,
});
gas.submitSeal = Number(r3.gas);
const sealedLog3 = r3.logs.map((l) => iface.parseLog(l)).find((p) => p?.name === 'Sealed');
const anchorTime1 = r3.timestamp;
assert(3, 'submitSeal accepts valid seal + Sealed event fields',
  !r3.reverted && sealedLog3 &&
  sealedLog3.args.guid === guid1 &&
  sealedLog3.args.signer === s1.signer &&
  sealedLog3.args.exactHash === D2.fields.exactHash &&
  sealedLog3.args.sealRecord === s1.record);

// [4] duplicate guid rejected.
const r4 = await sendTx('deployer', {
  to: registry,
  data: iface.encodeFunctionData('submitSeal', [s1.record, s1.sig.serialized]),
  value: SEAL_FEE,
});
assert(4, 'duplicate-guid resubmission reverts',
  r4.reverted && r4.revertError === 'DuplicateGuid', r4.revertError ?? '');

// [5] multi-attestation: second signer seals the SAME fields/exactHash, distinct guid.
const s2 = makeSeal(D2.fields.documentId, 'signer2', registryAddr); // same 12 fields, signer2
const guid2 = clientGuidOf(s2.digest, s2.signer);
const r5 = await sendTx('signer2', {
  to: registry,
  data: iface.encodeFunctionData('submitSeal', [s2.record, s2.sig.serialized]),
  value: SEAL_FEE,
});
const sealedLog5 = r5.logs.map((l) => iface.parseLog(l)).find((p) => p?.name === 'Sealed');
assert(5, 'multi-attestation: same exactHash, second signer, distinct guid',
  !r5.reverted && sealedLog5 &&
  s2.digest === s1.digest && // same commitment
  sealedLog5.args.guid === guid2 && guid2 !== guid1 &&
  sealedLog5.args.exactHash === D2.fields.exactHash);

// [6] fee enforcement.
const s6 = makeSeal('DOC-FEE', 'signer1', registryAddr);
const r6 = await sendTx('signer1', {
  to: registry,
  data: iface.encodeFunctionData('submitSeal', [s6.record, s6.sig.serialized]),
  value: SEAL_FEE - 1n,
});
assert(6, 'submitSeal below sealFee reverts',
  r6.reverted && r6.revertError === 'FeeTooLow', r6.revertError ?? '');

// [7] cross-registry replay rejected: the published vector signature was produced
// against verifyingContract 0x…0001 — recovery against THIS registry's digest
// yields a different address than the claimed signer.
const r7 = await sendTx('deployer', {
  to: registry,
  data: iface.encodeFunctionData('submitSeal', [s1.record, D2.signature.serialized]),
  value: SEAL_FEE,
});
assert(7, 'cross-registry replay (vector sig, other verifyingContract) reverts',
  r7.reverted && r7.revertError === 'SignerMismatch', r7.revertError ?? '');

// [8] high-s malleability rejected: s' = n - s, v flipped. The same record with
// the original low-s signature must succeed afterwards (isolates the cause).
const s8 = makeSeal('DOC-MALLEABLE', 'signer1', registryAddr);
const sHigh = ethers.toBeHex(SECP256K1_N - BigInt(s8.sig.s), 32);
const vFlipped = s8.sig.v === 27 ? '1c' : '1b';
const malleated = ethers.concat([s8.sig.r, sHigh]) + vFlipped;
const r8a = await sendTx('deployer', {
  to: registry,
  data: iface.encodeFunctionData('submitSeal', [s8.record, malleated]),
  value: SEAL_FEE,
});
const r8b = await sendTx('deployer', {
  to: registry,
  data: iface.encodeFunctionData('submitSeal', [s8.record, s8.sig.serialized]),
  value: SEAL_FEE,
});
assert(8, 'high-s twin rejected; original low-s accepted',
  r8a.reverted && r8a.revertError === 'MalleableSignature' && !r8b.reverted,
  r8a.revertError ?? '');

// [9] zero r / zero s rejected.
const s9 = makeSeal('DOC-ZERO', 'signer1', registryAddr);
const zeroR = ethers.concat([ZERO32, s9.sig.s]) + (s9.sig.v === 27 ? '1b' : '1c');
const zeroS = ethers.concat([s9.sig.r, ZERO32]) + (s9.sig.v === 27 ? '1b' : '1c');
const r9a = await sendTx('deployer', {
  to: registry,
  data: iface.encodeFunctionData('submitSeal', [s9.record, zeroR]),
  value: SEAL_FEE,
});
const r9b = await sendTx('deployer', {
  to: registry,
  data: iface.encodeFunctionData('submitSeal', [s9.record, zeroS]),
  value: SEAL_FEE,
});
assert(9, 'zero-r and zero-s signatures revert',
  r9a.reverted && r9a.revertError === 'ZeroSignatureValue' &&
  r9b.reverted && r9b.revertError === 'ZeroSignatureValue',
  `${r9a.revertError}/${r9b.revertError}`);

// [10] commit then reveal: precedence recorded from COMMIT time.
const s10 = makeSeal('DOC-COMMIT', 'signer1', registryAddr);
const guid10 = clientGuidOf(s10.digest, s10.signer);
const nonce10 = ethers.hexlify(ethers.randomBytes(32));
const c10 = ethers.keccak256(ethers.concat([s10.digest, nonce10]));
const rCommit = await sendTx('signer1', {
  to: registry,
  data: iface.encodeFunctionData('commit', [c10]),
  value: SEAL_FEE,
});
gas.commit = Number(rCommit.gas);
const commitTs = rCommit.timestamp;
// burn a block so reveal happens strictly later than commit
await sendTx('deployer', { to: registry, data: iface.encodeFunctionData('checkpoint', [0n, ZERO32, ZERO32, 0]) });
const rReveal = await sendTx('signer1', {
  to: registry,
  data: iface.encodeFunctionData('reveal', [s10.record, s10.sig.serialized, nonce10]),
});
gas.reveal = Number(rReveal.gas);
const sealedLog10 = rReveal.logs.map((l) => iface.parseLog(l)).find((p) => p?.name === 'Sealed');
const st10 = await callView(registry, 'seals', [guid10]);
assert(10, 'commit→reveal succeeds; anchorTime == commit time (not reveal time)',
  !rCommit.reverted && !rReveal.reverted && sealedLog10?.args.guid === guid10 &&
  st10[0] === commitTs && rReveal.timestamp > commitTs,
  `anchorTime=${st10[0]} commit=${commitTs} reveal=${rReveal.timestamp}`);

// [11] reveal without prior commit reverts.
const s11 = makeSeal('DOC-NOCOMMIT', 'signer1', registryAddr);
const r11 = await sendTx('signer1', {
  to: registry,
  data: iface.encodeFunctionData('reveal', [s11.record, s11.sig.serialized, ethers.hexlify(ethers.randomBytes(32))]),
});
assert(11, 'reveal without prior commit reverts',
  r11.reverted && r11.revertError === 'UnknownCommit', r11.revertError ?? '');

// [12] revoke by the signer, code 2 (KEY_COMPROMISE): packed (code, t) stored,
// existence record untouched, Revoked emitted.
const revokeT = 1760000000n;
const r12 = await sendTx('signer1', {
  to: registry,
  data: iface.encodeFunctionData('revoke', [guid1, 2, revokeT, s1.record, s1.sig.serialized]),
});
gas.revoke = Number(r12.gas);
const revokedLog = r12.logs.map((l) => iface.parseLog(l)).find((p) => p?.name === 'Revoked');
const st12 = await callView(registry, 'seals', [guid1]);
assert(12, 'revoke(code=2 KEY_COMPROMISE) by signer: packed state + intact anchor + Revoked event',
  !r12.reverted && revokedLog &&
  revokedLog.args.guid === guid1 && revokedLog.args.code === 2n &&
  revokedLog.args.t === revokeT && revokedLog.args.evidence === ZERO32 &&
  st12[0] === anchorTime1 && st12[1] === 2n && st12[2] === revokeT,
  `anchorTime=${st12[0]} code=${st12[1]} t=${st12[2]}`);

// [13] revoke by a non-signer reverts (signer1 attacks signer2's seal with signer2's record/sig).
const r13 = await sendTx('signer1', {
  to: registry,
  data: iface.encodeFunctionData('revoke', [guid2, 1, revokeT, s2.record, s2.sig.serialized]),
});
assert(13, 'revoke by non-signer reverts',
  r13.reverted && r13.revertError === 'NotSealSigner', r13.revertError ?? '');

// [14] re-revocation reverts (monotone).
const r14 = await sendTx('signer1', {
  to: registry,
  data: iface.encodeFunctionData('revoke', [guid1, 3, revokeT + 1n, s1.record, s1.sig.serialized]),
});
assert(14, 're-revocation reverts (monotone status)',
  r14.reverted && r14.revertError === 'AlreadyRevoked', r14.revertError ?? '');

// [15] checkpoint + renew from an unprivileged account, event fields exact.
const idxRoot = ethers.keccak256(ethers.toUtf8Bytes('index-root-epoch-7'));
const logRange = ethers.keccak256(ethers.toUtf8Bytes('log-range-epoch-7'));
const renewRoot = ethers.keccak256(ethers.toUtf8Bytes('renewal-root-epoch-7'));
const r15a = await sendTx('signer2', {
  to: registry,
  data: iface.encodeFunctionData('checkpoint', [7n, idxRoot, logRange, 1]),
});
gas.checkpoint = Number(r15a.gas);
const r15b = await sendTx('signer2', {
  to: registry,
  data: iface.encodeFunctionData('renew', [7n, renewRoot, 2, 3]),
});
gas.renew = Number(r15b.gas);
const cpLog = r15a.logs.map((l) => iface.parseLog(l)).find((p) => p?.name === 'IndexCheckpoint');
const rnLog = r15b.logs.map((l) => iface.parseLog(l)).find((p) => p?.name === 'RenewalRoot');
assert(15, 'checkpoint + renew permissionless, events carry exact fields',
  !r15a.reverted && !r15b.reverted && cpLog && rnLog &&
  cpLog.args.epoch === 7n && cpLog.args.indexRoot === idxRoot &&
  cpLog.args.logRangeCommitment === logRange && cpLog.args.indexRuleId === 1n &&
  rnLog.args.epoch === 7n && rnLog.args.root === renewRoot &&
  rnLog.args.hashMethodId === 2n && rnLog.args.sigMethodId === 3n);

// ------------------------------------------------------- gas: submitBatch
const rBatch = await sendTx('deployer', {
  to: registry,
  data: iface.encodeFunctionData('submitBatch', [ethers.keccak256(ethers.toUtf8Bytes('batch-root')), 1000]),
  value: SEAL_FEE,
});
if (rBatch.reverted) throw new Error('submitBatch gas probe reverted');
gas.submitBatch = Number(rBatch.gas);

// -------------------------------------------------------------------- report
const passed = results.filter((r) => r.ok).length;
console.log(`\n== result: ${passed}/15 ==`);
console.log('\n== gas ==');
for (const [k, v] of Object.entries(gas)) console.log(`${k.padEnd(12)} ${v}`);

writeFileSync(
  join(__dir, 'gas_report.json'),
  JSON.stringify(
    {
      hardfork: HARDFORK,
      chainId: Number(CHAIN_ID),
      solcVersion,
      optimizerRuns: OPTIMIZER_RUNS,
      solcWarnings: warningCount,
      gas,
      assertions: `${passed}/15`,
    },
    null,
    2,
  ) + '\n',
);
console.log('\ngas_report.json written');
process.exit(passed === 15 ? 0 : 1);
