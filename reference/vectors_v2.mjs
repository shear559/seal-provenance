// SEAL v2 conformance-vector suite — whitepaper Appendix D.7.
// Generates SEAL_test_vectors_v2.json: EXACTLY 17 deterministic vectors
// (G-01..G-17). All commitments are produced by the NORMATIVE encoder in
// ./seal_encoding.mjs — nothing is re-implemented here.
// Run: node vectors_v2.mjs
import { writeFileSync } from 'node:fs';
import { ethers } from 'ethers';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  SEAL_TYPE_STRING, exactHashOf, commitmentDigest, guidOf,
  signCommitment, recoverSigner,
} from './seal_encoding.mjs';

// ---------------- fixed parameters (demo profile, deterministic) ----------
const KEYS = {
  // Hardhat/Anvil well-known accounts #1, #2, #3 — never use in production.
  1: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
  2: '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
  3: '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6',
};
const ADDR = Object.fromEntries(
  Object.entries(KEYS).map(([k, v]) => [k, new ethers.Wallet(v).address]));

const REGISTRY_ID = ethers.keccak256(ethers.toUtf8Bytes('SEAL/registry/demo/1'));
const DOMAIN = {
  chainId: 11155111, // Sepolia
  verifyingContract: '0x0000000000000000000000000000000000000001',
  registryId: REGISTRY_ID,
};
const Z32 = ethers.ZeroHash;
const Z20 = ethers.ZeroAddress;
const BASE_TIME = 1750000000n;

const baseFields = {
  exactHashMethodId: 1, // keccak256
  exactHash: Z32,
  sealMode: 0,          // 0 = PUBLIC, 1 = CONFIDENTIAL
  fingerprintRoot: Z32,
  chunkRoot: Z32,
  cid: '',
  cidProfile: 0,
  issuer: Z20,
  documentId: '',
  prevGuid: Z32,
  declaredTime: BASE_TIME,
  sigMethodId: 1,       // ECDSA-secp256k1 low-s
};

// ---------------- test files ---------------------------------------------
const HEBREW = 'חותם דיגיטלי — אבטחה קריפטוגרפית מקצועית.';
const FILE_A = new Uint8Array(0);                       // empty
const FILE_B = new Uint8Array([0x00]);                  // single zero byte
const FILE_C = ethers.toUtf8Bytes(HEBREW);              // Hebrew UTF-8
const FILE_D = new Uint8Array(102400);                  // 100 kB deterministic
for (let i = 0; i < FILE_D.length; i++) FILE_D[i] = (i * 31 + 7) & 0xff;

// Fixed distinct CONFIDENTIAL-mode salts, one per file.
const SALT = {};
for (const tag of ['a', 'b', 'c', 'd'])
  SALT[tag] = ethers.keccak256(ethers.toUtf8Bytes(`SEAL/v2/salt/${tag}`));

// Byte flip rule used by every negative check in this suite: XOR with 0xFF.
const FLIP_RULE = 'flipped byte = original byte XOR 0xFF';
function flipByteHex(hex, index /* 0-based byte index; -1 = last */) {
  const b = ethers.getBytes(hex);
  const i = index < 0 ? b.length + index : index;
  b[i] ^= 0xff;
  return ethers.hexlify(b);
}
function flipByteBytes(bytes, index) {
  const b = new Uint8Array(bytes);
  const i = index < 0 ? b.length + index : index;
  b[i] ^= 0xff;
  return b;
}

// ---------------- Merkle tree (fixed-order, keccak256) --------------------
// Tree rule (normative for this suite):
//   leaf_i = keccak256(item_i); leaves kept in item order (NO sorted pairs).
//   parent = keccak256(left || right) with fixed left-right concatenation.
//   An odd node at any level is promoted unchanged to the next level.
const TREE_RULE =
  'leaf_i = keccak256(item_i) in item order; parent = keccak256(left || right) ' +
  'with fixed left-right order (no sorted pairs); an odd node at any level is ' +
  'promoted unchanged to the next level';

function merkleRoot(leaves) {
  if (leaves.length === 0) throw new Error('no leaves');
  let level = leaves.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i + 1 < level.length; i += 2)
      next.push(ethers.keccak256(ethers.concat([level[i], level[i + 1]])));
    if (level.length % 2 === 1) next.push(level[level.length - 1]);
    level = next;
  }
  return level[0];
}

// Inclusion path: array of { sibling, side } where side is the SIBLING's
// position relative to the current node at that level.
function merkleProof(leaves, index) {
  const path = [];
  let level = leaves.slice();
  let idx = index;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i + 1 < level.length; i += 2)
      next.push(ethers.keccak256(ethers.concat([level[i], level[i + 1]])));
    const odd = level.length % 2 === 1;
    if (odd) next.push(level[level.length - 1]);
    if (odd && idx === level.length - 1) {
      idx = next.length - 1; // promoted unchanged — no path element
    } else if (idx % 2 === 0) {
      path.push({ sibling: level[idx + 1], side: 'right' });
      idx = Math.floor(idx / 2);
    } else {
      path.push({ sibling: level[idx - 1], side: 'left' });
      idx = Math.floor(idx / 2);
    }
    level = next;
  }
  return path;
}

function merkleVerify(leaf, path, root) {
  let cur = leaf;
  for (const { sibling, side } of path) {
    cur = side === 'right'
      ? ethers.keccak256(ethers.concat([cur, sibling]))
      : ethers.keccak256(ethers.concat([sibling, cur]));
  }
  return cur === root;
}

// ---------------- seal helper ---------------------------------------------
function makeSeal({ signerNo, bytes, mode, salt = null, documentId,
                    declaredTime = BASE_TIME, chunkRoot = Z32 }) {
  const exactHash = mode === 'CONFIDENTIAL'
    ? exactHashOf(bytes, salt)
    : exactHashOf(bytes);
  const fields = {
    ...baseFields,
    exactHash,
    sealMode: mode === 'CONFIDENTIAL' ? 1 : 0,
    chunkRoot,
    documentId,
    declaredTime,
  };
  const digest = commitmentDigest(DOMAIN, fields);
  const sig = signCommitment(KEYS[signerNo], digest);
  const signer = ADDR[signerNo];
  const recovered = recoverSigner(digest, sig.serialized);
  if (recovered !== signer) throw new Error(`recover mismatch for ${documentId}`);
  const guid = guidOf(digest, signer);
  return { fields, exactHash, digest, sig, signer, signerNo, guid };
}

function fieldsJson(fields) {
  return { ...fields, declaredTime: fields.declaredTime.toString() };
}

// ---------------- generate ------------------------------------------------
const vectors = [];
const assert = (cond, msg) => { if (!cond) throw new Error(`ASSERT: ${msg}`); };

const FILES = [
  { tag: 'a', name: 'empty file (0 bytes)', bytes: FILE_A,
    content: { hex: '0x', utf8: null } },
  { tag: 'b', name: 'single zero byte 0x00', bytes: FILE_B,
    content: { hex: '0x00', utf8: null } },
  { tag: 'c', name: 'Hebrew UTF-8 text', bytes: FILE_C,
    content: { hex: ethers.hexlify(FILE_C), utf8: HEBREW } },
  { tag: 'd', name: '100 kB deterministic binary', bytes: FILE_D,
    content: { hex: null, utf8: null,
      rule: 'byte[i] = (i*31 + 7) & 0xFF for i in 0..102399 (length 102400)',
      keccak256: ethers.keccak256(FILE_D) } },
];

// ---- G-01..G-08: file edge cases × mode ----------------------------------
let n = 0;
for (const f of FILES) {
  for (const mode of ['PUBLIC', 'CONFIDENTIAL']) {
    n++;
    const id = `G-${String(n).padStart(2, '0')}`;
    const salt = mode === 'CONFIDENTIAL' ? SALT[f.tag] : null;
    const seal = makeSeal({
      signerNo: 1, bytes: f.bytes, mode, salt,
      documentId: `V2-${f.tag.toUpperCase()}-${mode === 'PUBLIC' ? 'PUB' : 'CONF'}`,
    });
    // Opening check.
    let openingCheck;
    if (mode === 'CONFIDENTIAL') {
      const wrongSalt = flipByteHex(salt, -1);
      const okOpen = exactHashOf(f.bytes, salt) === seal.exactHash;
      const badOpen = exactHashOf(f.bytes, wrongSalt) === seal.exactHash;
      assert(okOpen, `${id}: correct-salt opening must match`);
      assert(!badOpen, `${id}: wrong-salt opening must NOT match`);
      openingCheck = {
        correctSalt: salt, correctSaltMatches: true,
        wrongSalt, wrongSaltRule: 'last byte of salt XOR 0xFF',
        wrongSaltMatches: false,
      };
    } else {
      const okOpen = exactHashOf(f.bytes) === seal.exactHash;
      assert(okOpen, `${id}: public recompute must match`);
      openingCheck = { recomputeMatches: true };
    }
    vectors.push({
      id, label: `${f.name} — ${mode} mode`,
      file: f.content, fileLength: f.bytes.length,
      mode, salt, openingCheck,
      fields: fieldsJson(seal.fields),
      exactHash: seal.exactHash, commitmentDigest: seal.digest,
      signature: seal.sig, signer: seal.signer, signerAccount: 1,
      guid: seal.guid,
    });
  }
}

// ---- G-09..G-11: multi-attestation (signers #1,#2,#3 over same bytes) ----
const multi = [];
for (const signerNo of [1, 2, 3]) {
  n++;
  const id = `G-${String(n).padStart(2, '0')}`;
  const seal = makeSeal({
    signerNo, bytes: FILE_C, mode: 'PUBLIC', documentId: 'V2-MULTI',
  });
  multi.push(seal);
  vectors.push({
    id, label: `multi-attestation — Hebrew text sealed by signer #${signerNo}`,
    file: { hex: ethers.hexlify(FILE_C), utf8: HEBREW },
    mode: 'PUBLIC', salt: null,
    fields: fieldsJson(seal.fields),
    exactHash: seal.exactHash, commitmentDigest: seal.digest,
    signature: seal.sig, signer: seal.signer, signerAccount: signerNo,
    guid: seal.guid,
  });
}
assert(multi[0].exactHash === multi[1].exactHash &&
       multi[1].exactHash === multi[2].exactHash,
       'G-09..G-11 exactHash must be identical');
assert(new Set(multi.map(s => s.guid)).size === 3,
       'G-09..G-11 guids must be pairwise distinct');

// ---- G-12 / G-13: declaredTime boundaries ---------------------------------
for (const [t, name] of [[0n, 'declaredTime = 0'],
                         [18446744073709551615n, 'declaredTime = 2^64-1']]) {
  n++;
  const id = `G-${String(n).padStart(2, '0')}`;
  const seal = makeSeal({
    signerNo: 1, bytes: FILE_C, mode: 'PUBLIC',
    documentId: 'V2-TIME', declaredTime: t,
  });
  vectors.push({
    id, label: `boundary — ${name}`,
    file: { hex: ethers.hexlify(FILE_C), utf8: HEBREW },
    mode: 'PUBLIC', salt: null,
    fields: fieldsJson(seal.fields),
    exactHash: seal.exactHash, commitmentDigest: seal.digest,
    signature: seal.sig, signer: seal.signer, signerAccount: 1,
    guid: seal.guid,
  });
}

// ---- G-14: chunk-tree fragment proof --------------------------------------
{
  n++;
  const id = `G-${String(n).padStart(2, '0')}`;
  const CHUNK = 25600; // 25 kB
  const chunks = [0, 1, 2, 3].map(i => FILE_D.slice(i * CHUNK, (i + 1) * CHUNK));
  const leaves = chunks.map(c => ethers.keccak256(c));
  const chunkRoot = merkleRoot(leaves);
  const IDX = 2; // chunk index 2 (0-based; the third 25 kB chunk)
  const path = merkleProof(leaves, IDX);
  const genuineOk = merkleVerify(ethers.keccak256(chunks[IDX]), path, chunkRoot);
  const forged = flipByteBytes(chunks[IDX], 0); // first byte flipped (XOR 0xFF)
  const forgedOk = merkleVerify(ethers.keccak256(forged), path, chunkRoot);
  assert(genuineOk, 'G-14 genuine chunk must verify');
  assert(!forgedOk, 'G-14 forged chunk must NOT verify');
  const seal = makeSeal({
    signerNo: 1, bytes: FILE_D, mode: 'PUBLIC',
    documentId: 'V2-CHUNKS', chunkRoot,
  });
  vectors.push({
    id, label: 'chunk-tree fragment proof — 100 kB file, 4 × 25 kB chunks, proof for chunk 2',
    file: { rule: 'byte[i] = (i*31 + 7) & 0xFF for i in 0..102399 (length 102400)',
            keccak256: ethers.keccak256(FILE_D) },
    chunking: { chunkBytes: CHUNK, chunkCount: 4, treeRule: TREE_RULE },
    chunkLeaves: leaves, chunkRoot,
    proof: {
      chunkIndex: IDX, indexBase: '0-based',
      chunkLeaf: leaves[IDX], path,
      genuineChunkVerifies: true,
      forgedChunkRule: 'first byte of chunk 2 XOR 0xFF',
      forgedChunkLeaf: ethers.keccak256(forged),
      forgedChunkVerifies: false,
    },
    mode: 'PUBLIC', salt: null,
    fields: fieldsJson(seal.fields),
    exactHash: seal.exactHash, commitmentDigest: seal.digest,
    signature: seal.sig, signer: seal.signer, signerAccount: 1,
    guid: seal.guid,
  });
}

// ---- G-15: batch inclusion proof over guids of G-01..G-08 -----------------
{
  n++;
  const id = `G-${String(n).padStart(2, '0')}`;
  const guids = vectors.slice(0, 8).map(v => v.guid);
  // Batch leaves are the guids themselves (already 32-byte digests).
  const root = merkleRoot(guids);
  const IDX = 2; // vector 3 → G-03 → leaf index 2 (0-based)
  const path = merkleProof(guids, IDX);
  const ok = merkleVerify(guids[IDX], path, root);
  assert(ok, 'G-15 batch inclusion must verify');
  vectors.push({
    id, label: 'batch inclusion proof — Merkle root over guids of G-01..G-08, path for G-03',
    treeRule: TREE_RULE,
    leafNote: 'leaves are the 32-byte guids of G-01..G-08 in vector order (used directly, not re-hashed)',
    leaves: guids, batchRoot: root,
    proof: {
      vectorId: 'G-03', leafIndex: IDX, indexBase: '0-based',
      leaf: guids[IDX], path, verifies: true,
    },
  });
}

// ---- G-16: cross-chain replay matrix --------------------------------------
{
  n++;
  const id = `G-${String(n).padStart(2, '0')}`;
  const v9 = multi[0]; // G-09: signer #1 over Hebrew text
  const rows = [];
  for (const chainId of [11155111, 1, 137]) {
    const digest = commitmentDigest({ ...DOMAIN, chainId }, v9.fields);
    const recovered = recoverSigner(digest, v9.sig.serialized);
    const matches = recovered === v9.signer;
    rows.push({ chainId, commitmentDigest: digest, recovered,
                matchesSigner: matches });
  }
  assert(rows[0].matchesSigner, 'G-16 signed chain must recover signer');
  assert(!rows[1].matchesSigner && !rows[2].matchesSigner,
         'G-16 foreign chains must NOT recover signer');
  vectors.push({
    id, label: 'cross-chain replay matrix — G-09 signature replayed on chainId 1 and 137',
    sourceVector: 'G-09', signer: v9.signer, signature: v9.sig,
    matrix: rows,
    expect: 'recovered == signer only on the signed chainId (11155111); replay on 1/137 yields a different address, attestation fails',
  });
}

// ---- G-17: ML-DSA-65 dual-signature ---------------------------------------
{
  n++;
  const id = `G-${String(n).padStart(2, '0')}`;
  const seedHex = ethers.keccak256(ethers.toUtf8Bytes('SEAL/v2/mldsa/seed'));
  const seed = ethers.getBytes(seedHex); // 32 bytes
  const { publicKey, secretKey } = ml_dsa65.keygen(seed);
  const msg = ethers.getBytes(multi[0].digest); // G-09 commitmentDigest bytes
  // extraEntropy:false → deterministic (non-hedged) ML-DSA signing.
  const sig = ml_dsa65.sign(msg, secretKey, { extraEntropy: false });
  const okGood = ml_dsa65.verify(sig, msg, publicKey);
  const tampered = flipByteBytes(msg, -1); // last byte XOR 0xFF
  const okBad = ml_dsa65.verify(sig, tampered, publicKey);
  assert(okGood, 'G-17 genuine ML-DSA verify must pass');
  assert(!okBad, 'G-17 tampered ML-DSA verify must fail');
  assert(publicKey.length === 1952, `G-17 pk length ${publicKey.length} != 1952`);
  assert(sig.length === 3309, `G-17 sig length ${sig.length} != 3309`);
  const hex = (u8) => Buffer.from(u8).toString('hex');
  vectors.push({
    id, label: 'ML-DSA-65 dual-signature over G-09 commitmentDigest (deterministic, extraEntropy=false)',
    algorithm: 'ML-DSA-65 (FIPS 204), @noble/post-quantum',
    keygenSeed: seedHex,
    seedNote: 'seed = keccak256("SEAL/v2/mldsa/seed") used as 32 raw bytes',
    message: multi[0].digest, sourceVector: 'G-09',
    publicKeyLength: publicKey.length, signatureLength: sig.length,
    publicKeyFirst16Hex: hex(publicKey).slice(0, 16),
    signatureFirst16Hex: hex(sig).slice(0, 16),
    verify: true,
    tamperedMessageRule: 'last byte of digest XOR 0xFF',
    tamperedMessage: ethers.hexlify(tampered),
    tamperedVerify: false,
  });
}

// ---------------- finalize -------------------------------------------------
assert(vectors.length === 17, `expected 17 vectors, got ${vectors.length}`);
assert(new Set(vectors.map(v => v.id)).size === 17, 'vector ids must be unique');

const out = {
  schema: 'SEAL/conformance/v2',
  generator: 'vectors_v2.mjs (normative encoder: seal_encoding.mjs)',
  typeString: SEAL_TYPE_STRING,
  domain: { name: 'SEAL', version: '1', ...DOMAIN },
  signers: {
    1: { address: ADDR[1], note: 'Hardhat/Anvil well-known account #1' },
    2: { address: ADDR[2], note: 'Hardhat/Anvil well-known account #2' },
    3: { address: ADDR[3], note: 'Hardhat/Anvil well-known account #3' },
  },
  rules: { tree: TREE_RULE, byteFlip: FLIP_RULE },
  vectorCount: vectors.length,
  vectors,
};

writeFileSync(new URL('./SEAL_test_vectors_v2.json', import.meta.url),
              JSON.stringify(out, null, 2));

for (const v of vectors) console.log(`${v.id}  ${v.label}`);
console.log(`\nAll assertions passed — wrote SEAL_test_vectors_v2.json (${vectors.length} vectors)`);
