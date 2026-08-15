// SEAL v1 normative commitment encoding (whitepaper §4.3 + Appendix D).
// This module IS the normative reference: any independent implementation
// MUST reproduce its outputs bit-for-bit on the same inputs.
import { ethers } from 'ethers';

// EIP-712 domain. registryId is carried in the standard `salt` field.
export const SEAL_DOMAIN_NAME = 'SEAL';
export const SEAL_DOMAIN_VERSION = '1';

// Normative type string (field order is the §4.3 commitment order):
// Seal712(uint16 exactHashMethodId,bytes32 exactHash,uint8 sealMode,
//   bytes32 fingerprintRoot,bytes32 chunkRoot,string cid,uint8 cidProfile,
//   address issuer,string documentId,bytes32 prevGuid,uint64 declaredTime,
//   uint16 sigMethodId)
export const SEAL_TYPES = {
  Seal712: [
    { name: 'exactHashMethodId', type: 'uint16' },
    { name: 'exactHash', type: 'bytes32' },
    { name: 'sealMode', type: 'uint8' },
    { name: 'fingerprintRoot', type: 'bytes32' },
    { name: 'chunkRoot', type: 'bytes32' },
    { name: 'cid', type: 'string' },
    { name: 'cidProfile', type: 'uint8' },
    { name: 'issuer', type: 'address' },
    { name: 'documentId', type: 'string' },
    { name: 'prevGuid', type: 'bytes32' },
    { name: 'declaredTime', type: 'uint64' },
    { name: 'sigMethodId', type: 'uint16' },
  ],
};

export const SEAL_TYPE_STRING =
  'Seal712(uint16 exactHashMethodId,bytes32 exactHash,uint8 sealMode,' +
  'bytes32 fingerprintRoot,bytes32 chunkRoot,string cid,uint8 cidProfile,' +
  'address issuer,string documentId,bytes32 prevGuid,uint64 declaredTime,' +
  'uint16 sigMethodId)';

export function sealDomain({ chainId, verifyingContract, registryId }) {
  return {
    name: SEAL_DOMAIN_NAME,
    version: SEAL_DOMAIN_VERSION,
    chainId,
    verifyingContract,
    salt: registryId,
  };
}

// PUBLIC mode: exactHash = keccak256(bytes)
// CONFIDENTIAL mode: exactHash = keccak256(salt32 || bytes)
export function exactHashOf(bytes, salt32 = null) {
  return salt32
    ? ethers.keccak256(ethers.concat([salt32, bytes]))
    : ethers.keccak256(bytes);
}

export function commitmentDigest(domainParams, sealFields) {
  return ethers.TypedDataEncoder.hash(
    sealDomain(domainParams), SEAL_TYPES, sealFields);
}

// guid = keccak256(commitment || signer)  — signer as raw 20 address bytes
export function guidOf(commitment, signer) {
  return ethers.keccak256(ethers.concat([commitment, ethers.getAddress(signer)]));
}

export function signCommitment(privateKey, digest) {
  const sig = new ethers.SigningKey(privateKey).sign(digest); // RFC6979, low-s
  return { r: sig.r, s: sig.s, v: sig.v, serialized: sig.serialized };
}

export function recoverSigner(digest, sig) {
  return ethers.recoverAddress(digest, sig);
}
