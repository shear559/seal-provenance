// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISealRegistry — SEAL whitepaper §4.15 registry interface.
/// @notice No verifyDocument() on-chain. No owner, no upgrade proxy, no admin functions.
interface ISealRegistry {
    event Sealed(bytes32 indexed guid, address indexed signer, bytes32 indexed exactHash, bytes sealRecord);
    event Revoked(bytes32 indexed guid, uint8 code, uint64 t, bytes32 evidence);
    event IndexCheckpoint(uint64 indexed epoch, bytes32 indexRoot, bytes32 logRangeCommitment, uint16 indexRuleId);
    event RenewalRoot(uint64 indexed epoch, bytes32 root, uint16 hashMethodId, uint16 sigMethodId);

    function submitSeal(bytes calldata sealRecord, bytes calldata sig) external payable;
    function submitBatch(bytes32 merkleRoot, uint32 count) external payable;
    function commit(bytes32 c) external payable;
    function reveal(bytes calldata sealRecord, bytes calldata sig, bytes32 nonce) external;
    function revoke(bytes32 guid, uint8 code, uint64 t, bytes calldata sealRecord, bytes calldata sig) external;
    function checkpoint(uint64 epoch, bytes32 indexRoot, bytes32 logRange, uint16 ruleId) external; // permissionless
    function renew(uint64 epoch, bytes32 root, uint16 h, uint16 s) external;
    function sealFee() external view returns (uint256);
}

/// @title SealRegistry — SEAL v1 reference registry (whitepaper §4.15).
///
/// @notice Append-only, admin-free existence/attestation registry. The contract
/// reproduces the NORMATIVE client encoding (`seal_encoding.mjs`, Appendix D)
/// byte-for-byte:
///
///   commitmentDigest = EIP-712 hashTypedDataV4 over the Seal712 struct with
///   domain {name:"SEAL", version:"1", chainId, verifyingContract: address(this),
///   salt: registryId}, where the dynamic fields `cid` and `documentId` are
///   hashed with keccak256(bytes(.)) per EIP-712.
///
///   guid = keccak256(abi.encodePacked(commitmentDigest, signer))
///   (signer as raw 20 address bytes — identical to the client `guidOf`).
///
/// @dev sealRecord wire encoding (NORMATIVE for this registry):
///   abi.encode of the 12 Seal712 fields IN §4.3 ORDER, plus the claimed signer
///   address appended as a 13th top-level abi field (flat tuple, NOT a nested
///   struct):
///
///     abi.encode(
///       uint16  exactHashMethodId,
///       bytes32 exactHash,
///       uint8   sealMode,
///       bytes32 fingerprintRoot,
///       bytes32 chunkRoot,
///       string  cid,
///       uint8   cidProfile,
///       address issuer,
///       string  documentId,
///       bytes32 prevGuid,
///       uint64  declaredTime,
///       uint16  sigMethodId,
///       address signer            // 13th field: claimed signer for guid + recovery
///     )
///
/// Design invariants (paper §4.15 / Appendix B.3):
///  - NO admin: `sealFee` and `registryId` are immutable constructor parameters;
///    every function is permissionless. Fees accrue to the contract balance and
///    are unrecoverable by construction (economically burned anti-spam bond).
///  - The registry stores EXISTENCE (anchorTime) and REVOCATION (code, t) only;
///    verification of documents happens entirely off-chain.
///  - checkpoint()/renew() are claims-not-authority: anyone may emit them; their
///    weight comes from off-chain verification of the committed roots.
contract SealRegistry is ISealRegistry {
    // ---------------------------------------------------------------- errors
    error FeeTooLow();
    error BadRecordLength();
    error BadSignatureLength();
    error ZeroSignatureValue();
    error MalleableSignature();
    error BadSignatureV();
    error InvalidSignature();
    error SignerMismatch();
    error DuplicateGuid();
    error UnknownCommit();
    error CommitExists();
    error GuidRecordMismatch();
    error UnknownGuid();
    error AlreadyRevoked();
    error BadRevocationCode();
    error NotSealSigner();

    // ---------------------------------------------------------------- events
    /// @notice Extension to §4.15 (documented deviation): dedicated batch-anchor
    /// event instead of overloading Sealed with guid=merkleRoot.
    event BatchSealed(bytes32 indexed merkleRoot, uint32 count);

    // ------------------------------------------------------------- constants
    /// @dev keccak256 of the normative Seal712 type string (seal_encoding.mjs).
    bytes32 internal constant SEAL_TYPEHASH = keccak256(
        "Seal712(uint16 exactHashMethodId,bytes32 exactHash,uint8 sealMode,"
        "bytes32 fingerprintRoot,bytes32 chunkRoot,string cid,uint8 cidProfile,"
        "address issuer,string documentId,bytes32 prevGuid,uint64 declaredTime,"
        "uint16 sigMethodId)"
    );

    /// @dev EIP-712 domain typehash; field order is the EIP-712 canonical order
    /// used by ethers.TypedDataEncoder for {name,version,chainId,verifyingContract,salt}.
    bytes32 internal constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
    );

    bytes32 internal constant NAME_HASH = keccak256("SEAL");
    bytes32 internal constant VERSION_HASH = keccak256("1");

    /// @dev secp256k1 group order / 2 — signatures with s above this value are
    /// rejected as malleable (EIP-2 / Appendix F of the Yellow Paper).
    uint256 internal constant SECP256K1N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    // ------------------------------------------------------------- immutable
    /// @notice Anti-spam fee in wei, fixed forever at deployment. No admin can change it.
    uint256 private immutable _sealFee;

    /// @notice Registry instance identifier, carried in the EIP-712 domain `salt`.
    bytes32 public immutable registryId;

    // --------------------------------------------------------------- storage
    /// @dev Packed seal state: one storage slot (64 + 8 + 64 = 136 bits).
    struct SealState {
        uint64 anchorTime;     // 0 = does not exist; else timestamp of anchor (commit time for reveals)
        uint8 revocationCode;  // 0 = active; 1..4 per §4.15 revocation codes
        uint64 revokedAt;      // caller-declared revocation effective time t
    }

    /// @notice guid => packed existence/revocation record.
    mapping(bytes32 => SealState) public seals;

    /// @notice commitment hash c => commit timestamp (precedence anchor for reveal).
    mapping(bytes32 => uint64) public commitTime;

    // ----------------------------------------------------------- constructor
    constructor(uint256 sealFee_, bytes32 registryId_) {
        _sealFee = sealFee_;
        registryId = registryId_;
    }

    // ----------------------------------------------------------------- views
    /// @inheritdoc ISealRegistry
    function sealFee() external view returns (uint256) {
        return _sealFee;
    }

    /// @notice EIP-712 digest of a sealRecord against THIS registry
    /// (domain: name "SEAL", version "1", block.chainid, address(this), salt registryId).
    /// Byte-for-byte equal to the client encoder for the same fields.
    function commitmentDigest(bytes calldata sealRecord) public view returns (bytes32) {
        (Seal712 memory f, ) = _decode(sealRecord);
        return _hashTypedData(_structHash(f));
    }

    /// @notice guid = keccak256(commitmentDigest || signer), signer as raw 20 bytes.
    function guidOf(bytes calldata sealRecord) public view returns (bytes32) {
        (Seal712 memory f, address signer) = _decode(sealRecord);
        return keccak256(abi.encodePacked(_hashTypedData(_structHash(f)), signer));
    }

    // ------------------------------------------------------------ submission
    /// @inheritdoc ISealRegistry
    function submitSeal(bytes calldata sealRecord, bytes calldata sig) external payable {
        if (msg.value < _sealFee) revert FeeTooLow();
        _seal(sealRecord, sig, uint64(block.timestamp));
    }

    /// @inheritdoc ISealRegistry
    /// @dev Anchors a Merkle root covering `count` off-chain seal records for one
    /// flat fee (batch amortization, §4.15). Emits BatchSealed (documented
    /// extension); inclusion proofs are verified off-chain.
    function submitBatch(bytes32 merkleRoot, uint32 count) external payable {
        if (msg.value < _sealFee) revert FeeTooLow();
        emit BatchSealed(merkleRoot, count);
    }

    /// @inheritdoc ISealRegistry
    /// @dev Front-running shield: c = keccak256(abi.encodePacked(commitmentDigest, nonce)).
    /// The fee is paid here; reveal() is free. Re-commits of the same c are
    /// rejected so the recorded precedence time is monotone.
    function commit(bytes32 c) external payable {
        if (msg.value < _sealFee) revert FeeTooLow();
        if (commitTime[c] != 0) revert CommitExists();
        commitTime[c] = uint64(block.timestamp);
    }

    /// @inheritdoc ISealRegistry
    /// @dev Precedence = commit time: the stored anchorTime is the commit
    /// timestamp, not the reveal timestamp.
    function reveal(bytes calldata sealRecord, bytes calldata sig, bytes32 nonce) external {
        bytes32 c = keccak256(abi.encodePacked(commitmentDigest(sealRecord), nonce));
        uint64 committedAt = commitTime[c];
        if (committedAt == 0) revert UnknownCommit();
        _seal(sealRecord, sig, committedAt);
    }

    // ------------------------------------------------------------ revocation
    /// @inheritdoc ISealRegistry
    /// @dev Control proof: the caller must re-present the (sealRecord, sig) pair;
    /// the recovered signer must equal both the record's claimed signer and
    /// msg.sender. The existence record (anchorTime) is never touched —
    /// revocation is a monotone status overlay. The Revoked `evidence` field is
    /// emitted as bytes32(0): the §4.15 function signature carries no evidence
    /// parameter (documented deviation; reserved for future profiles).
    function revoke(bytes32 guid, uint8 code, uint64 t, bytes calldata sealRecord, bytes calldata sig)
        external
    {
        if (code == 0 || code > 4) revert BadRevocationCode();

        (Seal712 memory f, address claimedSigner) = _decode(sealRecord);
        bytes32 digest = _hashTypedData(_structHash(f));
        address recovered = _recover(digest, sig);
        if (recovered != claimedSigner) revert SignerMismatch();
        if (msg.sender != recovered) revert NotSealSigner();
        if (keccak256(abi.encodePacked(digest, claimedSigner)) != guid) revert GuidRecordMismatch();

        SealState storage st = seals[guid];
        if (st.anchorTime == 0) revert UnknownGuid();
        if (st.revocationCode != 0) revert AlreadyRevoked();

        st.revocationCode = code;
        st.revokedAt = t;
        emit Revoked(guid, code, t, bytes32(0));
    }

    // --------------------------------------------------- permissionless roots
    /// @inheritdoc ISealRegistry
    /// @dev Claims-not-authority (Appendix B.3): anyone may checkpoint; consumers
    /// verify the committed index root off-chain. Nothing is stored.
    function checkpoint(uint64 epoch, bytes32 indexRoot, bytes32 logRange, uint16 ruleId) external {
        emit IndexCheckpoint(epoch, indexRoot, logRange, ruleId);
    }

    /// @inheritdoc ISealRegistry
    /// @dev Claims-not-authority: permissionless renewal-root anchor for hash/sig
    /// algorithm migration (h = hashMethodId, s = sigMethodId). Nothing is stored.
    function renew(uint64 epoch, bytes32 root, uint16 h, uint16 s) external {
        emit RenewalRoot(epoch, root, h, s);
    }

    // -------------------------------------------------------------- internals
    /// @dev The 12 Seal712 commitment fields, §4.3 order.
    struct Seal712 {
        uint16 exactHashMethodId;
        bytes32 exactHash;
        uint8 sealMode;
        bytes32 fingerprintRoot;
        bytes32 chunkRoot;
        string cid;
        uint8 cidProfile;
        address issuer;
        string documentId;
        bytes32 prevGuid;
        uint64 declaredTime;
        uint16 sigMethodId;
    }

    /// @dev Shared seal path for submitSeal (anchor = now) and reveal (anchor = commit time).
    function _seal(bytes calldata sealRecord, bytes calldata sig, uint64 anchorTime) internal {
        (Seal712 memory f, address claimedSigner) = _decode(sealRecord);
        bytes32 digest = _hashTypedData(_structHash(f));
        address recovered = _recover(digest, sig);
        if (recovered != claimedSigner) revert SignerMismatch();

        bytes32 guid = keccak256(abi.encodePacked(digest, claimedSigner));
        if (seals[guid].anchorTime != 0) revert DuplicateGuid();

        seals[guid] = SealState({anchorTime: anchorTime, revocationCode: 0, revokedAt: 0});
        emit Sealed(guid, claimedSigner, f.exactHash, sealRecord);
    }

    /// @dev Decodes the 13-field flat sealRecord (12 Seal712 fields + signer).
    function _decode(bytes calldata sealRecord)
        internal
        pure
        returns (Seal712 memory f, address signer)
    {
        if (sealRecord.length < 13 * 32) revert BadRecordLength();
        (
            f.exactHashMethodId,
            f.exactHash,
            f.sealMode,
            f.fingerprintRoot,
            f.chunkRoot,
            f.cid,
            f.cidProfile,
            f.issuer,
            f.documentId,
            f.prevGuid,
            f.declaredTime,
            f.sigMethodId,
            signer
        ) = abi.decode(
            sealRecord,
            (uint16, bytes32, uint8, bytes32, bytes32, string, uint8, address, string, bytes32, uint64, uint16, address)
        );
    }

    /// @dev EIP-712 hashStruct: dynamic fields (cid, documentId) enter as keccak256(bytes(.)).
    function _structHash(Seal712 memory f) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                SEAL_TYPEHASH,
                f.exactHashMethodId,
                f.exactHash,
                f.sealMode,
                f.fingerprintRoot,
                f.chunkRoot,
                keccak256(bytes(f.cid)),
                f.cidProfile,
                f.issuer,
                keccak256(bytes(f.documentId)),
                f.prevGuid,
                f.declaredTime,
                f.sigMethodId
            )
        );
    }

    /// @dev hashTypedDataV4. The domain separator is recomputed from
    /// block.chainid on every call so that post-fork replicas produce diverging
    /// digests (cross-chain replay resistance is structural, not cached).
    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this), registryId)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /// @dev Strict 65-byte r||s||v ECDSA recovery:
    ///  - r != 0, s != 0 (explicit zero-value rejection),
    ///  - s <= secp256k1n/2 (EIP-2 low-s rule; high-s twins are malleable),
    ///  - v in {27, 28},
    ///  - ecrecover result != address(0).
    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert BadSignatureLength();
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (r == bytes32(0) || s == bytes32(0)) revert ZeroSignatureValue();
        if (uint256(s) > SECP256K1N_HALF) revert MalleableSignature();
        if (v != 27 && v != 28) revert BadSignatureV();
        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0)) revert InvalidSignature();
        return recovered;
    }
}
