# A trustless anchor for document provenance

**A signature proves *who*. It does not prove *when* — and in the generative-AI era, *when* is the claim that decides whether a document is evidence or a fabrication.**

This repository holds a 72-page position and architecture paper on sealing digital files so their provenance survives adversaries, transcoding, hash breaks and decades of time — together with the complete reference package, so every number in it can be reproduced on your own machine in about a minute.

**[Read the paper (PDF, 72 pp) →](paper/SEAL-whitepaper-v2.0.pdf)**

---

## Why a signature is not enough

Sign a contract with a private key and you have bound the bytes to a keypair. You have not established when the signature happened. The timestamp inside the file is a field the signer chose; the timestamp on the filesystem is a field anyone can choose. Backdating is a text edit.

The standards world solved the *what* and the *who*. [C2PA](https://c2pa.org) and JPEG Trust (ISO/IEC 21617-1:2025) specify hard binding to a hash and soft binding to a perceptual fingerprint that survives a re-encode, and they specify it well — this paper takes no credit for any of it and says so explicitly.

What those standards leave centralized is the *trust root*: a certificate authority, a trust list, a repository someone operates. A provenance claim is then only as durable as the institution vouching for it, and only as available as that institution's uptime in ten years' time.

That gap is what the paper addresses, and it makes **exactly three claims** — no more:

| Claim | What is proven | Where |
| --- | --- | --- |
| **A trustless anchor with interval timestamp semantics** | Anti-backdating holds even against the system's own sequencer, because the checkpoint hierarchy terminates in Bitcoin via OpenTimestamps. The bound is always cited at L1/Bitcoin level, never at L2 alone. | Theorem 4 (§6.1) |
| **A verifiable soft-binding resolution registry** | The decentralized analogue of C2PA's Soft Binding Resolution API, rebuilt in the Certificate-Transparency pattern: an on-chain append-only log as sole source of truth, a versioned deterministic index rule, permissionless off-chain indexers, anchored index roots, and proof-carrying results. Positive matches are trust-minimized. | Theorem 5 (§6.1) |
| **Longevity engineering with confidential sealing** | Salted commitments make the public record leak nothing about the sealed document, and epochal renewal carries a seal across a hash-function break — provided the data itself is re-sealed before deprecation, not merely the digest. | §4, §6 |

## What it deliberately does not claim

The most load-bearing section of any provenance paper is the one that says what it cannot do. This one:

- **It does not claim hard/soft binding** of what, who and when. That is C2PA and JPEG Trust, and an earlier draft of this work claimed it as novel before an adversarial review established it was already an ISO standard. The claim was withdrawn.
- **Attestation is not ownership.** A valid seal over stolen content is a valid seal. The system proves a keyholder asserted something at a time; it does not adjudicate who was entitled to.
- **Completeness of resolution is priced, not proven.** Positive matches carry proofs. *Absence* of a match rests on a k-of-n indexer quorum assumption, which is stated and bounded rather than hidden.
- **The evaluation plan is committed, not executed.** §9 specifies a falsifiable adversarial evaluation on a public chain. It has not been run. The measurements in this repo are conformance and cost figures from the environments named beside them, and they are not a substitute for it.

## Reproduce every number in the paper

The reference package is not pseudocode. It is the encoder the paper is normative about, a registry contract, a conformance suite and the benchmarks — all runnable:

```bash
cd reference && npm install
node seal_demo.mjs        # Appendix D.1-D.6: public + confidential seals, tamper evidence,
                          #   cross-chain replay rejection, the 100k-candidate dictionary experiment
node vectors_v2.mjs       # Appendix D.7: the 17-vector conformance suite, incl. real ML-DSA-65
node run_evm_tests.mjs    # compiles SealRegistry.sol and runs it in-EVM  -> expect "15/15"
node bench.mjs            # Appendix E: client-side microbenchmarks + Merkle batching
node measure_bundle.mjs   # verification-bundle size from real vector data
```

Verified end to end on 2026-08-15, Node 26, macOS x86-64:

```
run_evm_tests   == result: 15/15 ==
                deploy 895,102 · submitSeal 63,197 · commit 44,361 · reveal 69,316
                revoke 42,017 · checkpoint 24,712 · renew 24,396 · submitBatch 23,516
vectors_v2      17/17 vectors, all assertions passed
seal_demo       dictionary attack over 100,000 candidates:
                  unsalted -> target identified at i = 54,321 (0.87 s)
                  salted   -> 0 matches, trial commitments cannot be formed without the salt
bench           batching amortizes the anchor: 32 bytes/seal at N=1 -> 0.0032 at N=10,000
measure_bundle  offline verification bundle: 4.4 kB ECDSA-only, 10.9 kB with ML-DSA-65
```

`seal_encoding.mjs` is the normative part: the EIP-712 domain, the `Seal712` type string and `guid = keccak256(commitment ‖ signer)`. Any independent implementation has to reproduce its output bit for bit, which is the point of publishing it.

`SealRegistry.sol` has no owner, no upgrade proxy and no admin function; the fee is an immutable constructor parameter. That is a deliberate constraint, not an omission — an admin key is a trust root, and the whole argument is about not having one.

## Where this came from, and what it cost to be wrong

Two earlier versions of this paper were substantially wrong, and the corrections are the reason to trust the third:

**v0.1** claimed the exact-hash plus content-hash binding as its novelty. An adversarial review established it is precisely C2PA Durable Content Credentials — already standardized. Novelty as submitted: 22/100. Desk reject.

**v0.2** re-scoped to "a decentralized resolution registry is the novel part." Also wrong: C2PA's Soft Binding Resolution spec already contemplates a DLT registry. What it specifies, though, is an *honest-resolver* key→URI pointer store — so v0.3 narrowed the claim to what actually remained: a resolver threat model, `RESOLVE` returning inclusion **or non-membership** proofs against an on-chain-anchored root, and a soundness theorem.

**v1.0** claimed executed artifacts "shipped alongside" the paper. They did not exist. Every one of them was then built and run for real, which is what this repository contains — and which is why the results above are quoted from a run rather than from the manuscript.

A later 87-agent review produced 66 confirmed findings, two of which were genuine cryptographic defects rather than prose problems: digest-only epochal renewal does not survive a hash break, and the confidential chunk tree was a dictionary oracle until its leaves were salted per chunk. Both are fixed in the current text.

## Status and naming

This is a **position and architecture paper**, version 2.0, June 2026. It is not a deployed system and does not present itself as one.

**The name is provisional.** "SEAL" collides with established projects — most notably Microsoft SEAL, the homomorphic-encryption library — and will be re-evaluated before any formal release. Nothing in the architecture depends on it.

A phase-1a subset of this design — hard-binding commitment, EIP-712 attestation, browser-side signing and verification — ships in production inside [Click PDF](https://click-pdf.vercel.app), where a document can be edited and sealed in the same session.

## Citing and rights

If you cite this work, GitHub's **Cite this repository** button renders the entry from `CITATION.cff`.

The paper and the reference package are published so the results can be independently checked. All rights are reserved; publication here is not a licence to redistribute or reuse. If you want to build on it, open an issue and ask — the answer is likely yes.

Corrections are genuinely welcome. Three versions of this paper were wrong in ways that outside review caught, and that pattern is the only reason the current one is worth reading.
