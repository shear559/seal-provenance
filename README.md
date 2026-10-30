# Document Provenance — Paper and Reference Implementation

A position and architecture paper on anchoring document-provenance claims, accompanied by executable reference code for its conformance and cost measurements.

[Read the paper — version 2.0, 63 pages](paper/SEAL-whitepaper-v2.0.pdf) · [Reference guide](reference/README.md)

## Research question

A digital signature binds a statement to a key. Establishing when that statement existed, resolving it after a file changes representation, and preserving verifiability over time require additional mechanisms and explicit trust assumptions.

The paper studies three parts of that problem:

| Area | Proposed mechanism |
| --- | --- |
| Time anchoring | A checkpoint hierarchy ending in Bitcoin through OpenTimestamps, with interval-based timestamp semantics |
| Resolution | An append-only registry, deterministic indexing rules and proof-carrying positive matches |
| Longevity and confidentiality | Salted commitments and renewal that re-seals the underlying data before a cryptographic primitive is deprecated |

The paper distinguishes these proposals from established hard- and soft-binding work. Novelty claims and security arguments should be evaluated against the exact definitions and assumptions in the manuscript.

## Scope and limitations

This is a research artifact, not a deployed provenance service.

- Attestation is not ownership, authorship or truth. A keyholder can seal content they were not entitled to use.
- Positive resolution results and absence claims have different guarantees; the latter depend on the stated indexer-quorum assumptions.
- Renewal requires the underlying data, not merely an old digest.
- The public-chain adversarial evaluation specified in the paper has not been executed.
- The local conformance and cost measurements do not replace that evaluation.

“SEAL” is a provisional name and is unrelated to Microsoft SEAL.

## Reproduce the reference checks

The recorded reference run used Node.js 26 on macOS x86-64. See [reference/README.md](reference/README.md) for dependencies, outputs and environment details.

```sh
cd reference
npm install
node seal_demo.mjs
node vectors_v2.mjs
node run_evm_tests.mjs
node bench.mjs
node measure_bundle.mjs
```

Run these scripts directly: the package's default `npm test` is not the conformance suite.

| Artifact | Purpose |
| --- | --- |
| `seal_encoding.mjs` | Normative encoding and identifiers |
| `SealRegistry.sol` | Reference registry contract |
| `vectors_v2.mjs` | Encoding and cryptographic conformance vectors |
| `run_evm_tests.mjs` | In-EVM contract checks and gas output |
| `bench.mjs`, `measure_bundle.mjs` | Local timing, batching and bundle-size measurements |

Generated results depend on the runtime and configuration. Preserve those conditions when comparing measurements.

## Related implementation

A bounded browser-side subset was implemented in the former Click PDF application. Its PDF and SEAL workflows now continue in [Sculio](https://editor-beta-ruby.vercel.app/#pdf); that subset is not the full research architecture.

## Citation and rights

Use [CITATION.cff](CITATION.cff) or GitHub's **Cite this repository** action.

The paper and original reference work are published for inspection and verification with all rights reserved; publication is not a general redistribution or reuse grant. Obtain the author's permission before reuse, and retain third-party terms.

By [Ariel Shemesh](https://github.com/shear559).
