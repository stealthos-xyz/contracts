# StealthOS Vanta contracts

Public Solidity source for the Vanta privacy protocol on DogeOS Chikyu (chain ID 6281971).

## Source revisions

The default branch contains the contract source snapshot associated with signed partner SDK **0.4.65**. All 18 Solidity SHA-256 hashes listed in its signed publication were matched to this snapshot. Additional verifier and dependency sources are retained from the same revision. All exported Solidity, tests and original build configuration match their original Git blob IDs.

- [Contract sources](contracts/src/)
- [Selected Solidity tests](contracts/test/)
- [Source manifest](SOURCE_MANIFEST.json)
- [Signed publication and deployment contract lock](deployments/dogeos-chikyu/sdk-0.4.65-publication.json)
- [Audit report and findings](audits/README.md)
- [Vanta partner SDK](https://github.com/stealthos-xyz/vanta-sdk)

The original Solidity filenames, SPDX headers and source paths are preserved, including historical naming in required dependencies. Unrelated standalone experiments are not included. Audit remediation candidates are distinct from deployed contracts.

## Build locally

Install Foundry. The original Foundry compiler configuration and lockfile are included. From the repository root:

```sh
cd contracts
forge install foundry-rs/forge-std@7117c90c8cf6c68e5acce4f09a6b24715cea4de6 --no-git
forge install OpenZeppelin/openzeppelin-contracts@fcbae5394ae8ad52d8e580a3477db99814b9d565 --no-git
forge build
forge test
```

The exported subset has not been independently compiled or tested in this repository. Included tests may use local fixtures and do not establish live proof soundness or deployment readiness. Original deployment tooling and operational services are not included.

Verify the exact source SHA-256 pins in the manifest and compare actual network bytecode with the signed deployment lock before relying on a deployed contract. Final ceremony, final keys and deployment validation are separate release requirements.

## Security and licensing

See [SECURITY.md](SECURITY.md). Source files retain their original SPDX identifiers and notices. Dependencies have their own licenses. The audit is first-party, AI-assisted engineering assurance, not third-party certification or mainnet custody approval.
