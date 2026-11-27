# Phase 2: TRON compiler and upstream precompile results

2026-11-27. Research only. Status: **compiler compatibility PASS; primitive correctness PASS; direct-port timing gate FAIL on measured host**. No public network, RPC, signer, deployment, ceremony, release or production code change.

## Reproduction and provenance

- Branch: vanta-tron; run source 08ebc985df2d498cfac40717ed41dcf8e103dcb6.
- Workflow: https://github.com/stealthos-xyz/contracts/actions/runs/46043571994
- Compiler job: https://github.com/stealthos-xyz/contracts/actions/runs/46043571994/job/140657116918
- Precompile job: https://github.com/stealthos-xyz/contracts/actions/runs/46043571994/job/140657117089
- Compiler: official TVM fork 0.8.26+commit.733b4d28.Linux.g++; SHA-256 98a0df6518346d07f13ec151f64bed48f4df9dd01fbfd81018f9485a374f8edd.
- Runtime: java-tron GreatVoyage-v4.8.2.4 FullNode-x64.jar; SHA-256 709423e8d14ccba391daeef7aa78bb5f41a1b69559cc867346beacbd6aae39c9. Jar used as a classpath library, not started as a node. No debug mode.
- Runner: ubuntu-24.04, x86_64, 4 vCPU, AMD EPYC 9V45, OpenJDK 1.8.0_514, JVM -Xmx2g.
- Source manifest: verified all six inputs against recorded git blob IDs. Used existing 0.8.26, viaIR, Cancun, optimizer runs=1. No Solidity source changed.
- Both jobs concluded success, meaning instrumentation ran; this does not mean timing qualification passed.

## Compile results

| Contract | Runtime bytes | SHA-256 |
|---|---:|---|
| VantaFamilyGate0CcGroth16PreAudit | 3932 | d60b8714707a3fa5e63025b535709408b5aab8d1e17c492e93762586937f8d7e |
| VantaCaulkPlusGate1Research | 9688 | 0243fe5fef0f9dd8ed299052668cc0f8ca2261ad520fd6c68257009ff5f18575 |
| VantaCpLinkPairingResearch | 1131 | acca1eab7eea28e8a1f889f9bd902bafa84cc6911512da8bc346b21338f8e764 |
| VantaFamilyFullBundleVerifierPreAudit | 3313 | 5243db6a859893e7cea91bcb88039196612ee20b26187a37576b42a12f7837e0 |
| VantaFamilyPartnerKzgFeeVerifierPreAudit | 7397 | 9e281c94ac5ae8197f94351c14b261085be785f9fde8d7b4f1e55d23c0f525ec |

These hashes are compiler output objects, not deployed code or release artifacts. Immutable constructor arguments are not resolved in this compile-only check. The pool, settlement and full verifier closure beyond these files have not been compiled.

## Runtime results

The actual pinned precompiles returned expected results on all 15 primitive fixtures, including positive/negative arithmetic, nontrivial scalar, non-identity pairing returning zero, 2/3/4-pair identities, malformed length, invalid coordinate and swapped G2 limbs. An independently generated valid-curve wrong-subgroup vector remains outstanding. These are not genuine Vanta proofs.

The schedule executes 18 additions, 17 scalar multiplications, 6 pairing calls (15 pairs). Upstream runtime Energy functions match 884700 Istanbul / 2489000 legacy precompile-only Energy. Shared deadlines checked by harness and the pinned pairing implementation.

| Synthetic schedule | Budget (ms) | N | Timeouts | p50 ms | p95 ms | Max ms |
|---|---:|---:|---:|---:|---:|---:|
| Gate0 | 5000 | 20 | 0 | 49.207 | 50.304 | 100.079 |
| Gate1 | 5000 | 20 | 0 | 98.149 | 100.836 | 105.952 |
| CP_link | 5000 | 20 | 0 | 38.005 | 39.249 | 39.307 |
| Combined diagnostic | 5000 | 100 | 0 | 186.972 | 196.332 | 221.116 |
| Combined strict | 80 | 100 | 100 | 81.692 | 84.591 | 85.831 |

First cold bundle timed out at 1868.789 ms (one observation only, not a cold-run distribution). Strict timing rows measure time to completion or timeout; they are not successful verification latency. All 100 strict runs failed the deadline. Diagnostic 5s runs are measurements, not acceptance or timeout bypass on any live network. Wall clock on a single shared CI host is not a consensus-wide timing guarantee. Synthetic workloads reuse generator points and long scalars; actual proof key/proof distributions, VM bytecode execution, storage, fee paths and settlement remain unmeasured. The current documented Mainnet CPU limit is 80 ms; live Shasta/Nile parameter snapshots are still unverified.

## Disposition and next research

NO-GO for unchanged Vanta as a deployment candidate based on this screening; not a proof that every TRON host will fail or that Vanta cannot be adapted. No deployment/activation permitted. Defer full TVM settlement until a credible fast verifier candidate exists.

1. Reproduce with genuine disposable STREAM_BOUND4 8x5/32x5 proof inputs from privacy-protocol/scripts/family-qualification/ (evm-replay.mjs and disposable qualification tooling). Keep DogeOS keys and runtime untouched. Pin a TRON research family/genesis only when explicitly approved; no user secrets, no custody keys. Use isolated TVM bytecode execution with real deadline and representative host configurations.
2. Evaluate pairing-equation batching in Gate1 only as a separate research design: its first three equations share G20/G21, and its fourth shares G20 but has W. A reviewed Fiat-Shamir randomized combination could reduce repeated pairing operations, but requires full transcript/domain/key binding and adversarial soundness analysis; extra G1 operations and remaining gates/fees may still exceed budget. Never simply multiply unchecked equations or weaken any verifier.
3. Evaluate recursive compression/aggregate proof or TRON-side native BN254 acceleration with the TRON team if measured batching is insufficient. Preserve atomic settlement and independent validation. No custom consensus changes or changes to Vanta's production circuits authorized by this research.
4. Only reconsider full fee/KZG/pool settlement, both arities, recovery and ceremony when the proposed measured p95 has margin below the real CPU limit and zero invalid acceptance/timeouts. No production modifications in this phase.

Sources: https://github.com/tronprotocol/java-tron/releases/tag/GreatVoyage-v4.8.2.4 ; https://github.com/tronprotocol/solidity/releases/tag/tv_0.8.26 ; https://developers.tron.network/docs/node-operations-issues ; https://github.com/tronprotocol/java-tron/issues/6374 .
