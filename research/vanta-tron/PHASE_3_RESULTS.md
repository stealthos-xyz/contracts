# Phase 3: actual TVM, staged receipts and genuine native proofs

Date: 2026-11-27. Branch: `vanta-tron`.

## Decision

The research implementation is running and reproducible. The original verifier
arithmetic accepts the genuine native fixtures in the released TVM, and the
receipt prototype passes its constructed-fixture state tests. **The current
released runtime and six-stage prototype have not qualified genuine workloads
against the 80 ms screening budget.**

The decisive genuine-proof replay passed all 168 expected correctness outcomes,
but both full note bundles timed out in 30/30 strict samples. Their diagnostic
medians were about 440 ms. Native Gate0 timed out in every strict sample, while
individual Caulk equations and CP_link also showed timeout tails. The earlier
constructed receipt sequences completed 30/30 for both widths on a different
host. Those results must not be substituted for genuine receipt qualification.

The pinned optimized arithmetic candidate is promising: its completed eight-pair
microbenchmark was 13.30 times faster at the median than released arithmetic on
the same host. It differs in deadline behavior and is not a drop-in TVM
replacement. No optimized full-transaction result or network adoption is claimed.

Sources: [public implementation and CI](https://github.com/stealthos-xyz/contracts/actions/runs/46047977427),
[genuine native replay](https://github.com/stealthos-xyz/privacy-protocol/actions/runs/46048533798),
[staged raw evidence](results/staged-tvm.json),
[arithmetic raw evidence](results/bn128-comparison.json).

## What was implemented

### A no-funds staged verifier

`VantaCaulkPlusStagedResearch.sol` evaluates one of the original four Caulk
equations, preserving the original challenge derivation and source-pinned
arithmetic. It supports arities 1, 8 and 32.

`VantaStagedReceiptResearch.sol` supports six-input note widths 8 and 32. Its six
obligations are Gate0, the four Caulk equations, and CP_link. It pins verifier
addresses and code hashes, the accepted configuration, arity and family tag.
Receipt sessions bind the complete proof bundle, action, checkpoint, replay key,
expiry, chain and adapter. D and E come from the same bound bundle. Duplicate
submission is idempotent; receipts from different sessions cannot be combined.

Finalization requires all six receipts, a fresh exact-session state approval,
and unused action/replay keys. It marks the session consumed and emits one
research event. Expiry cleanup preserves consumed tombstones. The included
state checker is an owner-controlled fixture snapshot model. It supplies no
production authority, fee policy, full spent-nullifier set or token settlement.

### Actual released TVM execution

`TronVmProbe.java` executes compiled constructor and runtime bytecode through the
released VM, including nested calls, storage, return data, reverts and CPU
deadlines. Each transaction uses an isolated storage overlay that commits only
after success. The complete staged sequence receives a fresh deadline for each
transaction; a timeout aborts the sequence and cannot create a successful receipt.

Independent bytecode canaries write storage and then revert or time out. Both
prove that the overlay saw the write while the parent value remained unchanged.
A separate loop canary confirms that CPU timeouts are active. Debug, constant
call, SolidityNode and testing-suite deadline bypasses are disabled. Unsupported
repository operations fail closed.

### Reproducible genuine native fixtures

The protocol research workflow generates fresh disposable proofs using the
existing Rust ccGroth16, Caulk+ and CP_link implementations. Its nine cases are
normal8, normal32, combined deposit, combined withdrawal 8/32, combined private
send 8/32, and enhanced 8/32. Only normalized public verifier material is retained
in the private protocol repository; private engine source and witnesses are not
copied into this repository.

The existing qualification family and chain ID 6281971 are preserved on an
isolated local chain. The enhanced fee parser's domain guard remains enforced.
These are genuine existing-family native proofs, not activated TRON-family or
STREAM_BOUND4 browser proofs.

## Evidence and reproducibility

| Work | Source revision | CI evidence |
| --- | --- | --- |
| Public TVM, receipt and comparison implementation | `1601a5fd7ec51e06211bcfef7bfe6b2336712036` | [46047977427](https://github.com/stealthos-xyz/contracts/actions/runs/46047977427) |
| Native generation, all nine cases | `ef7dd4defb331c483a8f5e870c3379d8bad03c7a` | [46047333613](https://github.com/stealthos-xyz/privacy-protocol/actions/runs/46047333613) |
| Native TVM replay, pinned to the public implementation above | `3905831af5f4e0f933842a5c1b4b5dd63cacfc6d` | [46048533798](https://github.com/stealthos-xyz/privacy-protocol/actions/runs/46048533798) |

All three runs completed successfully. A green benchmark job means the expected
correctness outcomes and measurement instrumentation passed. Strict timeouts are
recorded evidence, not successful execution and not automatically a CI failure.

The official compiler is `tv_0.8.26`, version
`0.8.26+commit.733b4d28.Linux.g++`, with via-IR, Cancun and optimizer runs 1.
Its SHA-256 is
`98a0df6518346d07f13ec151f64bed48f4df9dd01fbfd81018f9485a374f8edd`.
The runtime is Java-Tron `GreatVoyage-v4.8.2.4`; `FullNode.jar` SHA-256 is
`709423e8d14ccba391daeef7aa78bb5f41a1b69559cc867346beacbd6aae39c9`.
Original verifier sources are checked against `SOURCE_MANIFEST.json`; no
`contracts/src` source was changed by this phase.

| Measurement | CI host | Allocated logical CPUs | Java |
| --- | --- | ---: | --- |
| Constructed bytecode and receipt sequences | AMD EPYC 9V74 | 4 | 1.8.0_514 |
| Released versus candidate direct arithmetic | Intel Xeon Platinum 8573C | 4 | 1.8.0_514 |
| Genuine native bytecode replay | AMD EPYC 7763 | 2 | 1.8.0_514 |

All used Linux `7.0.0-1020-azure`. Different hosts and workloads prevent attributing
the constructed/native timing difference solely to proof contents. Do not apply
the Intel arithmetic speedup to AMD full-transaction timings. Within-comparison
arithmetic samples alternate execution order in one process.

TVM timing uses 10 warmups and 30 measured repetitions per case and budget.
The arithmetic comparison uses 20 warmups per implementation and 30 measured
repetitions. A diagnostic 5,000 ms budget measures completed work; a separate
strict 80 ms budget screens deadline behavior. Reported diagnostic percentiles
below include completed work only. Timeout elapsed time is time until failure,
not total verification latency. These are warmed shared-runner measurements,
not a service-level guarantee or live-network parameter snapshot.

The 100,000,000 Energy allowance is a harness setting, not demonstrated
transaction affordability. Contract version 0 and the explicit VM configuration
are recorded with every result; Dynamic Energy is disabled.

## Correctness results

| Suite | Observed result |
| --- | --- |
| Constructed standalone TVM cases | 59 expected outcomes passed: 43 successful calls, 14 expected reverts, 2 expected out-of-Energy failures |
| Constructed receipt state sequences | 9 sequences, 82 steps passed |
| Genuine native arithmetic | 168 expected outcomes passed: 65 true and 103 false results across nine proof bundles |
| Direct arithmetic comparison | 93 known-answer/differential cases passed, including 49 upstream known answers and 2 wrong-subgroup cases |
| Deadline and rollback canaries | Passed in both TVM CI runs |

The constructed state tests cover incomplete sessions, duplicates, invalid
proofs, altered domains/configurations/actions, cross-adapter replay, mixed
receipts, revoked or wrong-session snapshots, expiry, cleanup and double
finalization. Wrong-subgroup coverage includes a G1-infinity variant. The tested
version-0 TVM path can consume the forwarded Energy allowance on malformed
pairing input; the two corresponding cases assert the specific out-of-Energy
rejection rather than incorrectly expecting `false`.

Native mutations include valid-point negations in every gate, changed public
inputs/contexts and D/E splices assembled from independently valid proof
material. The count 168 is a number of assertions, not 168 independently
generated proofs. Each of the nine genuine bundles is repeated for timing.
No native receipt state sequence was run.

## Genuine native timing: current screen fails

Source: [private retained replay evidence](https://github.com/stealthos-xyz/privacy-protocol/blob/vanta-tron/research/vanta-tron/results/native-tvm.json).
For range rows, the range covers the separate case-level percentiles; it is not
a pooled percentile.

| Workload | Diagnostic p50, ms | Diagnostic p95, ms | Strict 80 ms timeouts |
| --- | ---: | ---: | ---: |
| Note8 full bundle | 441.344 | 454.312 | 30/30 |
| Note32 full bundle | 439.951 | 449.209 | 30/30 |
| Note8 Gate0 | 118.245 | 145.999 | 30/30 |
| Note32 Gate0 | 107.241 | 135.738 | 30/30 |
| Seven fee Gate0 cases | 132.069 to 144.539 | 139.041 to 154.497 | 210/210 |
| Full Caulk, nine cases | 251.072 to 256.551 | 260.361 to 318.074 | 270/270 |
| CP_link, nine cases | 77.200 to 77.685 | 82.010 to 122.907 | 49/270 |

| Individual Caulk equation | Diagnostic p50 range, ms | Diagnostic p95 range, ms | Strict timeouts across nine cases |
| --- | ---: | ---: | ---: |
| 0 | 63.871 to 64.310 | 67.104 to 71.921 | 7/270 |
| 1 | 66.599 to 67.130 | 71.067 to 96.473 | 0/270 |
| 2 | 68.719 to 70.870 | 74.173 to 81.704 | 4/270 |
| 3 | 61.381 to 63.019 | 67.348 to 74.448 | 1/270 |

Splitting Caulk reduces work per transaction, but 12 of 1,080 strict individual
equation calls still timed out. All native Gate0 calls failed the budget and
CP_link has insufficient observed margin. The coarse six-stage design cannot be
called a demonstrated solution for genuine workloads on this host.

Gate0 includes public-input accumulation followed by one four-pair product
check. Splitting scalar accumulation may help fee-heavy work, but the remaining
pairing call must independently fit the deadline. A pairing-product predicate
cannot be arbitrarily split into independent boolean predicates without a
soundness argument. More receipts alone do not establish feasibility.

## Constructed receipt timing: limited feasibility evidence

Source: [complete raw samples](results/staged-tvm.json).

| Strict sequence | Completed | Slowest stage p50, ms | Slowest stage p95, ms | Maximum stage, ms | Smallest observed margin below 80 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Width 8 | 30/30 | 66.179 | 68.214 | 72.557 | 7.443 ms |
| Width 32 | 30/30 | 66.241 | 68.659 | 71.526 | 8.474 ms |

The slowest stage was Gate0. The other five proof stages' p95 values were
39.814 to 49.700 ms for width 8 and 39.867 to 49.333 ms for width 32.
Research finalization p95 was 0.666 ms and 0.619 ms respectively. This is an event
and replay-state update, not production token settlement. Fixture snapshot
approval and a receipt getter are included in the harness sequence; they are
not a proposed requirement for separate production user transactions.

The separate standalone constructed width-8 Gate0 diagnostic batch reached
134.209 ms. Its strict batch had 0/30 timeouts but reached 78.101 ms, leaving
1.899 ms. These are separate batches: the 134 ms observation was not a strict
sequence timeout. It nevertheless rules out treating the successful sequence
sample as a reliable latency upper bound.

For comparison within this same constructed-fixture host, unsplit full note
bundles had diagnostic p50 values of 269.590 and 270.279 ms and timed out 30/30
each at 80 ms. Constructed 40/41-input fee Gate0 medians were 124.053 and
125.924 ms, also with 30/30 strict timeouts each. The prototype does not implement
fee receipt stages.

## Optimized arithmetic: promising, not compatible yet

Source: [raw comparison](results/bn128-comparison.json).
Candidate: `yanghang8612/java-tron@1b7ab7983fc5d79e884237a6a4d4a212c7b0ccec`.
Twenty source/resource files are pinned by both Git blob identity and SHA-256.
The probe builds a separate optimized namespace plus its adapter; it does not
replace the released VM's loaded classes.

| Pair count | Released diagnostic p50, ms | Candidate diagnostic p50, ms | Median ratio | Strict released / candidate timeouts |
| --- | ---: | ---: | ---: | ---: |
| 2 | 44.013 | 4.510 | 9.76x | 0/30 / 0/30 |
| 4 | 77.641 | 6.607 | 11.75x | 0/30 / 0/30 |
| 8 | 145.048 | 10.910 | 13.30x | 30/30 / 0/30 |

The candidate's strict eight-pair p95 was 11.884 ms, maximum 12.089 ms. Released
strict eight-pair observations around 87 to 89 ms are failed timeout observations,
not completed eight-pair runtimes.

An expired pairing deadline exposes a compatibility difference: released code
throws `Program.OutOfTimeException`; the candidate returns `false` with empty
bytes. The result explicitly records `optimizedTvmCompatible: false`.
Full deadline, failure, consensus and Energy semantics require review before
any integrated TVM experiment. Network adoption is a separate external decision.

## Required next gates

1. **Resolve the remaining arithmetic deadline.** Benchmark proposed changes
   against genuine inputs on the same representative hosts. Evaluate compatible
   runtime arithmetic work and sound verifier decompositions independently.
   Include the residual pairing call, receipt overhead and tail behavior. Do
   not derive an optimized full-transaction estimate from these microbenchmarks.
2. **Integrate the existing canonical statement.** Native note input 0 is
   constrained by the circuit's canonical Poseidon action computation. The
   prototype's `statementFor` uses a different research Keccak digest. Merely
   regenerating a proof with a new context cannot reconcile the two. Adapt the
   receipt boundary to the existing canonical statement and context; do not
   redesign the circuits merely to fit the research adapter. Then test genuine
   staged receipt authorization end to end.
3. **Complete settlement semantics.** Add reviewed fee admission, all required
   KZG state transitions, current checkpoint authentication, full production
   nullifiers and pool settlement. Preserve the final atomic checks across
   delayed or reordered receipt transactions.
4. **Qualify the TRON family and deployment environment.** This includes the
   TRON-specific proof domain, STREAM_BOUND4 producer path, representative
   transaction/block admission, actual network parameters, Dynamic Energy,
   operational cost and independent security review.

No production deployment, wallet transaction, signing, release, ceremony
activation or active DogeOS runtime change occurred in this phase.

## Permanent evidence inventory

The source and reproduction commands are in [README.md](README.md). Public raw
results retain every timing sample and deployed runtime hash. Only constructor
return bytecode was removed from the retained TVM result, with that omission
recorded in its metadata. The private protocol repository retains the normalized
genuine corpus, native raw timings and its replay report.

| Original CI result | SHA-256 before evidence metadata/constructor-bytecode omission |
| --- | --- |
| Constructed TVM | `5904e31d2607aabeb2d6fb6509e282ff56b4e3674a272c1b0013d06bcc0fba8d` |
| Arithmetic comparison | `3a50052d4baedbd42a82a8ca2dd59803957b06278b0ec5a5c1995befb7535335` |
| Genuine native TVM | `5860cf780288836489492c01708949bf5f4b4d4a9bc20b418b3d6109fc3af7cd` |

The earlier precompile-only screen remains in
[PHASE_2_RESULTS.md](PHASE_2_RESULTS.md). Its hardware and fixtures differ from
this phase, so the absolute timing differences are not evidence of a regression.
