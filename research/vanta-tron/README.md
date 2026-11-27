# Vanta TRON research

All work in this directory belongs to the `vanta-tron` branch. The original
contracts in `contracts/src` remain unchanged and are checked against their
source manifest. This experiment moves no funds and grants no pool authority.

The completed [phase 3 results](PHASE_3_RESULTS.md) include raw CI evidence.
All 168 genuine native correctness outcomes passed, but the current released
runtime and coarse staging design did not qualify the 80 ms timing screen.

## What runs

1. **Actual TVM execution.** The pinned official TRON Solidity 0.8.26 compiler
   generates bytecode. `TronVmProbe.java` executes its constructors and calls
   in the released Java-Tron 4.8.2.4 VM with an in-memory repository. Nested
   calls, storage, return data, reverts and transaction CPU deadlines execute
   through the real VM. Unsupported repository operations fail closed.
2. **Staged family verification.** A research adapter verifies six separate
   obligations: family Gate0, four original Caulk equations, and CP_link.
   Every receipt binds the full bundle, action, keys, arity, chain and adapter.
   A fresh state callback and replay checks precede a one-time finalization
   event. This is not token settlement.
3. **Upstream arithmetic comparison.** A separate probe builds the pinned
   optimized BN128 candidate at
   `yanghang8612/java-tron@1b7ab7983fc5d79e884237a6a4d4a212c7b0ccec`.
   It compares known answers, rejection behavior and alternating timing
   samples against released precompiles. It never replaces released VM classes.
4. **Genuine native proof import.** `build-native-vm-fixtures.mjs` consumes
   integrity-checked public-only artifacts from the private protocol research
   workflow. It exercises both six-input note sizes and 40/41-input fee
   arithmetic, original full note bundles, isolated Caulk equations and invalid
   mutations. Native proof generation is not STREAM_BOUND4 browser qualification.

## Reproduction

Install Node 22 or newer and JDK 8. Download the official compiler and runtime
shown in `.github/workflows/vanta-tron-staged.yml`; verify both recorded SHA-256
hashes before running. Use an absolute, explicit compiler and JDK path.

From this directory:

```sh
npm ci --ignore-scripts --no-audit --no-fund
node staged/check-source-pins.mjs
node build-vm-fixtures.mjs /path/to/tron-solc /tmp/constructed-tvm.json
/path/to/jdk8/bin/javac -proc:none -cp /path/to/FullNode.jar -d /tmp/vanta-tron-classes TronVmProbe.java
cd /tmp
/path/to/jdk8/bin/java -Xmx2g -cp /tmp/vanta-tron-classes:/path/to/FullNode.jar TronVmProbe /tmp/constructed-tvm.json /tmp/tvm-results.json
```

For genuine native arithmetic, replace fixture construction with:

```sh
node build-native-vm-fixtures.mjs /path/to/tron-solc /tmp/native-tvm.json /path/to/note8 /path/to/note32 /path/to/fees
```

Each input directory must contain the generated public manifest and its exact
hashed JSON files. The importer rejects mixed source revisions and domains.
Current native producers use the existing local qualification domain with fresh
disposable keys; this does not activate a TRON proof family or reuse deployed
keys. The staged adapter has a separate new research statement/context, so those
native proofs test arithmetic rather than staged receipt finalization. The
native statement is constrained by the existing circuit's canonical Poseidon
computation; changing only the proof context cannot satisfy the adapter's
unrelated research Keccak statement. Integrate the existing canonical statement
and context into the adapter before qualifying genuine receipt authorization.

For the direct upstream comparison:

```sh
node prepare-optimized-bn128.mjs /path/to/FullNode.jar /path/to/jdk8/bin/javac /tmp/bn128-candidate
/path/to/jdk8/bin/java -Xmx2g -cp /tmp/bn128-candidate/classes:/path/to/FullNode.jar org.tron.core.vm.OptimizedBn128Probe /tmp/bn128-candidate/source/actuator/src/test/resources/bn128 /tmp/bn128-results.json
```

## Acceptance and limits

- Correctness requires exact returned bytes or the declared rejection, and
  every receipt-state assertion. Independent write-then-revert and
  write-then-timeout canaries check transaction rollback.
- Benchmarks retain raw samples, successful completion distributions and
  timeout counts. Diagnostic 5-second samples measure the complete work;
  strict 80-ms samples enforce a screening budget. Successful CI does not
  imply that every strict sample completed. Timeouts are not successful latency.
- Every staged transaction receives its own deadline. Later stages are skipped
  after a timeout and cannot inherit a receipt from that failed transaction.
- Debug, SolidityNode and constant-call bypasses are disabled. The explicit
  isolated TVM configuration includes `allowMultiSign` for normal address
  semantics, but is not a live-network parameter snapshot. Dynamic Energy
  surcharges and transaction admission are outside this in-memory harness.
- In the tested version-0 TVM path, malformed pairing input can consume the
  complete forwarded Energy allowance. The original wrapper can therefore
  reject with `OutOfEnergyException` instead of returning `false`. Wrong-subgroup
  tests require that specific failure, including a G1-infinity variant.
- The optimized candidate differs in timeout semantics: its adapter returns
  failure, while released pairing throws `OutOfTimeException`. It is not a
  drop-in runtime replacement and is not qualified or adopted by this research.
- `ResearchStateChecker` is an owner-controlled fixture snapshot model. It is
  not a production checkpoint/fee-policy implementation. The research replay
  key is not Vanta's complete production nullifier set.
- Fee admission, five-row KZG transitions, real pool settlement, production
  intent reconstruction, actual-network timing, operational costs and
  STREAM_BOUND4 proofs under a TRON family remain separate qualification work.

The earlier screen is recorded in [PHASE_2_RESULTS.md](PHASE_2_RESULTS.md).
