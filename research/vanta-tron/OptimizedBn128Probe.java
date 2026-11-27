package org.tron.core.vm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.commons.lang3.tuple.Pair;
import org.tron.common.parameter.CommonParameter;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;
import org.tron.core.vm.config.VMConfig;
import org.tron.core.vm.program.Program;

/** Direct differential/latency comparison; it never replaces released VM classes. */
public final class OptimizedBn128Probe {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final BigInteger P = new BigInteger(
      "21888242871839275222246405745257275088696311157297823662689037894645226208583");
  private static final BigInteger R = new BigInteger(
      "21888242871839275222246405745257275088548364400416034343698204186575808495617");
  private static final PrecompiledContract[] RELEASED = {
      new PrecompiledContracts.BN128Addition(), new PrecompiledContracts.BN128Multiplication(),
      new PrecompiledContracts.BN128Pairing()};

  private static void require(boolean condition, String message) {
    if (!condition) throw new AssertionError(message);
  }

  private static byte[] hex(String s) {
    if (s.startsWith("0x")) s = s.substring(2);
    require(s.matches("(?:[0-9a-fA-F]{2})*"), "Invalid fixture hex");
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(2*i, 2*i+2), 16);
    return out;
  }

  private static byte[] words(BigInteger... values) {
    byte[] out = new byte[values.length * 32];
    for (int i = 0; i < values.length; i++) {
      require(values[i].signum() >= 0 && values[i].bitLength() <= 256, "Word out of range");
      byte[] b = values[i].toByteArray();
      int length = Math.min(32, b.length);
      System.arraycopy(b, b.length - length, out, (i + 1) * 32 - length, length);
    }
    return out;
  }

  private static byte[] repeat(byte[] bytes, int times) {
    byte[] result = new byte[bytes.length * times];
    for (int i = 0; i < times; i++) System.arraycopy(bytes, 0, result, i * bytes.length, bytes.length);
    return result;
  }

  private static Pair<Boolean, byte[]> call(int operation, byte[] input, boolean optimized,
      long deadlineUs) {
    if (!optimized) {
      PrecompiledContract contract = RELEASED[operation];
      contract.setVmShouldEndInUs(deadlineUs);
      return contract.execute(input);
    }
    switch (operation) {
      case 0: return OptimizedBN128.add(input);
      case 1: return OptimizedBN128.multiply(input, deadlineUs);
      case 2: return OptimizedBN128.pairing(input, deadlineUs);
      default: throw new AssertionError("Unknown operation");
    }
  }

  private static final class Fixture {
    final String name;
    final int operation;
    final byte[] input;
    final byte[] expected; // Null means reject; null expected with differentialOnly skips an oracle.
    final boolean differentialOnly;
    Fixture(String name, int operation, byte[] input, byte[] expected, boolean differentialOnly) {
      this.name = name; this.operation = operation; this.input = input;
      this.expected = expected; this.differentialOnly = differentialOnly;
    }
  }

  private static void check(Fixture fixture) {
    Pair<Boolean, byte[]> released = call(fixture.operation, fixture.input, false,
        System.nanoTime() / 1000 + 5000000);
    Pair<Boolean, byte[]> optimized = call(fixture.operation, fixture.input, true,
        System.nanoTime() / 1000 + 5000000);
    require(released.getLeft().equals(optimized.getLeft())
        && Arrays.equals(released.getRight(), optimized.getRight()),
        "Differential mismatch: " + fixture.name);
    if (!fixture.differentialOnly) {
      require(fixture.expected == null ? !released.getLeft()
          : released.getLeft() && Arrays.equals(released.getRight(), fixture.expected),
          "Known-answer mismatch: " + fixture.name);
    }
  }

  private static ObjectNode sample(Fixture fixture, boolean optimized, int budgetMs) {
    long start = System.nanoTime();
    long deadlineUs = start / 1000 + budgetMs * 1000L;
    String status = "success";
    Pair<Boolean, byte[]> result = null;
    try { result = call(fixture.operation, fixture.input, optimized, deadlineUs); }
    catch (Program.OutOfTimeException timeout) { status = "timeout"; }
    long end = System.nanoTime();
    if (end / 1000 > deadlineUs) status = "timeout";
    if ("success".equals(status)) require(result != null && result.getLeft()
        && Arrays.equals(result.getRight(), fixture.expected), "Benchmark result: " + fixture.name);
    ObjectNode out = JSON.createObjectNode();
    out.put("status", status);
    out.put("elapsedMs", (end - start) / 1_000_000.0);
    return out;
  }

  private static ObjectNode summarize(ArrayNode samples) {
    List<Double> times = new ArrayList<>();
    int timeouts = 0;
    for (JsonNode sample : samples) {
      times.add(sample.get("elapsedMs").asDouble());
      if ("timeout".equals(sample.get("status").asText())) timeouts++;
    }
    Collections.sort(times);
    ObjectNode out = JSON.createObjectNode();
    out.put("samples", times.size()); out.put("timeouts", timeouts);
    out.put("p50CompletionOrTimeoutMs", times.get((int) Math.ceil(times.size() * 0.50) - 1));
    out.put("p95CompletionOrTimeoutMs", times.get((int) Math.ceil(times.size() * 0.95) - 1));
    out.put("maxCompletionOrTimeoutMs", times.get(times.size() - 1));
    return out;
  }

  public static void main(String[] args) throws Exception {
    require(args.length == 2, "Usage: OptimizedBn128Probe fixture-directory results.json");
    require(!CommonParameter.getInstance().isDebug() && !CommonParameter.getInstance().isSolidityNode(),
        "Debug/SolidityNode bypass must be disabled");
    VMConfig.initAllowTvmIstanbul(1);
    List<Fixture> vectors = new ArrayList<>();
    List<Fixture> benchmarks = new ArrayList<>();
    String[] names = {"bn256Add.json", "bn256ScalarMul.json", "bn256Pairing.json"};
    for (int operation = 0; operation < names.length; operation++) {
      JsonNode fixtures = JSON.readTree(new File(args[0], names[operation]));
      for (JsonNode f : fixtures) vectors.add(new Fixture(names[operation] + ":" + f.get("Name").asText(),
          operation, hex(f.get("Input").asText()), hex(f.get("Expected").asText()), false));
      JsonNode first = fixtures.get(0);
      benchmarks.add(new Fixture(names[operation], operation,
          hex(first.get("Input").asText()), hex(first.get("Expected").asText()), false));
    }
    Fixture twoPairs = benchmarks.get(2);
    benchmarks.add(new Fixture("pairing-four-pairs", 2, repeat(twoPairs.input, 2), twoPairs.expected, false));
    benchmarks.add(new Fixture("pairing-eight-pairs", 2, repeat(twoPairs.input, 4), twoPairs.expected, false));
    BigInteger one = BigInteger.ONE, two = BigInteger.valueOf(2);
    BigInteger badYIm = new BigInteger("19659275751359636165940301690575149581329631496732780143538578556285923319774");
    BigInteger badYRe = new BigInteger("7292567877523311580221095596750716176434782432868683424513645834767876293070");
    vectors.add(new Fixture("non-subgroup-g2", 2, words(one, two, one, two, badYIm, badYRe), null, false));
    vectors.add(new Fixture("non-subgroup-g2-with-g1-infinity", 2,
        words(BigInteger.ZERO, BigInteger.ZERO, one, two, badYIm, badYRe), null, false));
    vectors.add(new Fixture("invalid-pairing-length", 2, words(one), null, false));
    vectors.add(new Fixture("noncanonical-g1-add", 0, words(P, two, one, two), null, false));
    vectors.add(new Fixture("off-curve-g1-mul", 1, words(one, BigInteger.valueOf(3), one), null, false));
    BigInteger[] scalars = {BigInteger.ZERO, one, two, R.subtract(one), R, R.add(one),
        one.shiftLeft(256).subtract(one)};
    for (BigInteger scalar : scalars) vectors.add(new Fixture("scalar-" + scalar.toString(16), 1,
        words(one, two, scalar), null, true));
    for (int i = 0; i < 32; i++) {
      byte[] mutation = twoPairs.input.clone();
      mutation[(i * 13) % mutation.length] ^= (byte) (1 << (i % 8));
      vectors.add(new Fixture("pairing-bit-mutation-" + i, 2, mutation, null, true));
    }
    for (Fixture fixture : vectors) check(fixture);

    ObjectNode output = JSON.createObjectNode();
    output.put("scope", "Direct arithmetic only. Not optimized TVM execution or network qualification.");
    output.put("candidate", "yanghang8612/java-tron@1b7ab7983fc5d79e884237a6a4d4a212c7b0ccec");
    output.put("knownAnswerAndDifferentialCases", vectors.size());
    output.put("upstreamKnownAnswerCases", 49);
    output.put("wrongSubgroupCases", 2);
    output.put("sameProcessAlternatingOrder", true);
    output.put("warmupsPerCasePerImplementation", 20);
    output.put("samplesPerBudgetPerImplementation", 30);
    output.put("optimizedTvmCompatible", false);
    ObjectNode expiry = output.putObject("expiredPairingDeadline");
    try {
      call(2, twoPairs.input, false, System.nanoTime() / 1000 - 1);
      throw new AssertionError("Released pairing did not enforce expired deadline");
    } catch (Program.OutOfTimeException expected) { expiry.put("released", "OutOfTimeException"); }
    Pair<Boolean, byte[]> expired = call(2, twoPairs.input, true, System.nanoTime() / 1000 - 1);
    require(!expired.getLeft() && expired.getRight().length == 0, "Candidate ignored expired deadline");
    expiry.put("candidate", "false with empty return bytes");
    expiry.put("compatible", false);
    expiry.put("consequence", "No drop-in VM replacement is attempted. Timeout semantics require review.");
    ArrayNode all = output.putArray("benchmarks");
    for (Fixture fixture : benchmarks) {
      for (int i = 0; i < 20; i++) {
        sample(fixture, (i & 1) == 0, 5000);
        sample(fixture, (i & 1) != 0, 5000);
      }
      for (int budget : new int[] {5000, 80}) {
        ArrayNode released = JSON.createArrayNode(), candidate = JSON.createArrayNode();
        for (int i = 0; i < 30; i++) {
          if ((i & 1) == 0) {
            released.add(sample(fixture, false, budget)); candidate.add(sample(fixture, true, budget));
          } else {
            candidate.add(sample(fixture, true, budget)); released.add(sample(fixture, false, budget));
          }
        }
        ObjectNode record = JSON.createObjectNode();
        record.put("name", fixture.name); record.put("budgetMs", budget);
        record.set("released", summarize(released)); record.set("candidate", summarize(candidate));
        if (budget == 5000) require(record.get("released").get("timeouts").asInt() == 0
            && record.get("candidate").get("timeouts").asInt() == 0, "Diagnostic run timed out");
        System.out.println("ALGORITHM_COMPARISON=" + JSON.writeValueAsString(record));
        record.set("releasedRaw", released); record.set("candidateRaw", candidate); all.add(record);
      }
    }
    JSON.writerWithDefaultPrettyPrinter().writeValue(new File(args[1]), output);
    System.out.println("DIFFERENTIAL_CASES=" + vectors.size());
    System.out.println("DEADLINE_SEMANTICS_DIFFER=true; OPTIMIZED_TVM_COMPATIBLE=false");
  }
}
