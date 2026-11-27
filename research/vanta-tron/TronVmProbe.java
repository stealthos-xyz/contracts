import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.protobuf.ByteString;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.tron.common.crypto.Hash;
import org.tron.common.parameter.CommonParameter;
import org.tron.common.runtime.InternalTransaction;
import org.tron.common.runtime.ProgramResult;
import org.tron.common.runtime.vm.DataWord;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.BlockCapsule;
import org.tron.core.capsule.ContractCapsule;
import org.tron.core.vm.JumpTable;
import org.tron.core.vm.OperationRegistry;
import org.tron.core.vm.VM;
import org.tron.core.vm.config.VMConfig;
import org.tron.core.vm.program.Program;
import org.tron.core.vm.program.invoke.ProgramInvokeImpl;
import org.tron.core.vm.repository.Repository;
import org.tron.protos.Protocol;
import org.tron.protos.contract.SmartContractOuterClass.SmartContract;

/**
 * Isolated, zero-value execution of real TVM bytecode with the released java-tron VM.
 * No node, RPC, signing, mainnet state, database, or debug/constant-call bypass is used.
 * A deliberately small in-memory Repository supplies code, account metadata and storage.
 * Unsupported repository operations fail closed; this is not a full chain emulator.
 *
 * Usage: java -cp probe-classes:FullNode.jar TronVmProbe fixtures.json results.json
 * Contracts are installed from runtime hex, or created by executing creation hex plus
 * constructor arguments at their fixture address. Cases reset to the installed baseline.
 * Sequence steps share committed storage, and each step has its own transaction deadline.
 */
public final class TronVmProbe {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final byte[] EMPTY = new byte[0];
  private static final byte[] CALLER = address("00000000000000000000000000000000000000aa");
  private static final String DEFAULT_GENESIS =
      "0000000000000000000000000000000000000000000000000000000056545233";
  private static JumpTable table;
  private static long defaultBlock;
  private static long defaultTimestamp;
  private static long energyLimit;

  private static void require(boolean ok, String reason) {
    if (!ok) throw new AssertionError(reason);
  }

  private static byte[] hex(String input) {
    String s = input.startsWith("0x") ? input.substring(2) : input;
    require((s.length() & 1) == 0 && s.matches("[0-9a-fA-F]*"), "Invalid hex");
    byte[] bytes = new byte[s.length() / 2];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  private static String hex(byte[] bytes) {
    char[] alphabet = "0123456789abcdef".toCharArray();
    char[] result = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      int value = bytes[i] & 255;
      result[i * 2] = alphabet[value >>> 4];
      result[i * 2 + 1] = alphabet[value & 15];
    }
    return new String(result);
  }

  private static byte[] address(String input) {
    byte[] bytes = hex(input);
    if (bytes.length == 20) {
      byte[] tron = new byte[21];
      tron[0] = 0x41;
      System.arraycopy(bytes, 0, tron, 1, 20);
      return tron;
    }
    require(bytes.length == 21 && bytes[0] == 0x41, "Expected a 20-byte or 0x41-prefixed address");
    return bytes;
  }

  private static String hash(byte[] bytes) throws Exception {
    return hex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }

  private static String classHash(Class<?> type) throws Exception {
    String resource = "/" + type.getName().replace('.', '/') + ".class";
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    try (InputStream input = type.getResourceAsStream(resource)) {
      require(input != null, "Missing class bytes for " + type.getName());
      byte[] buffer = new byte[8192];
      for (int count; (count = input.read(buffer)) != -1;) digest.update(buffer, 0, count);
    }
    return hex(digest.digest());
  }

  /** Repository overlays provide real nested-call commit/rollback, without external state. */
  private static final class MemoryRepository implements InvocationHandler {
    final MemoryRepository parent;
    final Repository api;
    final BlockCapsule genesis;
    final Map<String, byte[]> code = new HashMap<>();
    final Map<String, AccountCapsule> accounts = new HashMap<>();
    final Map<String, ContractCapsule> contracts = new HashMap<>();
    final Map<String, byte[]> storage = new HashMap<>();
    final Map<String, byte[]> transientStorage = new HashMap<>();

    MemoryRepository(MemoryRepository parent, BlockCapsule genesis) {
      this.parent = parent;
      this.genesis = genesis;
      this.api = (Repository) Proxy.newProxyInstance(Repository.class.getClassLoader(),
          new Class<?>[] {Repository.class}, this);
    }

    MemoryRepository child() { return new MemoryRepository(this, genesis); }

    byte[] codeAt(String key) {
      byte[] value = code.get(key);
      return value != null ? value : parent == null ? EMPTY : parent.codeAt(key);
    }

    AccountCapsule accountAt(String key) {
      AccountCapsule value = accounts.get(key);
      if (value == null && parent != null) value = parent.accountAt(key);
      return value == null ? null : new AccountCapsule(value.getInstance());
    }

    ContractCapsule contractAt(String key) {
      ContractCapsule value = contracts.get(key);
      if (value == null && parent != null) value = parent.contractAt(key);
      return value == null ? null : new ContractCapsule(value.getInstance());
    }

    byte[] storageAt(String key, boolean transientValue) {
      byte[] value = (transientValue ? transientStorage : storage).get(key);
      if (value == null && parent != null) value = parent.storageAt(key, transientValue);
      return value == null ? new byte[32] : value.clone();
    }

    void addAccount(byte[] at, Protocol.AccountType type) {
      accounts.put(hex(at), new AccountCapsule(ByteString.copyFrom(at), type));
    }

    void install(byte[] at, byte[] runtime) {
      code.put(hex(at), runtime.clone());
      addAccount(at, Protocol.AccountType.Contract);
      contracts.put(hex(at), new ContractCapsule(SmartContract.newBuilder()
          .setContractAddress(ByteString.copyFrom(at))
          .setOriginAddress(ByteString.copyFrom(CALLER))
          .setCodeHash(ByteString.copyFrom(Hash.sha3(runtime))).build()));
    }

    void commit() {
      require(parent != null, "Cannot commit the root fixture repository");
      parent.code.putAll(code);
      parent.accounts.putAll(accounts);
      parent.contracts.putAll(contracts);
      parent.storage.putAll(storage);
      parent.transientStorage.putAll(transientStorage);
    }

    @Override public Object invoke(Object proxy, Method method, Object[] args) {
      String name = method.getName();
      switch (name) {
        case "toString": return "IsolatedMemoryRepository";
        case "hashCode": return System.identityHashCode(this);
        case "equals": return proxy == args[0];
        case "newRepositoryChild": return child().api;
        case "commit": commit(); return null;
        case "getCode": return codeAt(hex((byte[]) args[0])).clone();
        case "saveCode": code.put(hex((byte[]) args[0]), ((byte[]) args[1]).clone()); return null;
        case "getAccount": return accountAt(hex((byte[]) args[0]));
        case "getContract": return contractAt(hex((byte[]) args[0]));
        case "updateContract":
        case "createContract": contracts.put(hex((byte[]) args[0]),
            new ContractCapsule(((ContractCapsule) args[1]).getInstance())); return null;
        case "updateAccount":
        case "putAccountValue": accounts.put(hex((byte[]) args[0]),
            new AccountCapsule(((AccountCapsule) args[1]).getInstance())); return null;
        case "getBalance": {
          AccountCapsule account = accountAt(hex((byte[]) args[0]));
          return account == null ? 0L : account.getBalance();
        }
        case "getStorageValue": return new DataWord(storageAt(
            hex((byte[]) args[0]) + ":" + hex(((DataWord) args[1]).getData()), false));
        case "putStorageValue": storage.put(
            hex((byte[]) args[0]) + ":" + hex(((DataWord) args[1]).getData()),
            ((DataWord) args[2]).getData().clone()); return null;
        case "getTransientStorageValue": return storageAt(
            hex((byte[]) args[0]) + ":" + hex((byte[]) args[1]), true);
        case "updateTransientStorageValue": transientStorage.put(
            hex((byte[]) args[0]) + ":" + hex((byte[]) args[1]),
            ((byte[]) args[2]).clone()); return null;
        case "getBlockByNum":
          require(((Long) args[0]) == 0L, "Only fixture genesis is available");
          return genesis;
        default: throw new AssertionError("Unsupported Repository operation: " + name);
      }
    }
  }

  private static final class Outcome {
    String status;
    String error;
    byte[] returned;
    long nanos;
    long energy;
    int storageOverlaySlots;

    ObjectNode json() {
      ObjectNode out = JSON.createObjectNode();
      out.put("status", status);
      out.put("elapsedMs", nanos / 1_000_000.0);
      out.put("energy", energy);
      out.put("storageOverlaySlots", storageOverlaySlots);
      out.put("returnData", "0x" + hex(returned));
      if (error != null) out.put("error", error);
      return out;
    }
  }

  private static Outcome execute(MemoryRepository state, byte[] at, byte[] code,
      byte[] input, byte[] caller, long block, long timestamp, int budgetMs) {
    require(budgetMs > 0, "CPU budget must be positive");
    MemoryRepository tx = state.child();
    // Transient storage is transaction scoped, including all nested calls.
    state.transientStorage.clear();
    InternalTransaction internal = new InternalTransaction(new byte[32], -1, 0,
        caller, at, 0, input, "call", 0, Collections.<String, Long>emptyMap());
    long started = System.nanoTime();
    long startUs = started / 1000;
    ProgramInvokeImpl invoke = new ProgramInvokeImpl(at, caller, caller, 0L,
        0L, 0L, 0L, input, new byte[32], CALLER, timestamp, block,
        tx.api, startUs, startUs + budgetMs * 1000L, false, energyLimit);
    require(!invoke.isConstantCall() && !invoke.byTestingSuite(), "Execution bypass enabled");
    Program program = new Program(code, at, invoke, internal);
    program.setRootTransactionId(new byte[32]);
    Outcome out = new Outcome();
    try {
      VM.play(program, table);
      // Same final deadline check used by energy-adjusted execution. It also catches
      // an expensive final opcode or RETURN that completed immediately after its deadline.
      program.checkCPUTimeLimit("probe-final-check");
      ProgramResult result = program.getResult();
      if (result.getException() != null) {
        out.status = result.getException() instanceof Program.OutOfTimeException
            ? "timeout" : "error";
        out.error = result.getException().getClass().getName() + ": " + result.getException().getMessage();
      } else if (result.isRevert()) {
        out.status = "revert";
      } else {
        out.status = "success";
      }
    } catch (Program.OutOfTimeException timeout) {
      out.status = "timeout";
      out.error = timeout.getMessage();
    }
    out.nanos = System.nanoTime() - started;
    out.energy = program.getResult().getEnergyUsed();
    out.returned = program.getResult().getHReturn();
    out.storageOverlaySlots = tx.storage.size();
    if ("success".equals(out.status)) tx.commit();
    return out;
  }

  private static Outcome runCase(MemoryRepository state, JsonNode test, int budgetMs) {
    byte[] at = address(test.path("to").asText());
    byte[] code = state.codeAt(hex(at));
    require(code.length > 0, "Missing target code: " + test.path("name").asText());
    return execute(state, at, code, hex(test.path("data").asText()),
        test.has("caller") ? address(test.get("caller").asText()) : CALLER,
        test.path("blockNumber").asLong(defaultBlock),
        test.path("timestamp").asLong(defaultTimestamp), budgetMs);
  }

  private static void assertExpected(JsonNode test, Outcome out) {
    String name = test.path("name").asText("unnamed");
    JsonNode expected = test.path("expected");
    require(expected.has("status"), "Missing expected status: " + name);
    require(expected.get("status").asText().equals(out.status),
        name + ": unexpected execution result " + out.json());
    if (expected.has("returnData")) require(Arrays.equals(
        hex(expected.get("returnData").asText()), out.returned),
        name + ": incorrect returned bytes " + out.json());
    if (expected.has("errorContains")) {
      String fragment = expected.get("errorContains").asText();
      require(!fragment.isEmpty() && out.error != null && out.error.contains(fragment),
          name + ": expected specific failure " + fragment + ", got " + out.json());
    }
  }

  private static ObjectNode benchmark(MemoryRepository baseline, JsonNode test, int budgetMs,
      int samples) {
    ArrayNode raw = JSON.createArrayNode();
    List<Long> elapsed = new ArrayList<>();
    List<Long> successful = new ArrayList<>();
    int timeouts = 0;
    for (int i = 0; i < samples; i++) {
      Outcome out = runCase(baseline.child(), test, budgetMs);
      raw.add(out.json());
      elapsed.add(out.nanos);
      if ("timeout".equals(out.status)) timeouts++;
      else { assertExpected(test, out); successful.add(out.nanos); }
    }
    Collections.sort(elapsed);
    Collections.sort(successful);
    ObjectNode result = JSON.createObjectNode();
    result.put("name", test.path("name").asText());
    result.put("budgetMs", budgetMs);
    result.put("samples", samples);
    result.put("timeouts", timeouts);
    result.put("allCompleted", timeouts == 0);
    result.set("completionOrTimeoutMs", distribution(elapsed));
    if (!successful.isEmpty()) result.set("completedMs", distribution(successful));
    result.set("raw", raw);
    return result;
  }

  private static ObjectNode distribution(List<Long> sorted) {
    ObjectNode result = JSON.createObjectNode();
    result.put("p50", sorted.get((int) Math.ceil(sorted.size() * 0.50) - 1) / 1_000_000.0);
    result.put("p95", sorted.get((int) Math.ceil(sorted.size() * 0.95) - 1) / 1_000_000.0);
    result.put("max", sorted.get(sorted.size() - 1) / 1_000_000.0);
    return result;
  }

  /** These always-run canaries prove failure discards an actual preceding SSTORE. */
  private static ObjectNode rollbackCanaries(MemoryRepository baseline, int diagnosticBudget) {
    MemoryRepository state = baseline.child();
    byte[] at = address("00000000000000000000000000000000000000cc");
    state.addAccount(at, Protocol.AccountType.Contract);
    String key = hex(at) + ":" + hex(new DataWord(0).getData());
    byte[] original = new DataWord(7).getData();
    state.storage.put(key, original.clone());

    // PUSH1 42; PUSH1 0; SSTORE; PUSH1 0; PUSH1 0; REVERT.
    // Run this first to initialize the storage path before the short timed canary.
    Outcome reverted = execute(state, at, hex("602a60005560006000fd"), EMPTY,
        CALLER, defaultBlock, defaultTimestamp, diagnosticBudget);
    require("revert".equals(reverted.status) && reverted.storageOverlaySlots == 1,
        "Write/revert canary did not execute its SSTORE: " + reverted.json());
    require(Arrays.equals(original, state.storageAt(key, false)),
        "Write/revert canary leaked storage into its parent");

    // PUSH1 42; PUSH1 0; SSTORE; label at offset 5: JUMPDEST; PUSH1 5; JUMP.
    Outcome timedOut = execute(state, at, hex("602a6000555b600556"), EMPTY,
        CALLER, defaultBlock, defaultTimestamp, 20);
    require("timeout".equals(timedOut.status) && timedOut.storageOverlaySlots == 1,
        "Write/timeout canary did not execute its SSTORE: " + timedOut.json());
    require(Arrays.equals(original, state.storageAt(key, false)),
        "Write/timeout canary leaked storage into its parent");

    ObjectNode result = JSON.createObjectNode();
    result.set("writeThenRevert", reverted.json().put("budgetMs", diagnosticBudget));
    result.set("writeThenTimeout", timedOut.json().put("budgetMs", 20));
    result.put("originalStorageWord", "0x" + hex(original));
    result.put("bothParentStorageChecksPassed", true);
    return result;
  }

  private static ObjectNode benchmarkSequence(MemoryRepository baseline, JsonNode sequence,
      int budgetMs, int samples) {
    JsonNode steps = sequence.path("steps");
    List<ArrayNode> raw = new ArrayList<>();
    List<List<Long>> elapsed = new ArrayList<>();
    int[] timeouts = new int[steps.size()];
    for (JsonNode ignored : steps) {
      raw.add(JSON.createArrayNode());
      elapsed.add(new ArrayList<Long>());
    }
    int completed = 0;
    for (int sample = 0; sample < samples; sample++) {
      MemoryRepository state = baseline.child();
      boolean finished = true;
      for (int index = 0; index < steps.size(); index++) {
        JsonNode step = steps.get(index);
        Outcome out = runCase(state, step, budgetMs);
        ObjectNode detail = out.json();
        detail.put("sample", sample);
        raw.get(index).add(detail);
        elapsed.get(index).add(out.nanos);
        if ("timeout".equals(out.status)) {
          timeouts[index]++;
          finished = false;
          break; // Later stages cannot inherit a receipt from a timed-out transaction.
        }
        assertExpected(step, out);
      }
      if (finished) completed++;
    }
    ObjectNode result = JSON.createObjectNode();
    result.put("name", sequence.path("name").asText());
    result.put("budgetMsPerTransaction", budgetMs);
    result.put("sequenceSamples", samples);
    result.put("completedSequences", completed);
    result.put("abortedSequences", samples - completed);
    ArrayNode stages = result.putArray("steps");
    for (int index = 0; index < steps.size(); index++) {
      List<Long> measured = elapsed.get(index);
      Collections.sort(measured);
      ObjectNode stage = JSON.createObjectNode();
      stage.put("name", steps.get(index).path("name").asText());
      stage.put("attempts", measured.size());
      stage.put("timeouts", timeouts[index]);
      if (!measured.isEmpty()) stage.set("completionOrTimeoutMs", distribution(measured));
      stage.set("raw", raw.get(index));
      stages.add(stage);
    }
    return result;
  }

  public static void main(String[] args) throws Exception {
    require(args.length == 2, "Usage: TronVmProbe fixtures.json results.json");
    require(!CommonParameter.getInstance().isDebug(), "Debug mode must be disabled");
    require(!CommonParameter.getInstance().isSolidityNode(), "SolidityNode bypass must be disabled");
    JsonNode fixture = JSON.readTree(new File(args[0]));
    require(fixture.path("schemaVersion").asInt() == 1, "Unsupported fixture schema");
    VMConfig.Snapshot config = new VMConfig.Snapshot();
    config.allowMultiSign = true; // ADDRESS/ORIGIN use the final 20 bytes under this TVM rule.
    config.allowTvmTransferTrc10 = true;
    config.allowTvmConstantinople = true;
    config.allowTvmSolidity059 = true;
    config.allowTvmIstanbul = true;
    config.allowTvmLondon = true;
    config.allowTvmShanghai = true;
    config.allowTvmCancun = true;
    config.allowEnergyAdjustment = true;
    config.allowOptimizedReturnValueOfChainId = true;
    // Deliberately excludes dynamic Energy surcharges and unrelated chain features.
    // This explicit isolated configuration must not be called a live mainnet snapshot.
    VMConfig.setGlobalSnapshot(config);
    VMConfig.initVmHardFork(true);
    table = OperationRegistry.prepareAndGetTable(false);
    defaultBlock = fixture.path("blockNumber").asLong(1);
    defaultTimestamp = fixture.path("timestamp").asLong(1);
    energyLimit = fixture.path("energyLimit").asLong(100_000_000L);
    require(energyLimit > 0 && energyLimit <= 1_000_000_000L, "Invalid diagnostic Energy limit");
    final byte[] genesisBytes = hex(fixture.path("genesisHash").asText(DEFAULT_GENESIS));
    require(genesisBytes.length == 32, "Genesis hash must have 32 bytes");
    require(Arrays.equals(Arrays.copyOf(genesisBytes, 8), new byte[8]), "Genesis height must be zero");
    BlockCapsule genesis = new BlockCapsule(Protocol.Block.getDefaultInstance()) {
      @Override public BlockId getBlockId() { return new BlockId(genesisBytes, 0); }
    };
    MemoryRepository baseline = new MemoryRepository(null, genesis);
    baseline.addAccount(CALLER, Protocol.AccountType.Normal);
    JsonNode options = fixture.path("benchmark");
    int warmup = options.path("warmup").asInt(10);
    int samples = options.path("samples").asInt(30);
    int budget = options.path("budgetMs").asInt(80);
    int diagnosticBudget = options.path("diagnosticBudgetMs").asInt(5000);
    require(warmup >= 0 && warmup <= 10000 && samples > 0 && samples <= 10000,
        "Invalid benchmark sample counts");
    require(budget > 0 && diagnosticBudget > budget && diagnosticBudget <= 30000,
        "Invalid strict/diagnostic CPU budgets");

    ObjectNode output = JSON.createObjectNode();
    output.put("schemaVersion", 1);
    output.put("runtime", "java-tron GreatVoyage-v4.8.2.4");
    output.put("cryptoVariant", System.getProperty("vanta.cryptoVariant", "released-java"));
    ObjectNode classes = output.putObject("loadedClassSha256");
    classes.put("VM", classHash(VM.class));
    classes.put("PrecompiledContracts", classHash(org.tron.core.vm.PrecompiledContracts.class));
    classes.put("PairingCheck", classHash(org.tron.common.crypto.zksnark.PairingCheck.class));
    output.put("scope", fixture.path("scope").asText("unspecified"));
    output.put("fixtureSha256", hash(Files.readAllBytes(new File(args[0]).toPath())));
    output.put("genesisHash", "0x" + hex(genesisBytes));
    output.put("chainId", new java.math.BigInteger(1, Arrays.copyOfRange(genesisBytes, 28, 32)).toString());
    output.put("debug", false);
    output.put("constantCall", false);
    output.put("byTestingSuite", false);
    output.put("dynamicEnergy", false);
    output.put("energyLimit", energyLimit);
    output.put("javaVersion", System.getProperty("java.version"));
    output.put("osArch", System.getProperty("os.arch"));
    output.set("vmConfig", JSON.valueToTree(config));
    Outcome deadlineCanary = execute(baseline.child(), CALLER, hex("5b600056"),
        EMPTY, CALLER, defaultBlock, defaultTimestamp, 5);
    require("timeout".equals(deadlineCanary.status), "VM deadline canary did not time out");
    output.set("deadlineCanary", deadlineCanary.json().put("budgetMs", 5));
    output.set("rollbackCanaries", rollbackCanaries(baseline, diagnosticBudget));
    ArrayNode deployed = output.putArray("contracts");
    require(fixture.path("contracts").isArray(), "contracts must be an array");
    for (JsonNode contract : fixture.get("contracts")) {
      byte[] at = address(contract.path("address").asText());
      require(baseline.codeAt(hex(at)).length == 0, "Duplicate contract address");
      require(contract.has("creation") != contract.has("runtime"),
          "Specify exactly one of creation or runtime");
      baseline.addAccount(at, Protocol.AccountType.Contract);
      byte[] runtime;
      ObjectNode record = JSON.createObjectNode();
      record.put("name", contract.path("name").asText());
      record.put("address", "0x" + hex(at));
      if (contract.has("creation")) {
        Outcome created = execute(baseline, at, hex(contract.get("creation").asText()),
            EMPTY, CALLER, defaultBlock, defaultTimestamp, diagnosticBudget);
        require("success".equals(created.status) && created.returned.length > 0,
            "Constructor failed: " + record + " " + created.json());
        runtime = created.returned;
        record.set("constructor", created.json());
      } else runtime = hex(contract.get("runtime").asText());
      require(runtime.length > 0, "Empty installed runtime");
      baseline.install(at, runtime);
      Iterator<Map.Entry<String, JsonNode>> fields = contract.path("storage").fields();
      while (fields.hasNext()) {
        Map.Entry<String, JsonNode> field = fields.next();
        byte[] slot = new DataWord(hex(field.getKey())).getData();
        byte[] value = new DataWord(hex(field.getValue().asText())).getData();
        baseline.storage.put(hex(at) + ":" + hex(slot), value);
      }
      record.put("runtimeBytes", runtime.length);
      record.put("runtimeSha256", hash(runtime));
      deployed.add(record);
    }

    ArrayNode checked = output.putArray("correctness");
    ArrayNode timings = output.putArray("benchmarks");
    require(fixture.path("cases").isArray(), "cases must be an array");
    for (JsonNode test : fixture.get("cases")) {
      Outcome out = runCase(baseline.child(), test, diagnosticBudget);
      assertExpected(test, out);
      ObjectNode record = out.json();
      record.put("name", test.path("name").asText());
      checked.add(record);
      if (test.path("benchmark").asBoolean(false)) {
        require("success".equals(test.path("expected").path("status").asText()),
            "Benchmark only accepted verifier calls; negative cases are correctness tests");
        for (int i = 0; i < warmup; i++) {
          Outcome warmed = runCase(baseline.child(), test, diagnosticBudget);
          assertExpected(test, warmed);
        }
        ObjectNode diagnostic = benchmark(baseline, test, diagnosticBudget, samples);
        require(diagnostic.get("allCompleted").asBoolean(), "Diagnostic sample timed out");
        timings.add(diagnostic);
        timings.add(benchmark(baseline, test, budget, samples));
      }
    }
    ArrayNode sequences = output.putArray("sequences");
    ArrayNode sequenceBenchmarks = output.putArray("sequenceBenchmarks");
    for (JsonNode sequence : fixture.path("sequences")) {
      MemoryRepository state = baseline.child();
      ObjectNode record = JSON.createObjectNode();
      record.put("name", sequence.path("name").asText());
      ArrayNode steps = record.putArray("steps");
      for (JsonNode step : sequence.path("steps")) {
        Outcome out = runCase(state, step, diagnosticBudget);
        assertExpected(step, out);
        ObjectNode detail = out.json();
        detail.put("name", step.path("name").asText());
        steps.add(detail);
      }
      sequences.add(record);
      if (sequence.path("benchmark").asBoolean(false)) {
        for (int i = 0; i < warmup; i++) {
          MemoryRepository warmedState = baseline.child();
          for (JsonNode step : sequence.path("steps")) {
            assertExpected(step, runCase(warmedState, step, diagnosticBudget));
          }
        }
        ObjectNode diagnostic = benchmarkSequence(baseline, sequence, diagnosticBudget, samples);
        require(diagnostic.get("abortedSequences").asInt() == 0, "Diagnostic sequence timed out");
        sequenceBenchmarks.add(diagnostic);
        sequenceBenchmarks.add(benchmarkSequence(baseline, sequence, budget, samples));
      }
    }
    output.put("qualification", "Isolated TVM bytecode execution only; fixture scope applies. "
        + "No transaction admission, block production, persistent database, token transfer, "
        + "real-network parameters, or mainnet settlement qualification.");
    JSON.writerWithDefaultPrettyPrinter().writeValue(new File(args[1]), output);
    System.out.println("TVM_BYTECODE_CASES=" + checked.size());
    System.out.println("TVM_STATE_SEQUENCES=" + sequences.size());
    for (JsonNode timing : timings) {
      ObjectNode summary = ((ObjectNode) timing).deepCopy();
      summary.remove("raw");
      System.out.println("TVM_BENCHMARK=" + JSON.writeValueAsString(summary));
    }
    for (JsonNode timing : sequenceBenchmarks) {
      ObjectNode summary = ((ObjectNode) timing).deepCopy();
      for (JsonNode step : summary.get("steps")) ((ObjectNode) step).remove("raw");
      System.out.println("TVM_SEQUENCE_BENCHMARK=" + JSON.writeValueAsString(summary));
    }
    System.out.println("RESULTS=" + args[1]);
  }
}
