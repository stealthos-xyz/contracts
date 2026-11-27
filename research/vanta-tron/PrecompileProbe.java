// Research only: direct calls to the pinned java-tron precompiles.
// No node, network, wallet, contract deployment, or signing.
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.tuple.Pair;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;
import org.tron.core.vm.config.VMConfig;
import org.tron.core.vm.program.Program;

public final class PrecompileProbe {
    private static final BigInteger P = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
    private static final BigInteger R = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger[] G2 = {
        new BigInteger("11559732032986387107991004021392285783925812861821192530917403151452391805634"),
        new BigInteger("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
        new BigInteger("4082367875863433681332203403145435568316851327593401208105741076214120093531"),
        new BigInteger("8495653923123431417604973247489272438418190587263600148770280649306958101930")
    };
    private static final BigInteger X2 = new BigInteger("1368015179489954701390400359078579693043519447331113978918064868415326638035");
    private static final BigInteger Y2 = new BigInteger("9918110051302171585080402603319702774565515993150576347155970296011118125764");
    private static final PrecompiledContract ADD = new PrecompiledContracts.BN128Addition();
    private static final PrecompiledContract MUL = new PrecompiledContracts.BN128Multiplication();
    private static final PrecompiledContract PAIR = new PrecompiledContracts.BN128Pairing();

    private static byte[] words(BigInteger... values) {
        byte[] out = new byte[32 * values.length];
        for (int i = 0; i < values.length; i++) {
            BigInteger value = values[i];
            if (value.signum() < 0 || value.bitLength() > 256) throw new IllegalArgumentException("word range");
            byte[] bytes = value.toByteArray();
            int len = Math.min(32, bytes.length);
            System.arraycopy(bytes, bytes.length - len, out, (i + 1) * 32 - len, len);
        }
        return out;
    }

    private static byte[] concat(byte[]... arrays) {
        int size = 0;
        for (byte[] a : arrays) size = Math.addExact(size, a.length);
        byte[] out = new byte[size];
        int offset = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, out, offset, a.length);
            offset += a.length;
        }
        return out;
    }

    private static byte[] pair(BigInteger x, BigInteger y) {
        return concat(words(x, y), words(G2));
    }

    private static final class Fixture {
        final String name;
        final PrecompiledContract op;
        final byte[] input;
        final byte[] output; // null means the precompile must reject, not return false.
        Fixture(String name, PrecompiledContract op, byte[] input, byte[] output) {
            this.name = name;
            this.op = op;
            this.input = input;
            this.output = output;
        }
    }

    private static List<Fixture> fixtures() {
        byte[] positive = pair(ONE, TWO);
        byte[] negative = pair(ONE, P.subtract(TWO));
        byte[] negativeDouble = pair(X2, P.subtract(Y2));
        List<Fixture> f = new ArrayList<>();
        f.add(new Fixture("add-generator", ADD, words(ONE, TWO, ONE, TWO), words(X2, Y2)));
        f.add(new Fixture("add-inverse", ADD, words(ONE, TWO, ONE, P.subtract(TWO)), words(ZERO, ZERO)));
        f.add(new Fixture("add-out-of-field", ADD, words(P, TWO, ONE, TWO), null));
        f.add(new Fixture("mul-double", MUL, words(ONE, TWO, TWO), words(X2, Y2)));
        f.add(new Fixture("mul-order", MUL, words(ONE, TWO, R), words(ZERO, ZERO)));
        f.add(new Fixture("mul-zero", MUL, words(ONE, TWO, ZERO), words(ZERO, ZERO)));
        f.add(new Fixture("mul-off-curve", MUL, words(ONE, BigInteger.valueOf(3), ONE), null));
        f.add(new Fixture("pair-single-false", PAIR, positive, words(ZERO)));
        f.add(new Fixture("pair-two-cancel", PAIR, concat(positive, negative), words(ONE)));
        f.add(new Fixture("pair-three-cancel", PAIR, concat(positive, positive, negativeDouble), words(ONE)));
        f.add(new Fixture("pair-four-cancel", PAIR, concat(positive, negative, positive, negative), words(ONE)));
        f.add(new Fixture("pair-invalid-g2-limb", PAIR, words(ONE, TWO, P, G2[1], G2[2], G2[3]), null));
        f.add(new Fixture("pair-invalid-length", PAIR, words(ONE), null));
        f.add(new Fixture("mul-large", MUL, words(ONE, TWO, R.subtract(ONE)), words(ONE, P.subtract(TWO))));
        f.add(new Fixture("pair-swapped-limbs", PAIR, words(ONE, TWO, G2[1], G2[0], G2[3], G2[2]), null));
        return f;
    }

    private static Fixture named(List<Fixture> fixtures, String name) {
        for (Fixture f : fixtures) if (f.name.equals(name)) return f;
        throw new IllegalArgumentException(name);
    }

    private static void verify(Fixture f, long deadlineNs) {
        f.op.setVmShouldEndInUs(TimeUnit.NANOSECONDS.toMicros(deadlineNs));
        Pair<Boolean, byte[]> actual = f.op.execute(f.input);
        if (f.output == null) {
            if (actual.getLeft()) throw new AssertionError("invalid accepted: " + f.name);
        } else if (!actual.getLeft() || !Arrays.equals(f.output, actual.getRight())) {
            throw new AssertionError("wrong result: " + f.name);
        }
    }

    private static void repeat(List<Fixture> out, Fixture f, int count) {
        for (int i = 0; i < count; i++) out.add(f);
    }

    private static List<Fixture> schedule(List<Fixture> f, int gate) {
        List<Fixture> out = new ArrayList<>();
        Fixture mul = named(f, "mul-large"), add = named(f, "add-generator");
        if (gate == 0 || gate == 3) {
            repeat(out, mul, 6); repeat(out, add, 7);
            out.add(named(f, "pair-four-cancel"));
        }
        if (gate == 1 || gate == 3) {
            repeat(out, mul, 11); repeat(out, add, 11);
            repeat(out, named(f, "pair-two-cancel"), 4);
        }
        if (gate == 2 || gate == 3) out.add(named(f, "pair-three-cancel"));
        return out;
    }

    private static long energy(List<Fixture> schedule, boolean istanbul) {
        VMConfig.initAllowTvmIstanbul(istanbul ? 1 : 0);
        long total = 0;
        for (Fixture f : schedule) total += f.op.getEnergyForData(f.input);
        return total;
    }

    // Returns negative elapsed nanos if the shared deadline is exceeded.
    // A relaxed diagnostic deadline is not an acceptance run.
    private static long timed(List<Fixture> schedule, long budgetMs) {
        long start = System.nanoTime();
        long deadline = start + TimeUnit.MILLISECONDS.toNanos(budgetMs);
        try {
            for (Fixture f : schedule) {
                if (System.nanoTime() >= deadline) return -(System.nanoTime() - start);
                verify(f, deadline);
            }
        } catch (Program.OutOfTimeException timeout) {
            return -(System.nanoTime() - start);
        }
        long elapsed = System.nanoTime() - start;
        return System.nanoTime() >= deadline ? -elapsed : elapsed;
    }

    private static double ms(long nanos) { return Math.abs(nanos) / 1e6; }

    private static void bench(String name, List<Fixture> schedule, int runs, long budgetMs) {
        long[] elapsed = new long[runs];
        int missed = 0;
        for (int i = 0; i < runs; i++) {
            long t = timed(schedule, budgetMs);
            if (t < 0) missed++;
            elapsed[i] = Math.abs(t);
        }
        Arrays.sort(elapsed);
        System.out.printf(Locale.ROOT, "%s budget_ms=%d n=%d timeout=%d p50_ms=%.3f p95_ms=%.3f max_ms=%.3f%n",
            name, budgetMs, runs, missed, ms(elapsed[(runs - 1) / 2]),
            ms(elapsed[(int) Math.ceil(runs * 0.95) - 1]), ms(elapsed[runs - 1]));
        if (budgetMs > 80 && missed > 0) throw new AssertionError("diagnostic timed out: " + name);
    }

    public static void main(String[] args) {
        List<Fixture> f = fixtures();
        List<Fixture> bundle = schedule(f, 3);
        if (bundle.size() != 41 || energy(bundle, true) != 884700 || energy(bundle, false) != 2489000) {
            throw new AssertionError("unexpected precompile cost or operation count");
        }
        VMConfig.initAllowTvmIstanbul(1);
        long cold = timed(bundle, 80);
        System.out.printf(Locale.ROOT, "cold first bundle: %s %.3f ms%n", cold < 0 ? "TIMEOUT" : "PASS", ms(cold));
        for (Fixture fixture : f) {
            verify(fixture, System.nanoTime() + TimeUnit.SECONDS.toNanos(5));
            System.out.println("PASS " + fixture.name);
        }
        System.out.println("Native precompile fixtures: " + f.size() + "/" + f.size());
        for (int i = 0; i < 10; i++) {
            if (timed(bundle, 5000) < 0) throw new AssertionError("warmup timeout");
        }
        for (int gate = 0; gate < 3; gate++) bench("gate" + gate + "-synthetic", schedule(f, gate), 20, 5000);
        bench("bundle-diagnostic-synthetic", bundle, 100, 5000);
        bench("bundle-80ms-synthetic", bundle, 100, 80);
        System.out.println("SCOPE: real Java precompiles; synthetic inputs, no bytecode execution or settlement; not TVM qualification.");
    }
}
