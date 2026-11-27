import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';

// Direct arithmetic comparison only. Never replaces VM, VMConfig or PrecompiledContracts.
const here = dirname(fileURLToPath(import.meta.url));
const [jarArg, javacArg, outputArg] = process.argv.slice(2);
assert(jarArg && javacArg && outputArg,
  'Usage: node prepare-optimized-bn128.mjs FullNode.jar /path/to/javac work-directory');
assert(isAbsolute(javacArg), 'Use an explicit JDK 8 javac path');
const jar = resolve(jarArg);
const output = resolve(outputArg);
const manifest = JSON.parse(await readFile(join(here, 'optimized-bn128-pins.json'), 'utf8'));
assert.equal(manifest.schemaVersion, 1);
assert.match(manifest.commit, /^[0-9a-f]{40}$/);
assert.equal(manifest.repository, 'yanghang8612/java-tron');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
assert.equal(sha256(await readFile(jar)), manifest.baseRuntime.jarSha256,
  'Released java-tron JAR does not match the pinned runtime');
await mkdir(output, { recursive: true });
const sources = join(output, 'source');
const classes = join(output, 'classes');
await mkdir(classes, { recursive: true });
const downloaded = [];
for (let offset = 0; offset < manifest.files.length; offset += 4) {
  const batch = manifest.files.slice(offset, offset + 4);
  const results = await Promise.allSettled(batch.map(async (entry) => {
    assert(!entry.path.includes('..') && !isAbsolute(entry.path), 'Invalid source path');
    const target = join(sources, entry.path);
    let bytes;
    try { bytes = await readFile(target); } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (!bytes || sha256(bytes) !== entry.sha256) {
      const url = `https://raw.githubusercontent.com/${manifest.repository}/${manifest.commit}/${entry.path}`;
      const response = await fetch(url, { signal: AbortSignal.timeout(60000) });
      assert(response.ok, `Download failed: ${entry.path}, HTTP ${response.status}`);
      bytes = Buffer.from(await response.arrayBuffer());
    }
    assert.equal(sha256(bytes), entry.sha256, `SHA-256 mismatch: ${entry.path}`);
    const blob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    assert.equal(blob, entry.gitBlobSha1, `Git blob mismatch: ${entry.path}`);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, bytes);
    return target;
  }));
  for (const result of results) {
    if (result.status === 'rejected') throw result.reason;
    downloaded.push(result.value);
  }
}
const javaSources = downloaded.filter((path) => path.endsWith('.java'));
javaSources.push(join(here, 'OptimizedBn128Probe.java'));
const compiled = spawnSync(javacArg,
  ['-proc:none', '-cp', jar, '-d', classes, ...javaSources],
  { encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024 });
if (compiled.stdout) process.stdout.write(compiled.stdout);
if (compiled.stderr) process.stderr.write(compiled.stderr);
assert.equal(compiled.status, 0, `Candidate compilation failed: ${compiled.error?.message ?? ''}`);
async function checkOutput(directory, prefix = '') {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const relative = prefix + entry.name;
    if (entry.isDirectory()) await checkOutput(join(directory, entry.name), `${relative}/`);
    else assert(entry.isFile() && (
      /^org\/tron\/common\/crypto\/zksnark\/optimized\/[A-Za-z0-9_$]+\.class$/.test(relative)
      || /^org\/tron\/core\/vm\/OptimizedBN128\.class$/.test(relative)
      || /^org\/tron\/core\/vm\/OptimizedBn128Probe(?:\$[A-Za-z0-9_$]+)?\.class$/.test(relative)
    ), `Unexpected classpath entry; refusing a possible runtime override: ${relative}`);
  }
}
await checkOutput(classes);
const report = {
  candidate: `${manifest.repository}@${manifest.commit}`,
  runtimeJarSha256: manifest.baseRuntime.jarSha256,
  compiledFiles: javaSources.length,
  classes,
  fixtures: join(sources, 'actuator/src/test/resources/bn128'),
  mainClass: 'org.tron.core.vm.OptimizedBn128Probe',
  optimizedTvmCompatible: false,
  reason: 'The candidate uses a separate adapter and returns failure on deadline expiry. '
    + 'Released TVM pairing throws OutOfTimeException. Only direct arithmetic is compared.',
};
await writeFile(join(output, 'build.json'), `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report));
