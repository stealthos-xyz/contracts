import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve, posix } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = fileURLToPath(new URL('../../', import.meta.url));
export const compilerSha256 = '98a0df6518346d07f13ec151f64bed48f4df9dd01fbfd81018f9485a374f8edd';

/** Compile only explicitly selected entries and their imports; production blobs stay pinned. */
export function compile(binaryPath, entryPaths) {
  const binary = resolve(binaryPath);
  assert.equal(createHash('sha256').update(readFileSync(binary)).digest('hex'), compilerSha256, 'compiler hash mismatch');
  const manifest = JSON.parse(readFileSync(resolve(root, 'SOURCE_MANIFEST.json'), 'utf8'));
  const sources = {};
  function load(path) {
    assert(!path.startsWith('../') && !posix.isAbsolute(path), 'source outside repository');
    if (sources[path]) return;
    const bytes = readFileSync(resolve(root, path));
    if (path.startsWith('contracts/')) {
      const blob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
      assert.equal(blob, manifest.files[path]?.gitBlobSha, `production source drift: ${path}`);
    }
    const content = bytes.toString('utf8');
    sources[path] = { content };
    for (const match of content.matchAll(/import\s+(?:[^;]*?from\s+)?["']([^"']+)["']\s*;/g)) {
      assert(match[1].startsWith('.'), 'external imports are outside this isolated probe');
      load(posix.normalize(posix.join(posix.dirname(path), match[1])));
    }
  }
  entryPaths.forEach(load);
  const input = { language: 'Solidity', sources, settings: {
    optimizer: { enabled: true, runs: 1 }, viaIR: true, evmVersion: 'cancun',
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object'] } },
  } };
  const result = spawnSync(binary, ['--standard-json'], {
    input: JSON.stringify(input), encoding: 'utf8', timeout: 180000, maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr || 'compiler failed');
  const output = JSON.parse(result.stdout);
  const errors = (output.errors || []).filter(x => x.severity === 'error');
  assert.equal(errors.length, 0, errors.map(x => x.formattedMessage).join('\n'));
  return output.contracts;
}
