// Compile-only TVM research. No chain, RPC, wallet, deployment or publication.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const compiler = process.argv[2];
assert(compiler, 'Usage: node research/vanta-tron/compile-probe.mjs /absolute/path/to/tron-solc');
const binary = resolve(compiler);
const pin = '98a0df6518346d07f13ec151f64bed48f4df9dd01fbfd81018f9485a374f8edd';
assert.equal(createHash('sha256').update(readFileSync(binary)).digest('hex'), pin, 'compiler hash mismatch');
const manifest = JSON.parse(readFileSync(resolve(root, 'SOURCE_MANIFEST.json'), 'utf8'));
const names = [
  'VantaFamilyGate0CcGroth16PreAudit',
  'VantaCaulkPlusGate1Research',
  'VantaCpLinkPairingResearch',
  'VantaFamilyFullBundleVerifierPreAudit',
  'VantaFamilyReleaseBinding',
  'VantaFamilyPartnerKzgFeeVerifierPreAudit',
];
const sources = Object.fromEntries(names.map((name) => {
  const path = `contracts/src/vanta/${name}.sol`;
  const bytes = readFileSync(resolve(root, path));
  const blob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
  assert.equal(blob, manifest.files[path]?.gitBlobSha, `source hash mismatch: ${path}`);
  return [path, { content: bytes.toString('utf8') }];
}));
const run = (args, input) => {
  const result = spawnSync(binary, args, { input, encoding: 'utf8', timeout: 120000, maxBuffer: 32 * 1024 * 1024 });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr || 'compiler failed');
  return result.stdout;
};
const version = run(['--version']);
assert.match(version, /0\.8\.26/);
console.log(version.trim(), 'sha256=' + pin);
const input = {
  language: 'Solidity',
  sources,
  settings: {
    optimizer: { enabled: true, runs: 1 },
    viaIR: true,
    evmVersion: 'cancun',
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object'] } },
  },
};
const output = JSON.parse(run(['--standard-json'], JSON.stringify(input)));
const errors = (output.errors || []).filter((e) => e.severity === 'error');
for (const e of output.errors || []) console.log(e.formattedMessage || e.message);
assert.equal(errors.length, 0, 'TRON compiler errors');
for (const name of names.filter((n) => n !== 'VantaFamilyReleaseBinding')) {
  const contract = output.contracts?.[`contracts/src/vanta/${name}.sol`]?.[name];
  const bytecode = contract?.evm?.deployedBytecode?.object;
  assert(bytecode && /^[a-f0-9]+$/i.test(bytecode) && bytecode.length % 2 === 0, `missing or unlinked runtime: ${name}`);
  console.log(name, 'runtime_bytes=' + bytecode.length / 2, 'sha256=' + createHash('sha256').update(Buffer.from(bytecode, 'hex')).digest('hex'));
}
console.log('PASS compile-only, 5 concrete contracts; no TVM bytecode execution or deployment');
