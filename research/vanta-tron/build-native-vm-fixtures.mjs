// Public verifier inputs from private native generation; no private engine or witnesses.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { Interface } from 'ethers';
import { compile, compilerSha256 } from './compiler.mjs';

const [compiler, outputArg, ...directories] = process.argv.slice(2);
assert.ok(compiler && outputArg && directories.length,
  'Usage: build-native-vm-fixtures.mjs TRON_SOLC OUTPUT_JSON PUBLIC_FIXTURE_DIRECTORY...');
const outputPath = resolve(outputArg);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const expectedCases = ['normal8', 'normal32', 'kzg-combined-deposit',
  'kzg-combined-withdrawal8', 'kzg-combined-withdrawal32',
  'kzg-combined-private-send8', 'kzg-combined-private-send32', 'kzg-enhanced8', 'kzg-enhanced32'];
const fixtures = new Map(), inventories = [];

for (const directory of directories) {
  const path = resolve(directory), manifestBytes = readFileSync(join(path, 'manifest.json'));
  const manifest = JSON.parse(manifestBytes);
  assert.equal(manifest.schema, 'vanta-tron-public-fixture-inventory-v1');
  assert.equal(manifest.researchOnly, true); assert.equal(manifest.safeForFunds, false);
  assert.equal(manifest.browserQualification, false); assert.equal(manifest.tvmQualified, false);
  assert.match(manifest.sourceRevision, /^[0-9a-f]{40}$/u);
  assert.ok(Array.isArray(manifest.fixtures) && manifest.fixtures.length > 0);
  const inventory = { manifestSha256: hash(manifestBytes), sourceRevision: manifest.sourceRevision, files: [] };
  for (const entry of manifest.fixtures) {
    assert.equal(basename(entry.file), entry.file);
    assert.match(entry.file, /^[a-z0-9-]+\.json$/u);
    const bytes = readFileSync(join(path, entry.file));
    assert.equal(bytes.length, entry.bytes); assert.equal(hash(bytes), entry.sha256);
    const fixture = JSON.parse(bytes);
    assert.equal(fixture.schema, 'vanta-tron-public-verifier-fixture-v1');
    assert.equal(entry.file, fixture.caseId + '.json');
    assert.ok(expectedCases.includes(fixture.caseId));
    assert.ok(!fixtures.has(fixture.caseId), 'Duplicate case: ' + fixture.caseId);
    assert.equal(fixture.researchOnly, true); assert.equal(fixture.safeForFunds, false);
    assert.equal(fixture.browserQualification, false); assert.equal(fixture.tvmQualified, false);
    assert.equal(fixture.generation, 'native-current-source-disposable-setup');
    assert.ok([31337, 6281971].includes(fixture.domain.sourceChainId), 'Unsupported isolated native qualification domain.');
    assert.equal(fixture.provenance.sourceRevision, manifest.sourceRevision);
    const note = fixture.caseId.startsWith('normal');
    const inputs = note ? 6 : fixture.caseId.startsWith('kzg-enhanced') ? 41 : 40;
    const arity = note ? Number(fixture.caseId.slice(6)) : 1;
    assert.equal(fixture.gate0.inputs.length, inputs); assert.equal(entry.publicInputs, inputs);
    assert.equal(fixture.gate0.vk.ic.length, inputs + 1);
    assert.equal(fixture.gate1.arity, arity); assert.equal(entry.lookupArity, arity);
    assert.deepEqual(fixture.cpLink.d, fixture.gate0.proof.d);
    assert.deepEqual(fixture.cpLink.e, fixture.gate1.table.query);
    fixtures.set(fixture.caseId, fixture);
    inventory.files.push({ file: entry.file, bytes: bytes.length, sha256: entry.sha256 });
  }
  inventories.push(inventory);
}
assert.equal(new Set(inventories.map(value => value.sourceRevision)).size, 1,
  'All profiles must originate from the same private source revision.');

assert.equal(new Set([...fixtures.values()].map(value => value.domain.sourceChainId)).size, 1,
  'Use separate TVM replays for different source domains.');

const compiled = compile(compiler, [
  'contracts/src/vanta/VantaFamilyFullBundleVerifierPreAudit.sol',
  'research/vanta-tron/staged/VantaCaulkPlusStagedResearch.sol',
]);
const address = value => '0x' + BigInt(value).toString(16).padStart(40, '0');
const ids = { gate0: address(0x200), caulk: address(0x201), link: address(0x202),
  full: address(0x203), stages: address(0x204) };
const contracts = [], interfaces = {}, cases = [];
function deploy(id, name, args = []) {
  const matches = Object.values(compiled).map(file => file[name]).filter(Boolean);
  assert.equal(matches.length, 1, name);
  const artifact = matches[0], iface = new Interface(artifact.abi);
  interfaces[id] = iface;
  contracts.push({ name, address: ids[id],
    creation: '0x' + artifact.evm.bytecode.object + iface.encodeDeploy(args).slice(2) });
}
deploy('gate0', 'VantaFamilyGate0CcGroth16PreAudit');
deploy('caulk', 'VantaCaulkPlusGate1Research');
deploy('link', 'VantaCpLinkPairingResearch');
deploy('full', 'VantaFamilyFullBundleVerifierPreAudit', [ids.gate0, ids.caulk, ids.link]);
deploy('stages', 'VantaCaulkPlusStagedResearch', [ids.caulk]);

function call(name, id, fn, args, accepted, benchmark = false) {
  cases.push({ name, to: ids[id], data: interfaces[id].encodeFunctionData(fn, args),
    expected: { status: 'success', returnData: interfaces[id].encodeFunctionResult(fn, [accepted]) }, benchmark });
}
function neg(point) {
  const y = BigInt(point.y);
  assert.ok(y !== 0n, 'Negation must change a valid proof point.');
  return { ...point, y: '0x' + (FQ - y).toString(16).padStart(64, '0') };
}
function bundle(fixture) {
  const { gate0, gate1, cpLink } = fixture;
  return { g0: { vk: gate0.vk, proof: gate0.proof, publicInputs: gate0.inputs },
    g1: { table: gate1.table, srs: gate1.srs, proof: gate1.proof, context: gate1.context },
    link: { pi: cpLink.pi, a2: cpLink.a2, c1: cpLink.c1, c2: cpLink.c2 } };
}

for (const [caseId, fixture] of fixtures) {
  const { gate0: a, gate1: b, cpLink: c } = fixture;
  const note = b.arity !== 1, gate0Method = note ? 'verifyFamily' : 'verifyFee';
  const gate1Method = note ? 'verifyResearchForArity' : 'verifySingletonResearch';
  const gate1Args = proof => note ? [b.arity, b.table, b.srs, proof, b.context]
    : [b.table, b.srs, proof, b.context];
  const name = 'native-' + caseId;
  call(name + '-gate0', 'gate0', gate0Method, [a.vk, a.proof, a.inputs], true, true);
  call(name + '-caulk', 'caulk', gate1Method, gate1Args(b.proof), true, true);
  call(name + '-cp-link', 'link', 'verifyResearch', [c.pi, c.d, c.e, c.a2, c.c1, c.c2], true, true);
  if (note) {
    const p = bundle(fixture);
    call(name + '-full', 'full', 'verifyV8ResearchBundle', [b.arity, p.g0, p.g1, p.link], true, true);
  }
  for (let eq = 0; eq < 4; eq++) {
    call(name + '-caulk-equation' + eq, 'stages', 'verifyEquation',
      [eq, b.arity, b.table, b.srs, b.proof, b.context], true, true);
    const corrupted = structuredClone(b.proof);
    const field = eq < 3 ? 'pi' + (eq + 1) : 'zI';
    corrupted[field] = neg(corrupted[field]);
    call(name + '-reject-equation' + eq + '-valid-point-negation', 'stages', 'verifyEquation',
      [eq, b.arity, b.table, b.srs, corrupted, b.context], false);
  }
  call(name + '-reject-gate0-valid-point-negation', 'gate0', gate0Method,
    [a.vk, { ...a.proof, a: neg(a.proof.a) }, a.inputs], false);
  call(name + '-reject-caulk-valid-point-negation', 'caulk', gate1Method,
    gate1Args({ ...b.proof, pi1: neg(b.proof.pi1) }), false);
  call(name + '-reject-link-valid-point-negation', 'link', 'verifyResearch',
    [neg(c.pi), c.d, c.e, c.a2, c.c1, c.c2], false);
  call(name + '-reject-link-D-splice', 'link', 'verifyResearch',
    [c.pi, neg(c.d), c.e, c.a2, c.c1, c.c2], false);
  call(name + '-reject-link-E-splice', 'link', 'verifyResearch',
    [c.pi, c.d, neg(c.e), c.a2, c.c1, c.c2], false);
  assert.ok(b.context.length > 2);
  const mutatedContext = '0x' + (Number.parseInt(b.context.slice(2, 4), 16) ^ 1).toString(16).padStart(2, '0') + b.context.slice(4);
  const wrongContext = gate1Args(b.proof); wrongContext[wrongContext.length - 1] = mutatedContext;
  call(name + '-reject-changed-context', 'caulk', gate1Method, wrongContext, false);
  const changedInputs = [...a.inputs]; changedInputs[0] = (BigInt(changedInputs[0]) + 1n) % FR;
  call(name + '-reject-changed-public-input', 'gate0', gate0Method, [a.vk, a.proof, changedInputs], false);
}

// Both substituted individual gates remain genuine and valid. The original link
// must reject another note proof's D or E when the full verifier wires them in.
const crossGateSplices = fixtures.has('normal8') && fixtures.has('normal32');
if (crossGateSplices) {
  for (const [original, other] of [['normal8', 'normal32'], ['normal32', 'normal8']]) {
    const first = fixtures.get(original), second = fixtures.get(other);
    const p = bundle(first), q = bundle(second);
    assert.notDeepEqual(p.g0.proof.d, q.g0.proof.d);
    assert.notDeepEqual(p.g1.table.query, q.g1.table.query);
    call('native-' + original + '-full-reject-cross-gate-D-splice', 'full', 'verifyV8ResearchBundle',
      [first.gate1.arity, q.g0, p.g1, p.link], false);
    call('native-' + original + '-full-reject-cross-gate-E-splice', 'full', 'verifyV8ResearchBundle',
      [second.gate1.arity, p.g0, q.g1, p.link], false);
  }
}

const output = {
  schemaVersion: 1, scope: 'genuine-native-DogeOS-family-arithmetic-on-isolated-TVM-not-TRON-family-or-STREAM_BOUND4-or-settlement',
  provenance: { compilerSha256, inventories,
    setup: 'Fresh disposable native setup; no user keys or production artifacts.',
    domainScope: 'Existing DogeOS-family qualification proofs with isolated local genesis. No TRON family proof, cross-family reuse or activation.',
    browserQualification: false, coversProductionSettlement: false, coversReceiptAdapter: false,
    liveNetworkParameters: false },
  coverage: { cases: [...fixtures.keys()], completeNativeCorpus: fixtures.size === expectedCases.length,
    missingCases: expectedCases.filter(id => !fixtures.has(id)), crossGateSplices },
  genesisHash: '0x' + BigInt(fixtures.values().next().value.domain.sourceChainId).toString(16).padStart(64, '0'), timestamp: 1_800_000_000,
  blockNumber: 1, contracts, cases, sequences: [],
  benchmark: { warmup: 10, samples: 30, budgetMs: 80, diagnosticBudgetMs: 5000 },
};
const json = JSON.stringify(output, (_, value) => typeof value === 'bigint' ? value.toString() : value, 2) + '\n';
mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, json, { flag: 'wx' });
console.log(JSON.stringify({ outputPath, contracts: contracts.length, cases: cases.length,
  sha256: hash(json), scope: output.scope, coverage: output.coverage }));
