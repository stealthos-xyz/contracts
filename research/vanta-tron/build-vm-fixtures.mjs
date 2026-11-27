// Exact TVM bytecode + reproducible algebraic test inputs. No network or real proving keys.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { AbiCoder, Interface, keccak256, toUtf8Bytes } from 'ethers';
import { compile, compilerSha256 } from './compiler.mjs';
import { bundle as construct, keys, scalar, point1, wrongSubgroupPoint, FR, FQ } from './fixtures/constructed-bundle.mjs';

assert(process.argv[2], 'Usage: node build-vm-fixtures.mjs /path/to/tron-solc [output.json]');
const outputPath = resolve(process.argv[3] || 'out/constructed-tvm.json');
const compiled = compile(process.argv[2], [
  'contracts/src/vanta/VantaFamilyFullBundleVerifierPreAudit.sol',
  'research/vanta-tron/staged/VantaStagedReceiptResearch.sol',
  'research/vanta-tron/fixtures/ResearchStateChecker.sol',
]);
const abi = AbiCoder.defaultAbiCoder();
const address = suffix => '0x' + BigInt(suffix).toString(16).padStart(40, '0');
const ids = {
  gate0: address(0x100), caulk: address(0x101), link: address(0x102), full: address(0x103),
  stages: address(0x104), state: address(0x105), adapter8: address(0x108), adapter32: address(0x120), alias: address(0x109),
};
const OWNER = address(0xaa), OTHER = address(0xbb);
const CHAIN_ID = 0x56545233n, NOW = 1_800_000_000;
const DOMAIN = keccak256(toUtf8Bytes('STEALTHOS_VANTA_TRON_STAGED_RESEARCH_V1'));
const hash = text => keccak256(toUtf8Bytes(text));
const contracts = [];
const interfaces = {};
function deploy(id, name, args = []) {
  const matches = Object.values(compiled).map(x => x[name]).filter(Boolean);
  assert.equal(matches.length, 1, name);
  const artifact = matches[0], iface = new Interface(artifact.abi);
  interfaces[id] = iface;
  contracts.push({ name, address: ids[id], creation: '0x' + artifact.evm.bytecode.object + iface.encodeDeploy(args).slice(2) });
  return iface;
}
deploy('gate0', 'VantaFamilyGate0CcGroth16PreAudit');
deploy('caulk', 'VantaCaulkPlusGate1Research');
deploy('link', 'VantaCpLinkPairingResearch');
deploy('full', 'VantaFamilyFullBundleVerifierPreAudit', [ids.gate0, ids.caulk, ids.link]);
deploy('stages', 'VantaCaulkPlusStagedResearch', [ids.caulk]);
deploy('state', 'ResearchStateChecker', [OWNER]);
const receiptArtifact = Object.values(compiled).find(x => x.VantaStagedReceiptResearch).VantaStagedReceiptResearch;
const receiptAbi = new Interface(receiptArtifact.abi);
const bundleType = receiptAbi.getFunction('sessionIdFor').inputs[0];
const intentType = receiptAbi.getFunction('sessionIdFor').inputs[1];
const vkType = bundleType.components[0].components[0];
const srsType = bundleType.components[1].components[1];
const tableType = bundleType.components[1].components[0];
const g2Type = bundleType.components[2].components[1];

const family = {};
for (const arity of [8, 32]) {
  const id = 'adapter' + arity, key = keys('family' + arity), familyTag = scalar('familyTag' + arity);
  const config = keccak256(abi.encode(['uint8', 'uint256', vkType, srsType, g2Type, g2Type, g2Type],
    [arity, familyTag, key.vk, key.srs, key.link.a2, key.link.c1, key.link.c2]));
  deploy(id, 'VantaStagedReceiptResearch', [ids.gate0, ids.stages, ids.link, ids.state, config, arity, familyTag]);
  family[arity] = { id, arity, key, familyTag, config };
}
deploy('alias', 'VantaStagedReceiptResearch', [ids.gate0, ids.stages, ids.link, ids.state, family[8].config, 8, family[8].familyTag]);

function researchProof(arity, changes = {}, proofSuffix = '') {
  const f = family[arity];
  const intent = { actionHash: hash('action:' + arity), checkpoint: hash('checkpoint:' + arity),
    nullifier: hash('replay-key:' + arity), expiresAt: NOW + 3600, ...changes };
  const prefixTypes = ['bytes32', 'uint256', 'address', 'bytes32', 'uint8', 'uint256', intentType];
  const prefix = [DOMAIN, CHAIN_ID, ids[f.id], f.config, arity, f.familyTag, intent];
  const statement = BigInt(keccak256(abi.encode(prefixTypes, prefix))) % FR;
  const publicInputs = [statement, 150n, 350n, scalar('amount:' + arity), f.familyTag, CHAIN_ID];
  const inputsHash = keccak256(abi.encode(['uint256[6]'], [publicInputs]));
  const context = abi.encode([...prefixTypes, 'bytes32'], [...prefix, inputsHash]);
  const built = construct('family' + arity + proofSuffix, f.key, publicInputs, context, arity);
  const session = keccak256(abi.encode([...prefixTypes, 'bytes32'], [...prefix,
    keccak256(abi.encode([bundleType], [built.data]))]));
  const snapshot = keccak256(abi.encode(Array(7).fill('bytes32'), [session, f.config,
    intent.actionHash, intent.checkpoint, intent.nullifier,
    keccak256(abi.encode([tableType], [built.data.g1.table])), inputsHash]));
  return { ...built, f, intent, session, snapshot, statement, context };
}
const valid = { 8: researchProof(8), 32: researchProof(32) };
const cases = [], sequences = [];
function call(name, id, fn, args, returns = [], options = {}) {
  return { name, to: ids[id], data: interfaces[id].encodeFunctionData(fn, args),
    expected: { status: 'success', returnData: interfaces[id].encodeFunctionResult(fn, returns) }, ...options };
}
function rejected(name, id, fn, args, error, options = {}) {
  return { name, to: ids[id], data: interfaces[id].encodeFunctionData(fn, args),
    expected: { status: 'revert', ...(error ? { returnData: interfaces[id].encodeErrorResult(error) } : {}) }, ...options };
}
const stage = (p, index, name = 'stage-' + index, options = {}) => call(name, p.f.id, 'submitStage', [index, p.data, p.intent], [p.session], options);
const receipt = (p, mask, finalized = false, expiry = p.intent.expiresAt) => call('receipt-' + mask + '-' + finalized,
  p.f.id, 'receipts', [p.session], [expiry, mask, finalized]);
const approve = (p, enabled = true) => call(enabled ? 'approve-current-snapshot' : 'revoke-snapshot', 'state',
  'setCurrent', [p.snapshot, enabled], [], { caller: OWNER });
const finish = p => call('atomic-research-finalization', p.f.id, 'finalize', [p.data, p.intent], [p.session]);

for (const arity of [8, 32]) {
  const p = valid[arity], { g0, g1, link } = p.data;
  cases.push(call('constructed-family' + arity + '-gate0', 'gate0', 'verifyFamily', [g0.vk, g0.proof, g0.publicInputs], [true], { benchmark: true }));
  cases.push(call('constructed-family' + arity + '-caulk', 'caulk', 'verifyResearchForArity', [arity, g1.table, g1.srs, g1.proof, g1.context], [true], { benchmark: true }));
  cases.push(call('constructed-family' + arity + '-cp-link', 'link', 'verifyResearch', [link.pi, g0.proof.d, g1.table.query, link.a2, link.c1, link.c2], [true], { benchmark: true }));
  cases.push(call('constructed-family' + arity + '-full', 'full', 'verifyV8ResearchBundle', [arity, g0, g1, link], [true], { benchmark: true }));
  cases.push(call('exact-original-transcript-' + arity, 'caulk', 'deriveChallengesForArity', [arity, g1.table, g1.proof, g1.context], p.challenges));
  cases.push(call('statement-binding-' + arity, p.f.id, 'statementFor', [p.intent], [p.statement]));
  cases.push(call('context-binding-' + arity, p.f.id, 'contextFor', [g0.publicInputs, p.intent], [p.context]));
  cases.push(call('session-binding-' + arity, p.f.id, 'sessionIdFor', [p.data, p.intent], [p.session]));
  cases.push(call('configuration-binding-' + arity, p.f.id, 'configurationHashFor', [p.data], [p.f.config]));
  for (let eq = 0; eq < 4; eq++) {
    cases.push(call('constructed-family' + arity + '-caulk-equation' + eq, 'stages', 'verifyEquation',
      [eq, arity, g1.table, g1.srs, g1.proof, g1.context], [true], { benchmark: true }));
    const bad = structuredClone(g1.proof);
    if (eq < 3) bad['pi' + (eq + 1)] = point1(scalar('invalid-pi-' + eq));
    else bad.zI = point1(scalar('invalid-zi'));
    cases.push(call('invalid-equation-' + arity + '-' + eq, 'stages', 'verifyEquation',
      [eq, arity, g1.table, g1.srs, bad, g1.context], [false]));
  }
  sequences.push({ name: 'staged-family' + arity + '-success', benchmark: true,
    steps: [approve(p), ...[0, 1, 2, 3, 4, 5].map(x => stage(p, x)), finish(p), receipt(p, 63, true)] });
}

// High-input fee Gate0 and singleton Caulk use the real Solidity equations but synthetic public vectors.
for (const count of [40, 41]) {
  const key = keys('fee' + count, count);
  const signals = Array.from({ length: count }, (_, i) => i === 0 ? CHAIN_ID : scalar('fee:' + count + ':' + i));
  const p = construct('fee' + count, key, signals, '0x' + Buffer.from('constructed-fee-only').toString('hex'), 1);
  const { g0, g1, link } = p.data;
  cases.push(call('constructed-fee' + count + '-gate0', 'gate0', 'verifyFee', [g0.vk, g0.proof, signals], [true], { benchmark: true }));
  cases.push(call('constructed-fee' + count + '-singleton-caulk', 'caulk', 'verifySingletonResearch',
    [g1.table, g1.srs, g1.proof, g1.context], [true], { benchmark: true }));
  cases.push(call('constructed-fee' + count + '-cp-link', 'link', 'verifyResearch',
    [link.pi, g0.proof.d, g1.table.query, link.a2, link.c1, link.c2], [true]));
}

const p = valid[8], { g0, g1, link } = p.data;
const subgroup = wrongSubgroupPoint();
const subgroupFailure = { expected: { status: 'error', returnData: '0x', errorContains: 'Program$OutOfEnergyException' } };
// Version-0 TVM forwards the full allowance: malformed precompile input fails closed
// but can exhaust Energy before the original wrapper can return false.
cases.push(call('reject-correct-curve-wrong-subgroup', 'link', 'verifyResearch',
  [link.pi, g0.proof.d, g1.table.query, subgroup, link.c1, link.c2], [false], subgroupFailure));
cases.push(call('reject-wrong-subgroup-even-with-g1-infinity', 'gate0', 'verifyFamily',
  [g0.vk, { ...g0.proof, a: { x: 0n, y: 0n }, b: subgroup }, g0.publicInputs], [false], subgroupFailure));
const badField = { ...g0.proof, a: { x: FQ, y: 2n } };
cases.push(call('reject-noncanonical-coordinate', 'gate0', 'verifyFamily', [g0.vk, badField, g0.publicInputs], [false]));
const badInputs = [...g0.publicInputs]; badInputs[1] = FR;
cases.push(call('reject-noncanonical-scalar', 'gate0', 'verifyFamily', [g0.vk, g0.proof, badInputs], [false]));
const badLink = { ...p.data.link, pi: point1(scalar('wrong-link')) };
cases.push(call('reject-wrong-full-bundle-link', 'full', 'verifyV8ResearchBundle', [8, g0, g1, badLink], [false]));
cases.push(rejected('cannot-finalize-without-receipts', p.f.id, 'finalize', [p.data, p.intent], 'IncompleteSession'));
cases.push(rejected('invalid-stage', p.f.id, 'submitStage', [6, p.data, p.intent], 'InvalidStage'));
cases.push(rejected('cross-adapter-replay', 'alias', 'submitStage', [0, p.data, p.intent], 'InvalidBundle'));
cases.push(rejected('expired-intent', p.f.id, 'submitStage', [0, p.data, p.intent], 'ExpiredSession', { timestamp: p.intent.expiresAt }));
cases.push(rejected('excessive-expiry', p.f.id, 'submitStage', [0, p.data, { ...p.intent, expiresAt: NOW + 86401 }], 'InvalidIntent'));
for (const field of ['actionHash', 'checkpoint', 'nullifier']) {
  cases.push(rejected('intent-substitution-' + field, p.f.id, 'submitStage',
    [0, p.data, { ...p.intent, [field]: hash('substituted-' + field) }], 'InvalidBundle'));
}
for (const [name, mutate] of [
  ['key', b => { b.g0.vk.ic[0] = point1(scalar('substitute-key')); }],
  ['context', b => { b.g1.context += '00'; }],
  ['chain', b => { b.g0.publicInputs[5] += 1n; }],
  ['family', b => { b.g0.publicInputs[4] += 1n; }],
]) {
  const changed = structuredClone(p.data); mutate(changed);
  cases.push(rejected('bundle-substitution-' + name, p.f.id, 'submitStage', [0, changed, p.intent], 'InvalidBundle'));
}
const falseProof = structuredClone(p.data); falseProof.g0.proof.c = point1(scalar('wrong-groth16-c'));
cases.push(rejected('invalid-proof-cannot-record-stage', p.f.id, 'submitStage', [0, falseProof, p.intent], 'VerificationFailed'));
cases.push(rejected('unauthorized-snapshot-update', 'state', 'setCurrent', [p.snapshot, true], null, { caller: OTHER }));

sequences.push({ name: 'duplicate-stage-is-idempotent', steps: [stage(p, 0), receipt(p, 1), stage(p, 0, 'duplicate-stage'), receipt(p, 1)] });
sequences.push({ name: 'missing-stage-cannot-finalize', steps: [approve(p), ...[0, 1, 2, 3, 4].map(x => stage(p, x)),
  rejected('reject-incomplete', p.f.id, 'finalize', [p.data, p.intent], 'IncompleteSession'), receipt(p, 31)] });
sequences.push({ name: 'revoked-snapshot-cannot-finalize', steps: [approve(p), ...[0, 1, 2, 3, 4, 5].map(x => stage(p, x)), approve(p, false),
  rejected('reject-stale-state', p.f.id, 'finalize', [p.data, p.intent], 'StaleState'), receipt(p, 63)] });
const alternate = researchProof(8, {}, ':alternate-proof');
sequences.push({ name: 'snapshot-for-another-session-cannot-authorize-finalization', steps: [
  approve(p), ...[0, 1, 2, 3, 4, 5].map(x => stage(alternate, x)),
  rejected('reject-other-session-snapshot', p.f.id, 'finalize', [alternate.data, alternate.intent], 'StaleState'),
  receipt(alternate, 63),
] });
sequences.push({ name: 'cannot-mix-receipts-from-different-proofs', steps: [
  ...[0, 1, 2].map(x => stage(p, x)), ...[3, 4, 5].map(x => stage(alternate, x)),
  rejected('reject-mixed-session', p.f.id, 'finalize', [p.data, p.intent], 'IncompleteSession'),
  receipt(p, 7), receipt(alternate, 56),
] });
const reusedAction = researchProof(8, { nullifier: hash('second-replay-key') });
const reusedNullifier = researchProof(8, { actionHash: hash('second-action') });
sequences.push({ name: 'finalization-and-pruning-preserve-replay-protection', steps: [
  approve(p), ...[0, 1, 2, 3, 4, 5].map(x => stage(p, x)), finish(p),
  rejected('double-finalize', p.f.id, 'finalize', [p.data, p.intent], 'AlreadyFinalized'),
  rejected('action-reuse', p.f.id, 'submitStage', [0, reusedAction.data, reusedAction.intent], 'AlreadyFinalized'),
  rejected('nullifier-reuse', p.f.id, 'submitStage', [0, reusedNullifier.data, reusedNullifier.intent], 'AlreadyFinalized'),
  call('prune-expired-receipt', p.f.id, 'pruneExpired', [p.session], [], { timestamp: p.intent.expiresAt + 1 }),
  receipt(p, 0, false, 0),
  call('action-tombstone-remains', p.f.id, 'usedActions', [p.intent.actionHash], [true]),
  call('nullifier-tombstone-remains', p.f.id, 'usedNullifiers', [p.intent.nullifier], [true]),
] });
sequences.push({ name: 'expired-stages-cannot-finalize', steps: [
  approve(p), ...[0, 1, 2, 3, 4, 5].map(x => stage(p, x)),
  rejected('expired-finalization', p.f.id, 'finalize', [p.data, p.intent], 'ExpiredSession', { timestamp: p.intent.expiresAt }), receipt(p, 63),
] });

// A stateful sequence never moves block time backwards after an expiry step.
for (const sequence of sequences) {
  let timestamp = NOW;
  for (const step of sequence.steps) {
    if (step.timestamp !== undefined) assert(step.timestamp >= timestamp, 'Sequence time moved backwards');
    timestamp = step.timestamp ?? timestamp;
    step.timestamp = timestamp;
  }
}

const output = {
  schemaVersion: 1, scope: 'constructed-algebraic-fixtures-not-R1CS-or-STREAM_BOUND4',
  provenance: { compilerSha256, originalSourceCommit: 'ed1d4411e010d5bd2d2935f569851382fe639719',
    setup: 'public deterministic scalar construction, unsafe for funds', browserQualification: false,
    liveNetworkParameters: false, coversProductionSettlement: false },
  genesisHash: '0x' + CHAIN_ID.toString(16).padStart(64, '0'), timestamp: NOW, blockNumber: 1,
  contracts, cases, sequences,
  benchmark: { warmup: 10, samples: 30, budgetMs: 80, diagnosticBudgetMs: 5000 },
};
const json = JSON.stringify(output, (_, value) => typeof value === 'bigint' ? value.toString() : value, 2) + '\n';
mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, json);
console.log(JSON.stringify({ outputPath, contracts: contracts.length, cases: cases.length,
  sequences: sequences.length, sha256: createHash('sha256').update(json).digest('hex'), scope: output.scope }));
