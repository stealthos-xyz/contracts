import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const pins = [
  ['VantaFamilyGate0CcGroth16PreAudit.sol', '4f6c6ad21c1a162a3c36e910ce50677fdb665cb1'],
  ['VantaCaulkPlusGate1Research.sol', 'db550e581713cb63fc196442877b98028d2e4a80'],
  ['VantaCpLinkPairingResearch.sol', 'cb8a935d6e111e13523b49a0532124510fb91f59'],
];

await Promise.all(pins.map(async ([name, expected]) => {
  const source = await readFile(new URL(`../../../contracts/src/vanta/${name}`, import.meta.url));
  const actual = createHash('sha1')
    .update(`blob ${source.length}\0`)
    .update(source)
    .digest('hex');
  assert.equal(actual, expected, `${name}: reviewed source changed`);
}));

console.log('Staged research source pins: 3 unchanged original verifiers.');
