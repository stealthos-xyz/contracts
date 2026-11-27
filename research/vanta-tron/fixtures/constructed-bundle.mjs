// Public, deterministic algebraic fixtures. NOT R1CS/STREAM_BOUND4 proofs or safe setup keys.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { bn254 } from '@noble/curves/bn254';

export const FQ = bn254.fields.Fp.ORDER;
export const FR = bn254.fields.Fr.ORDER;
const G1 = bn254.G1.ProjectivePoint;
const G2 = bn254.G2.ProjectivePoint;
const domain = Buffer.from('STEALTHOS_VANTA_CAULK_PLUS_V1');
export const mod = x => ((x % FR) + FR) % FR;
export const scalar = label => {
  const n = BigInt('0x' + createHash('sha256').update('VANTA_TRON_CONSTRUCTED_ONLY_V1:' + label).digest('hex')) % FR;
  assert(n !== 0n);
  return n;
};
const inv = x => bn254.fields.Fr.inv(mod(x));
export const point1 = x => {
  const p = mod(x) === 0n ? G1.ZERO : G1.BASE.multiply(mod(x));
  return p.toAffine();
};
export const point2 = x => {
  const p = mod(x) === 0n ? G2.ZERO : G2.BASE.multiply(mod(x));
  const { x: a, y: b } = p.toAffine();
  return { xIm: a.c1, xRe: a.c0, yIm: b.c1, yRe: b.c0 };
};
const be = (x, bytes) => Buffer.from(BigInt(x).toString(16).padStart(bytes * 2, '0'), 'hex');
const le = x => Buffer.from(be(x, 32)).reverse();
function ark1(p) {
  const bytes = le(p.x);
  const flag = p.x === 0n && p.y === 0n ? 0x40 : p.y > FQ - p.y ? 0x80 : 0;
  bytes[31] |= flag;
  return bytes;
}
function ark2(p) {
  const re = le(p.xRe), im = le(p.xIm);
  const negIm = p.yIm === 0n ? 0n : FQ - p.yIm;
  const negRe = p.yRe === 0n ? 0n : FQ - p.yRe;
  const infinity = (p.xIm | p.xRe | p.yIm | p.yRe) === 0n;
  im[31] |= infinity ? 0x40 : p.yIm > negIm || (p.yIm === negIm && p.yRe > negRe) ? 0x80 : 0;
  return Buffer.concat([re, im]);
}
function challenge(transcript, label, arity = 0) {
  for (let count = 0; count < 32; count++) {
    const bytes = Buffer.concat([domain, be(label.length, 8), Buffer.from(label), transcript, be(count, 4)]);
    const value = BigInt('0x' + createHash('sha256').update(bytes).digest('hex')) % FR;
    if (value && (!arity || bn254.fields.Fr.pow(value, BigInt(arity)) !== 1n)) return value;
  }
  throw new Error('Fiat-Shamir rejection limit');
}

export function keys(label, inputCount = 6) {
  const s = Object.fromEntries(['alpha', 'beta', 'gamma', 'delta', 'tau', 'a2', 'c1', 'c2'].map(x => [x, scalar(label + ':' + x)]));
  s.ic = Array.from({ length: inputCount + 1 }, (_, i) => scalar(label + ':ic:' + i));
  return {
    scalars: s,
    vk: { alpha: point1(s.alpha), beta: point2(s.beta), gamma: point2(s.gamma), delta: point2(s.delta), ic: s.ic.map(point1) },
    srs: { g1: point1(1n), g20: point2(1n), g21: point2(s.tau) },
    link: { a2: point2(s.a2), c1: point2(s.c1), c2: point2(s.c2) },
  };
}

export function bundle(label, key, publicInputs, context, arity) {
  assert([1, 8, 32].includes(arity));
  assert.equal(publicInputs.length + 1, key.scalars.ic.length);
  const a = scalar(label + ':a'), b = scalar(label + ':b'), d = scalar(label + ':d');
  const accumulator = key.scalars.ic.reduce((sum, x, i) => mod(sum + x * (i === 0 ? 1n : publicInputs[i - 1])), 0n);
  const c = mod((a * b - key.scalars.alpha * key.scalars.beta - (accumulator + d) * key.scalars.gamma) * inv(key.scalars.delta));
  const tableScalars = { c: scalar(label + ':table'), zh: mod(bn254.fields.Fr.pow(key.scalars.tau, 65536n) - 1n), e: scalar(label + ':query') };
  const table = { n: 65536n, commitment: point1(tableScalars.c), zH: point1(tableScalars.zh), query: point1(tableScalars.e) };
  const zI = scalar(label + ':zi'), cI = scalar(label + ':ci'), u = scalar(label + ':u'), h = scalar(label + ':h');
  const proof = { zI: point1(zI), cI: point1(cI), u: point1(u), h: point1(h) };
  const rawContext = Buffer.from(context.replace(/^0x/, ''), 'hex');
  const t1 = Buffer.concat([domain, be(rawContext.length, 8), rawContext, be(table.n, 8),
    ark1(table.commitment), ark1(table.zH), ark1(table.query), ark1(proof.zI), ark1(proof.cI), ark1(proof.u)]);
  const chi1 = challenge(t1, 'chi1'), chi2 = challenge(t1, 'chi2');
  const w = mod((tableScalars.c - cI + chi2 * tableScalars.zh) * inv(zI));
  proof.w = point2(w);
  const alpha = challenge(Buffer.concat([t1, ark2(proof.w), ark1(proof.h)]), 'alpha', arity);
  proof.v1 = scalar(label + ':v1');
  proof.v2 = scalar(label + ':v2');
  const pi1 = mod((u - proof.v1) * inv(key.scalars.tau - alpha));
  const pi2 = mod((zI + chi1 * cI - proof.v2) * inv(key.scalars.tau - proof.v1));
  const pi3 = mod((proof.v2 - chi1 * tableScalars.e - (bn254.fields.Fr.pow(alpha, BigInt(arity)) - 1n) * h) * inv(key.scalars.tau - alpha));
  Object.assign(proof, { pi1: point1(pi1), pi2: point1(pi2), pi3: point1(pi3) });
  const pi = mod((d * key.scalars.c1 + tableScalars.e * key.scalars.c2) * inv(key.scalars.a2));

  // Independent scalar-field equations catch fixture-construction errors before TVM.
  assert.equal(mod(a * b - key.scalars.alpha * key.scalars.beta - (accumulator + d) * key.scalars.gamma - c * key.scalars.delta), 0n);
  assert.equal(mod(u - proof.v1 - pi1 * (key.scalars.tau - alpha)), 0n);
  assert.equal(mod(zI + chi1 * cI - proof.v2 - pi2 * (key.scalars.tau - proof.v1)), 0n);
  assert.equal(mod(proof.v2 - chi1 * tableScalars.e - (bn254.fields.Fr.pow(alpha, BigInt(arity)) - 1n) * h - pi3 * (key.scalars.tau - alpha)), 0n);
  assert.equal(mod(tableScalars.c - cI + chi2 * tableScalars.zh - zI * w), 0n);
  assert.equal(mod(pi * key.scalars.a2 - d * key.scalars.c1 - tableScalars.e * key.scalars.c2), 0n);
  return {
    data: {
      g0: { vk: key.vk, proof: { a: point1(a), b: point2(b), c: point1(c), d: point1(d) }, publicInputs },
      g1: { table, srs: key.srs, proof, context },
      link: { pi: point1(pi), ...key.link },
    },
    challenges: [chi1, chi2, alpha],
  };
}

/** An on-twist point outside the prime-order subgroup, independently checked by noble. */
export function wrongSubgroupPoint() {
  const field = bn254.fields.Fp2;
  for (let i = 1n; i < 128n; i++) {
    const x = { c0: i, c1: 1n };
    let y;
    try { y = field.sqrt(field.add(field.mul(field.sqr(x), x), bn254.G2.CURVE.b)); } catch (error) {
      if (!/sqrt|square root/i.test(error.message)) throw error;
      continue;
    }
    const p = G2.fromAffine({ x, y });
    if (p.isTorsionFree()) continue;
    assert(field.eql(field.sqr(y), field.add(field.mul(field.sqr(x), x), bn254.G2.CURVE.b)));
    return { xIm: x.c1, xRe: x.c0, yIm: y.c1, yRe: y.c0 };
  }
  throw new Error('No wrong-subgroup fixture found');
}
