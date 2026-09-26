import { test } from 'node:test';
import assert from 'node:assert/strict';
import { abjadSum, wafq, deriveKey, seal, open } from './lib.ts';

test('abjad values', () => {
  assert.equal(abjadSum('الله'), 66);
  assert.equal(abjadSum('بسم'), 102);
  assert.equal(abjadSum('Ab c'), 1 + 2 + 20);
});

test('wafq is magic for every total', () => {
  assert.equal(wafq(29), null);
  for (let s = 30; s <= 5000; s++) {
    const g = wafq(s)!;
    const at = (r: number, c: number) => g[r * 4 + c];
    const lines = [0, 1, 2, 3].flatMap((i) => [
      [0, 1, 2, 3].map((j) => at(i, j)),
      [0, 1, 2, 3].map((j) => at(j, i)),
    ]);
    lines.push([0, 1, 2, 3].map((i) => at(i, i)), [0, 1, 2, 3].map((i) => at(i, 3 - i)));
    for (const l of lines) assert.equal(l.reduce((a, b) => a + b), s, `total ${s}`);
    assert.equal(new Set(g).size, 16, `distinct ${s}`);
  }
});

test('seal/open round trip, rejects tamper and wrong key', () => {
  const key = deriveKey('secret');
  const pkt = seal(key, 'pc\nسلام');
  assert.equal(open(key, pkt), 'pc\nسلام');
  pkt[20] ^= 1;
  assert.equal(open(key, pkt), null);
  assert.equal(open(deriveKey('other'), seal(key, 'x')), null);
});
