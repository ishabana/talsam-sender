import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';

// Must match firmware/include/abjad.h and firmware/src/main.cpp.
export const PORT = 4646;
const SALT = 'abjad-talisman-v1';
const KDF_ITER = 50000;
const MAGIC = Buffer.from('ABJ1');

// Abjad values (hawwaz order).
const ARABIC: Record<string, number> = {
  'ا': 1, 'أ': 1, 'إ': 1, 'آ': 1, 'ٱ': 1, 'ء': 1, 'ب': 2, 'ج': 3, 'د': 4, 'ه': 5, 'ة': 5,
  'و': 6, 'ؤ': 6, 'ز': 7, 'ح': 8, 'ط': 9, 'ي': 10, 'ى': 10, 'ئ': 10, 'ك': 20, 'ل': 30,
  'م': 40, 'ن': 50, 'س': 60, 'ع': 70, 'ف': 80, 'ص': 90, 'ق': 100, 'ر': 200, 'ش': 300,
  'ت': 400, 'ث': 500, 'خ': 600, 'ذ': 700, 'ض': 800, 'ظ': 900, 'غ': 1000,
};
const LATIN = [1, 2, 20, 4, 10, 80, 3, 5, 10, 3, 20, 30, 40, 50, 6, 2, 100, 200, 60, 400, 6, 80, 6, 600, 10, 7];

export function abjadSum(text: string): number {
  let sum = 0;
  for (const ch of text.toLowerCase()) {
    const c = ch.charCodeAt(0);
    sum += ARABIC[ch] ?? (c >= 97 && c <= 122 ? LATIN[c - 97] : 0);
  }
  return sum;
}

// Classical 4x4 wafq whose rows, columns and diagonals all sum to `total`.
export function wafq(total: number): number[] | null {
  const BASE = [8, 11, 14, 1, 13, 2, 7, 12, 3, 16, 9, 6, 10, 5, 4, 15];
  if (total < 30) return null;
  const q = Math.floor((total - 30) / 4), r = (total - 30) % 4;
  return BASE.map((k) => k - 1 + q + (k >= 13 ? r : 0));
}

export function wafqText(total: number): string {
  const sq = wafq(total);
  const rows = sq ? [0, 1, 2, 3].map((r) => '  ' + sq.slice(r * 4, r * 4 + 4).map((n) => String(n).padStart(6)).join('')) : ['  (below 30, no wafq)'];
  return [`  abjad ${total}`, ...rows].join('\n');
}

export const deriveKey = (pass: string) => pbkdf2Sync(pass, SALT, KDF_ITER, 32, 'sha256');

// "ABJ1" | nonce(12) | ciphertext | tag(16), AAD = "ABJ1"
export function seal(key: Buffer, plain: string): Buffer {
  const nonce = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, nonce).setAAD(MAGIC);
  const body = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return Buffer.concat([MAGIC, nonce, body, c.getAuthTag()]);
}

export function open(key: Buffer, pkt: Buffer): string | null {
  if (pkt.length < 32 || !pkt.subarray(0, 4).equals(MAGIC)) return null;
  try {
    const d = createDecipheriv('aes-256-gcm', key, pkt.subarray(4, 16)).setAAD(MAGIC);
    d.setAuthTag(pkt.subarray(pkt.length - 16));
    return Buffer.concat([d.update(pkt.subarray(16, pkt.length - 16)), d.final()]).toString('utf8');
  } catch {
    return null;
  }
}
