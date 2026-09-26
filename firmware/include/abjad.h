#pragma once
#include <Arduino.h>

// Abjad values (hawwaz order). Must match pc/lib.ts.
static int abjadOf(uint32_t cp) {
  switch (cp) {
    case 0x627: case 0x623: case 0x625: case 0x622: case 0x671: case 0x621: return 1;  // ا أ إ آ ٱ ء
    case 0x628: return 2;     // ب
    case 0x62C: return 3;     // ج
    case 0x62F: return 4;     // د
    case 0x647: case 0x629: return 5;  // ه ة  (ponytail: some traditions count ة as 400)
    case 0x648: case 0x624: return 6;  // و ؤ
    case 0x632: return 7;     // ز
    case 0x62D: return 8;     // ح
    case 0x637: return 9;     // ط
    case 0x64A: case 0x649: case 0x626: return 10;  // ي ى ئ
    case 0x643: return 20;    // ك
    case 0x644: return 30;    // ل
    case 0x645: return 40;    // م
    case 0x646: return 50;    // ن
    case 0x633: return 60;    // س
    case 0x639: return 70;    // ع
    case 0x641: return 80;    // ف
    case 0x635: return 90;    // ص
    case 0x642: return 100;   // ق
    case 0x631: return 200;   // ر
    case 0x634: return 300;   // ش
    case 0x62A: return 400;   // ت
    case 0x62B: return 500;   // ث
    case 0x62E: return 600;   // خ
    case 0x630: return 700;   // ذ
    case 0x636: return 800;   // ض
    case 0x638: return 900;   // ظ
    case 0x63A: return 1000;  // غ
  }
  // Latin letters by transliteration. ponytail: single letters only, no sh/th/kh digraphs.
  static const int16_t LATIN[26] = {1, 2, 20, 4, 10, 80, 3, 5, 10, 3, 20, 30, 40,
                                    50, 6, 2, 100, 200, 60, 400, 6, 80, 6, 600, 10, 7};
  if (cp >= 'A' && cp <= 'Z') cp += 32;
  if (cp >= 'a' && cp <= 'z') return LATIN[cp - 'a'];
  return 0;
}

static long abjadSum(const char *s) {
  long sum = 0;
  const uint8_t *p = (const uint8_t *)s;
  while (*p) {
    int n = *p < 0x80 ? 1 : (*p & 0xE0) == 0xC0 ? 2 : (*p & 0xF0) == 0xE0 ? 3 : 4;
    uint32_t cp = n == 1 ? *p : *p & (0x7F >> n);
    int i = 1;
    for (; i < n && p[i]; i++) cp = (cp << 6) | (p[i] & 0x3F);
    sum += abjadOf(cp);
    p += i;
  }
  return sum;
}

// Classical 4x4 wafq: base square (constant 34) shifted so every row, column
// and main diagonal sums to `total`. Cells 13..16 sit one per row/column/diagonal
// and absorb the remainder. Needs total >= 30.
static bool wafq(long total, long out[16]) {
  static const uint8_t BASE[16] = {8, 11, 14, 1, 13, 2, 7, 12, 3, 16, 9, 6, 10, 5, 4, 15};
  if (total < 30) return false;
  long q = (total - 30) / 4, r = (total - 30) % 4;
  for (int i = 0; i < 16; i++) out[i] = BASE[i] - 1 + q + (BASE[i] >= 13 ? r : 0);
  return true;
}
