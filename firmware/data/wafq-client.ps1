# wafq for bare Windows (PowerShell 5.1+, no Node). Served by the board; ASCII only.
# Shows the board's talismans; `decode <passphrase>` reveals messages locally.
param([string]$BoardHost = 'thmi.local')
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

# Must match firmware/src/main.cpp and pc/lib.ts.
$SALT = [Text.Encoding]::UTF8.GetBytes('abjad-talisman-v1')
$ITER = 50000
$MAGIC = [Text.Encoding]::ASCII.GetBytes('ABJ1')
$BASE = 8, 11, 14, 1, 13, 2, 7, 12, 3, 16, 9, 6, 10, 5, 4, 15

Add-Type -TypeDefinition @'
using System;
using System.Security.Cryptography;
public static class WafqGcm {
  // AES-256-GCM open, 96-bit nonce. .NET Framework has no AesGcm, so CTR + GHASH by hand.
  public static byte[] Open(byte[] key, byte[] nonce, byte[] aad, byte[] ct, byte[] tag) {
    using (var aes = Aes.Create()) {
      aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None; aes.Key = key;
      var enc = aes.CreateEncryptor();
      Func<byte[], byte[]> E = b => { var o = new byte[16]; enc.TransformBlock(b, 0, 16, o, 0); return o; };
      var h = E(new byte[16]);
      var j0 = new byte[16]; Buffer.BlockCopy(nonce, 0, j0, 0, 12); j0[15] = 1;
      var lens = new byte[16];
      WriteBE(lens, 0, (ulong)aad.Length * 8); WriteBE(lens, 8, (ulong)ct.Length * 8);
      var y = new byte[16];
      y = Absorb(Absorb(Absorb(y, aad, h), ct, h), lens, h);
      var s = E(j0);
      int diff = 0;
      for (int k = 0; k < 16; k++) diff |= y[k] ^ s[k] ^ tag[k];
      if (diff != 0) return null;
      var pt = new byte[ct.Length]; var ctr = (byte[])j0.Clone();
      for (int i = 0; i < ct.Length; i += 16) {
        Inc32(ctr); var ks = E(ctr);
        for (int k = 0; k < 16 && i + k < ct.Length; k++) pt[i + k] = (byte)(ct[i + k] ^ ks[k]);
      }
      return pt;
    }
  }
  static byte[] Absorb(byte[] y, byte[] data, byte[] h) {
    for (int i = 0; i < data.Length; i += 16) {
      for (int k = 0; k < 16 && i + k < data.Length; k++) y[k] ^= data[i + k];
      y = Mul(y, h);
    }
    return y;
  }
  static byte[] Mul(byte[] x, byte[] h) {
    var z = new byte[16]; var v = (byte[])h.Clone();
    for (int i = 0; i < 128; i++) {
      if ((x[i >> 3] & (0x80 >> (i & 7))) != 0) for (int k = 0; k < 16; k++) z[k] ^= v[k];
      bool lsb = (v[15] & 1) != 0;
      for (int k = 15; k > 0; k--) v[k] = (byte)((v[k] >> 1) | (v[k - 1] << 7));
      v[0] >>= 1;
      if (lsb) v[0] ^= 0xE1;
    }
    return z;
  }
  static void Inc32(byte[] c) { for (int i = 15; i >= 12; i--) if (++c[i] != 0) break; }
  static void WriteBE(byte[] b, int off, ulong v) { for (int i = 7; i >= 0; i--) { b[off + i] = (byte)v; v >>= 8; } }
}
'@

function WafqText($t) {
  "  abjad $t"
  if ($t -lt 30) { '  (below 30, no wafq)'; return }
  $q = [math]::Floor(($t - 30) / 4); $r = ($t - 30) % 4
  $sq = $BASE | ForEach-Object { $_ - 1 + $q + $(if ($_ -ge 13) { $r } else { 0 }) }
  for ($i = 0; $i -lt 16; $i += 4) { '  ' + (($sq[$i..($i + 3)] | ForEach-Object { "$_".PadLeft(6) }) -join '') }
}

function Reveal($m) {
  $p = [byte[]]($m.packet -split '(..)' | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_, 16) })
  if ($null -eq $key -or $p.Length -le 32) { return $null }
  $n = $p.Length
  $pt = [WafqGcm]::Open($key, [byte[]]$p[4..15], $MAGIC, [byte[]]$p[16..($n - 17)], [byte[]]$p[($n - 16)..($n - 1)])
  if ($null -eq $pt) { return $null }
  $parts = [Text.Encoding]::UTF8.GetString($pt).Split([char[]]"`n", 2)
  $parts -join ': '
}

function Show {
  $res = Invoke-RestMethod "http://$BoardHost/messages.json"
  $script:msgs = @($res | Where-Object { $_ })
  if (-not $msgs.Count) { 'no messages yet' }
  foreach ($m in $msgs) {
    ''
    WafqText $m.total
    if ($key) { $r = Reveal $m; '  ' + $(if ($r) { $r } else { '(sealed with another passphrase)' }) }
  }
}

$key = $null
Show
while ($true) {
  Write-Host -NoNewline "`n> "
  $line = [Console]::ReadLine()
  if ($null -eq $line) { break }
  $cmd, $rest = $line.Trim() -split ' ', 2
  if ($cmd -eq 'decode' -and $rest) {
    $prev = $key
    $key = (New-Object Security.Cryptography.Rfc2898DeriveBytes($rest, $SALT, $ITER, [Security.Cryptography.HashAlgorithmName]::SHA256)).GetBytes(32)
    if ($msgs.Count -and -not ($msgs | Where-Object { Reveal $_ })) { $key = $prev; 'wrong passphrase' } else { Show }
  }
  elseif ($cmd -eq 'hide') { $key = $null; Show }
  elseif ($cmd -eq 'refresh') { Show }
  elseif ($cmd -eq 'quit') { break }
  else { 'decode <passphrase> | hide | refresh | quit' }
}
