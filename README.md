# Talsam sender

Abjad talisman messenger for the LilyGO T-HMI (ESP32-S3, 2.8" touch). Type in
Arabic (abjad-order keyboard) or Latin; each message is sealed with AES-256-GCM
and broadcast over UDP 4646. Every sent or received message shows its abjad
total and a 4x4 wafq whose rows, columns and diagonals sum to that total.

## Setup

1. Copy `firmware/include/secrets.example.h` to `firmware/include/secrets.h`,
   fill in Wi-Fi (2.4 GHz), a long shared passphrase and a device name.
2. Flash (PlatformIO, board on COM10 — change in `platformio.ini`):
   ```powershell
   cd firmware
   pio run -t upload
   ```

## Talking to the board

- **Browser:** `http://thmi.local` (or the IP on the status line). Shows the
  squares; type `decode <passphrase>` to reveal text in the browser.
- **Any Windows PowerShell, nothing installed:** `irm thmi.local | iex`
- **PC chat peer (Node 24):** `cd pc` then `node talisman.ts`
- **`wafq` command on this PC:** `cd pc` then `npm link`, then `wafq [host]`

Decryption always happens on the viewer's machine; the board only publishes
totals and ciphertext.

## Files

- `firmware/src/main.cpp` — display, touch, keyboard, crypto, UDP, web server
- `firmware/include/abjad.h` — abjad values and wafq construction
- `firmware/include/page.h` — web page
- `firmware/data/wafq-client.ps1` — PowerShell client served by the board
- `firmware/tools/boot-image.ps1` — turns `art/boot.png` into the boot screen:
  `.\tools\boot-image.ps1 -Source art\boot.png -Rotate 90`
- `pc/lib.ts` — abjad, wafq and wire format shared by the PC tools
  (`node --test lib.test.ts`)

Wire format: `"ABJ1" | nonce(12) | AES-256-GCM("name\ntext") | tag(16)`,
AAD `"ABJ1"`, key = PBKDF2-SHA256(passphrase, "abjad-talisman-v1", 50000).
