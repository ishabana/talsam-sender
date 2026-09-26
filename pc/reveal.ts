#!/usr/bin/env node
// Fetch the board's talismans; `decode <passphrase>` reveals the messages locally.
// Usage: wafq [board-host]   (default thmi.local)
import readline from 'node:readline/promises';
import { wafqText, deriveKey, open } from './lib.ts';

const host = process.argv[2] ?? 'thmi.local';

type Msg = { total: number; packet: string };
let msgs: Msg[] = [];
let key: Buffer | null = null;

const reveal = (m: Msg) => {
  const s = key && open(key, Buffer.from(m.packet, 'hex'));
  return s && s.replace('\n', ': ');
};

async function show() {
  msgs = await (await fetch(`http://${host}/messages.json`)).json();
  if (!msgs.length) console.log('no messages yet');
  for (const m of msgs) {
    console.log('\n' + wafqText(m.total));
    if (key) console.log('  ' + (reveal(m) ?? '(sealed with another passphrase)'));
  }
}

await show();
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
let closed = false;
rl.on('close', () => (closed = true));
rl.setPrompt('\n> ');
rl.prompt();
for await (const line of rl) {
  const [cmd, ...rest] = line.trim().split(' ');
  if (cmd === 'decode' && rest.length) {
    const prev = key;
    key = deriveKey(rest.join(' '));
    if (msgs.length && !msgs.some(reveal)) {
      key = prev;
      console.log('wrong passphrase');
    } else await show();
  } else if (cmd === 'hide') {
    key = null;
    await show();
  } else if (cmd === 'refresh') await show();
  else if (cmd === 'quit') break;
  else console.log('decode <passphrase> · hide · refresh · quit');
  if (!closed) rl.prompt();
}
