import dgram from 'node:dgram';
import os from 'node:os';
import readline from 'node:readline/promises';
import { PORT, abjadSum, wafqText, deriveKey, seal, open } from './lib.ts';

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const pass = process.env.ABJAD_PASS ?? (await rl.question('passphrase: '));
const name = process.env.ABJAD_NAME ?? os.hostname();
const key = deriveKey(pass);

// Subnet broadcast address of every IPv4 interface.
function broadcasts(): string[] {
  const out: string[] = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const i of list ?? []) {
      if (i.family !== 'IPv4' || i.internal) continue;
      const ip = i.address.split('.').map(Number), m = i.netmask.split('.').map(Number);
      out.push(ip.map((b, k) => (b & m[k]) | (~m[k] & 255)).join('.'));
    }
  }
  return out;
}

const printTalisman = (text: string) => console.log(wafqText(abjadSum(text)));

const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
sock.on('message', (pkt) => {
  const plain = open(key, pkt);
  if (!plain) return;
  const nl = plain.indexOf('\n');
  const from = plain.slice(0, nl), text = plain.slice(nl + 1);
  if (nl < 0 || from === name) return;
  console.log(`\n${from}: ${text}`);
  printTalisman(text);
});
sock.bind(PORT, () => {
  sock.setBroadcast(true);
  console.log(`${name} listening on UDP ${PORT}. Type a message, Enter to send.`);
});

for await (const line of rl) {
  if (!line.trim()) continue;
  const pkt = seal(key, `${name}\n${line}`);
  for (const addr of broadcasts()) sock.send(pkt, PORT, addr);
  printTalisman(line);
}
