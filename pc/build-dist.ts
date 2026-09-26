// Builds firmware/data/wafq.tgz: the `wafq` CLI as plain JS, served by the board
// so any machine can `npm i -g http://thmi.local/wafq.tgz`. Rerun + reflash after editing reveal.ts/lib.ts.
import { stripTypeScriptTypes } from 'node:module';
import { execSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, rmSync, renameSync } from 'node:fs';

const here = (p: string) => new URL(p, import.meta.url);
rmSync(here('dist'), { recursive: true, force: true });
mkdirSync(here('dist'));
mkdirSync(here('../firmware/data'), { recursive: true });

for (const f of ['lib', 'reveal']) {
  const js = stripTypeScriptTypes(readFileSync(here(`${f}.ts`), 'utf8')).replaceAll("'./lib.ts'", "'./lib.js'");
  writeFileSync(here(`dist/${f}.js`), js);
}
const pkg = { name: 'wafq', version: '1.0.0', type: 'module', bin: { wafq: 'reveal.js' } };
writeFileSync(here('dist/package.json'), JSON.stringify(pkg, null, 2));

execSync('npm pack --pack-destination ../../firmware/data', { cwd: here('dist'), stdio: 'ignore' });
renameSync(here('../firmware/data/wafq-1.0.0.tgz'), here('../firmware/data/wafq.tgz'));
console.log('built firmware/data/wafq.tgz');
