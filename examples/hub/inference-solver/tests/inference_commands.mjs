import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
const source = readFileSync(new URL('../site/app.js', import.meta.url), 'utf8');
const start = source.indexOf('function installCommand(');
const end = source.indexOf('\nconst PROTOCOLS', start);
const context = {};
runInNewContext(source.slice(start, end), context);
test('every website install action uses Yougori directly', () => {
  for (const origin of ['http://abc123.localhost:54272', 'https://inference.example']) {
    const address = new URL(origin);
    assert.equal(context.installCommand('node', address), `yougori inference connect "${origin}"`);
    assert.equal(context.installCommand('pi', address), `yougori inference run pi --server "${origin}"`);
  }
  const compute = readFileSync(new URL('../site/compute-ui.js', import.meta.url), 'utf8');
  assert.match(compute, /const connect = installCommand\("node"\)/);
  assert.match(compute, /\["Connect this computer", connect, "compute-install"\]/);
  assert.doesNotMatch(source + compute, /powershell -NoProfile|irm '|solver-node/);
  // The only installer Local GPUs names is Yougori's own, from yougori.com: install or update.
  const installers = [...compute.matchAll(/(?:irm|curl -fsSL) (\S+)/g)].map(match => match[1]);
  assert.deepEqual(installers, ['https://yougori.com/install-preview.ps1', 'https://yougori.com/install-preview.sh']);
  assert.throws(() => context.installCommand('pi; shutdown', new URL('https://inference.example')));
  assert.throws(() => context.installCommand('pi', {origin:'https://example.com/$(bad)'}));
});
