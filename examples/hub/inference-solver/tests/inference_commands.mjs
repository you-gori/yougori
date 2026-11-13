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
    // Yougori's page: the command that asks which harness, then which model.
    assert.equal(context.installCommand('yougori', address), `yougori inference run yougori --server "${origin}"`);
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
// With --yes, `yougori inference run` asks nothing and stops on a question with no answer and no default
// (cli/src/inference.rs, settle), so each harness's page names the options it needs (yesAnswers).
test('each harness page names the options --yes needs', () => {
  const pick = (from, to) => source.slice(source.indexOf(from), source.indexOf(to, source.indexOf(from)));
  const pages = {};
  runInNewContext(pick('const esc = ', '\nconst ready') + pick('const ASKS = ', '\n// What every security harness'), pages);
  const plain = html => html.replace(/<[^>]+>/g, '').replace(/&quot;/g, '"');
  const catalogue = JSON.parse(readFileSync(new URL('../site/harnesses.json', import.meta.url), 'utf8'));
  const target = '--set target=practice (the practice app) or --set target=URL --set permission=yes (a target you may test)';
  const needs = {swe: ['--set issue="..." (the issue to fix)'], strix: [target], shannon: [target, '--workspace "C:\\path\\to\\project" (source code)'], pentagi: [target], pentestgpt: [target], hexstrike: [target]};
  for (const h of catalogue) assert.deepEqual(pages.yesAnswers(h).map(plain), needs[h.id] || [], h.id);
  assert.equal(pages.asks(catalogue.find(h => h.id === 'pi')), '');
  // A secret and a must-confirm never take a default; a question waiting for an answer --yes need not give
  // is left out.
  const shapes = {questions: [
    {id: 'token', type: 'secret', required: true, default: 'x'},
    {id: 'mode', type: 'choice', required: true, choices: [{value: 'a'}, {value: 'b'}]},
    {id: 'sure', type: 'confirm', required: true, must: true, default: 'yes'},
    {id: 'later', type: 'text', required: true, when: {id: 'mode', not: 'a'}},
    {id: 'alone', type: 'text', required: true, when: {id: 'other', present: false}},
    {id: 'after', type: 'text', required: true, when: {id: 'other', present: true}},
    {id: 'kept', type: 'text', required: true, default: 'x'},
    {id: 'free', type: 'text'},
  ]};
  assert.deepEqual(pages.yesAnswers(shapes).map(plain), ['the YOUGORI_SECRET_TOKEN environment variable (token)', '--set mode=a|b (mode)', '--set sure=yes (sure)', '--set later="..." (later)', '--set alone="..." (alone)']);
});
