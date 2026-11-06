import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, cpSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const sdk = resolve('appliance/agent/setupkit/sdk');
test('typescript: package resolution and nested conditional inputs compile', () => {
  const root = mkdtempSync(join(tmpdir(), 'yougori-sdk-types-'));
  try {
    cpSync(sdk, join(root, 'node_modules', 'yougori'), {recursive:true});
    writeFileSync(join(root, 'app.mts'), `import { Setup } from 'yougori';
      const setup = new Setup({name:'site', image:'node:22-alpine', files:['app.mjs'], command:['node','app.mjs']});
      setup.admin(); setup.checkbox('workers','Enable workers?');
      setup.input('key','Key',{type:'secret',when:{all:[{workers:'yes'},{not:{mode:'local'}}]}});
      setup.grid('sandbox',{when:'workers'}); setup.onSetup(values=>{ if(typeof values.admin_email === 'string') values.admin_email.toLowerCase(); });
      await setup.run(values=>values);
    `);
    const result = spawnSync(process.execPath, [resolve('node_modules/typescript/bin/tsc'), '--noEmit', '--strict', '--target', 'es2022', '--module', 'NodeNext', '--moduleResolution', 'NodeNext', 'app.mts'], {cwd:root,encoding:'utf8'});
    assert.equal(result.status,0,result.stdout+result.stderr);
  } finally { rmSync(root,{recursive:true,force:true}); }
});
const questions = `setup.admin(); setup.checkbox('workers', 'Enable workers?'); setup.input('count', 'Workers', {type: 'number', min: 1, max: 8}); setup.input('models', 'Models', {type: 'multichoice', choices: [{value:'small', label:'Small'}, {value:'large', label:'Large'}]});`;
for (const language of ['javascript', 'python']) test(`${language}: declaration, typed answers, once-only hook and failure before ready`, () => {
  const root = mkdtempSync(join(tmpdir(), 'yougori-sdk-'));
  try {
    cpSync(join(sdk, 'yougori.py'), join(root, 'yougori.py'));
    cpSync(sdk, join(root, 'node_modules', 'yougori'), {recursive:true});
    const js = `import {Setup} from 'yougori'; import {writeFileSync,appendFileSync} from 'node:fs';
      const setup = new Setup({name:'site',image:'node:22-slim',files:['app.mjs'],command:['node','app.mjs']});
      ${questions}
      setup.onSetup(v=>{if(v.admin_email==='fail@example.com') throw Error('setup failed'); appendFileSync('hooks','x');});
      await setup.run(v=>writeFileSync('received.json',JSON.stringify(v)));`;
    const py = `from yougori import Setup
import json
from pathlib import Path
setup=Setup('site',image='python:3.12-slim',files=['app.py'],command=['python','app.py'])
setup.admin()
setup.checkbox('workers','Enable workers?')
setup.input('count','Workers',type='number',min=1,max=8)
setup.input('models','Models',type='multichoice',choices=[{'value':'small','label':'Small'},{'value':'large','label':'Large'}])
@setup.on_setup
def initialize(values):
    if values['admin_email']=='fail@example.com': raise ValueError('setup failed')
    with open('hooks','a') as stream: stream.write('x')
setup.run(lambda values: Path('received.json').write_text(json.dumps(values)))
`;
    writeFileSync(join(root, language === 'python' ? 'app.py' : 'app.mjs'), language === 'python' ? py : js);
    const run = () => language === 'python'
      ? spawnSync(process.platform === 'win32' ? 'py' : 'python3', process.platform === 'win32' ? ['-3','app.py'] : ['app.py'], {cwd:root,encoding:'utf8'})
      : spawnSync(process.execPath,['app.mjs'],{cwd:root,encoding:'utf8'});
    let result = run(); assert.equal(result.status,0,result.stderr);
    assert(!existsSync(join(root,'hooks'))); assert(!existsSync(join(root,'received.json')));
    const declaration = JSON.parse(readFileSync(join(root,'.yougori','setup.json')));
    assert.equal(declaration.questions.length,5); assert.equal(declaration.questions[1].type,'secret');
    assert(!('default' in declaration.questions[1]));
    const answers = {admin_email:'owner@example.com',admin_password:'fixture-value-only',workers:'yes',count:'3',models:'small,large',_yougori_generation:'one',_yougori_launch:'launch-one'};
    const save = () => writeFileSync(join(root,'.yougori','answers.json'),JSON.stringify(answers)); save();
    for(let i=0;i<2;i++){result=run();assert.equal(result.status,0,result.stderr);assert(!result.stdout.includes(answers.admin_password));}
    const received=JSON.parse(readFileSync(join(root,'received.json')));
    assert.equal(received.workers,true);assert.equal(received.count,3);assert.deepEqual(received.models,['small','large']);
    assert.equal(readFileSync(join(root,'hooks'),'utf8'),'x');
    assert.equal(readFileSync(join(root,'.yougori','launch-ready'),'utf8'),'launch-one');
    answers._yougori_generation='two';answers._yougori_launch='launch-two';answers.admin_email='fail@example.com';save();
    result=run();assert.notEqual(result.status,0);assert.equal(readFileSync(join(root,'hooks'),'utf8'),'x');
    assert.notEqual(readFileSync(join(root,'.yougori','launch-ready'),'utf8'),'launch-two');
  } finally { rmSync(root,{recursive:true,force:true}); }
});
