import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { verifyGuestSource } from './check-guest-source.mjs'

test('old but checksum-valid guest is rejected when agent code or dependencies change', async () => {
  const root=await mkdtemp(join(tmpdir(),'guest-source-'))
  try {
    const agent=join(root,'appliance/agent')
    await mkdir(join(agent,'cmd/yougori-sandbox-agent'),{recursive:true});await mkdir(join(agent,'link'));await mkdir(join(agent,'gridkit'));await mkdir(join(agent,'setupkit'))
    const files={'cmd/yougori-sandbox-agent/main.go':'package main','gridkit/grid.go':'package gridkit','setupkit/setup.go':'package setupkit','link/link.go':'package link'}
    const hash=createHash('sha256')
    for(const [path,content] of Object.entries(files).sort(([a],[b])=>a<b?-1:a>b?1:0)) {
      await writeFile(join(agent,path),content);hash.update(path+'\0'+Buffer.byteLength(content)+'\0'+content)
    }
    const inputs=[{path:'appliance/agent/{link,cmd/yougori-sandbox-agent,gridkit,setupkit}',sha256:hash.digest('hex'),files:4}]
    for(const name of ['go.mod','go.sum']) {await writeFile(join(agent,name),name);inputs.push({path:'appliance/agent/'+name,sha256:createHash('sha256').update(name).digest('hex')})}
    const record=join(root,'record.json');await writeFile(record,JSON.stringify({agent_build:'current',inputs}))
    assert.equal(await verifyGuestSource(root,record),'current')
    await writeFile(join(agent,'gridkit/grid.go'),'changed grid tool')
    await assert.rejects(verifyGuestSource(root,record),/guest is stale/)
    await writeFile(join(agent,'gridkit/grid.go'),files['gridkit/grid.go'])
    await writeFile(join(agent,'link/link.go'),'package link // changed')
    await assert.rejects(verifyGuestSource(root,record),/guest is stale/)
    await writeFile(join(agent,'link/link.go'),files['link/link.go'])
    await writeFile(join(agent,'go.mod'),'new dependency')
    await assert.rejects(verifyGuestSource(root,record),/dependencies are stale/)
  } finally {await rm(root,{recursive:true,force:true})}
})
