
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openDb,addJob,jobs,tick} from '../scripts/worker.mjs';
test('repo-check and cli-smoke can never execute untrusted checkout code without OS isolation',()=>{
 const dir=mkdtempSync(join(tmpdir(),'repo-exec-block-'));
 const old={state:process.env.MCP_DEV_HUB_STATE_DIR,scope:process.env.MCP_DEV_HUB_APPROVED_SCOPE,
  write:process.env.MCP_DEV_HUB_ENABLE_AI_WRITE,push:process.env.MCP_DEV_HUB_ENABLE_AI_PUSH};
 Object.assign(process.env,{MCP_DEV_HUB_STATE_DIR:dir,MCP_DEV_HUB_APPROVED_SCOPE:'demo:local:workspace',
  MCP_DEV_HUB_ENABLE_AI_WRITE:'1',MCP_DEV_HUB_ENABLE_AI_PUSH:'1'});
 try{
  const db=openDb();
  for(const kind of ['repo-check','cli-smoke']){
   addJob(db,{id:'unsafe-'+kind,kind,project:'demo',target:'local',workspace:'workspace'});
   assert.equal(tick(db),false,'must not open tmux for '+kind);
   const row=jobs(db).find(j=>j.id==='unsafe-'+kind);
   assert.equal(row.state,'blocked');
   assert.equal(row.window,null);
  }
  db.close();
 }finally{
  const mapping={MCP_DEV_HUB_STATE_DIR:old.state,MCP_DEV_HUB_APPROVED_SCOPE:old.scope,
   MCP_DEV_HUB_ENABLE_AI_WRITE:old.write,MCP_DEV_HUB_ENABLE_AI_PUSH:old.push};
  for(const [k,v] of Object.entries(mapping)){if(v===undefined)delete process.env[k];else process.env[k]=v;}
  rmSync(dir,{recursive:true,force:true});
 }
});
