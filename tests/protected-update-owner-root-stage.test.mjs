import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {
 OWNER_STAGE_FILES,verifyOwnerStageManifest,stageOwnerApprovedPackOnce
} from '../scripts/protected-update-owner-root-stage.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';
const deny=fn=>assert.throws(fn,
 /protected_owner_root_stage_denied_or_unknown/);
const HEAD='a'.repeat(40);
const files=OWNER_STAGE_FILES.map((path,i)=>({
 path,bytes:i+1,sha256:'c'.repeat(64)
}));
const manifest={
 version:1,repository:'al-hub/mcp-dev-hub',head:HEAD,
 installAuthorized:false,
 requiredIndependentIssuers:['independent-codex','protected-approval'],
 files
};
const raw=JSON.stringify(manifest);
const digest=s=>createHash('sha256').update(s).digest('hex');
const fixture=(m=manifest)=>({
 raw:JSON.stringify(m),head:HEAD,sha256:digest(JSON.stringify(m))
});
test('owner-only staged root source files equal exact reviewed immutable packet',()=>{
 assert.deepEqual(OWNER_STAGE_FILES,PROTECTED_BOOTSTRAP_FILES);
 assert.equal(verifyOwnerStageManifest(fixture()).fileCount,
  PROTECTED_BOOTSTRAP_FILES.length);
});
test('invalid owner source, dynamic archive path and fake authority fail closed',()=>{
 for(const m of [
  {...manifest,installAuthorized:true},
  {...manifest,head:'b'.repeat(40)},
  {...manifest,repository:'other/repo'},
  {...manifest,requiredIndependentIssuers:[]},
  {...manifest,files:[]},
  {...manifest,files:[...files.slice(0,-1),{...files.at(-1),path:'../foo'}]},
  {...manifest,files:[...files.slice(0,-1),{...files.at(-1),sha256:'bad'}]},
  {...manifest,files:[...files.slice(0,-1),{...files.at(-1),bytes:0}]},
  {...manifest,extraPermission:true}
 ])deny(()=>verifyOwnerStageManifest(fixture(m)));
 for(const v of [
  {...fixture(),head:'b'.repeat(40)},
  {...fixture(),sha256:'f'.repeat(64)},
  {...fixture(),raw:'not-json'},
  {}
 ])deny(()=>verifyOwnerStageManifest(v));
});
test('checkout or non-local session can never stage code or privileges',()=>{
 deny(()=>stageOwnerApprovedPackOnce());
 const path=fileURLToPath(new URL(
  '../scripts/protected-update-owner-root-stage.mjs',import.meta.url));
 const r=spawnSync(process.execPath,[path],{
  encoding:'utf8',timeout:5000,maxBuffer:1024
 });
 assert.equal(r.status,1);
 assert.match(r.stderr,/protected_owner_root_stage_denied_or_unknown/);
 assert.equal(r.stdout,'');
 const src=readFileSync(path,'utf8');
 assert.doesNotMatch(src,/spawnSync\s*\(\s*['"](?:sudo|\/usr\/sbin\/useradd)/);
 assert.doesNotMatch(src,/NOPASSWD:ALL|rm\s+-rf/);
 assert.match(src,/process.stdin.isTTY!==true/);
 assert.match(src,/process.env.SUDO_UID/);
 assert.match(src,/absent\(DEST\);absent\(PENDING\);/);
 assert.match(src,/packPayload\(PENDING,0,head,hash\)/);
 assert.match(src,/packPayload\(DEST,0,head,hash\)/);
 assert.match(src,/opendirSync\(path\)/);
 assert.match(src,/scanned>maxMembers/);
 assert.doesNotMatch(src,/readdirSync/);
 assert.match(src,/path!==PENDING&&path!==DEST/);
});
