import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assertFixedRootProtectedUpdateLayout,
  verifyProtectedLayoutEvidence
} from '../src/ops/protected-update-root-layout.mjs';

const paths=[
  '/','/usr','/usr/local','/usr/local/lib',
  '/usr/local/lib/mcp-dev-hub',
  '/usr/local/lib/mcp-dev-hub/versions',
  '/var','/var/lib','/var/lib/mcp-dev-hub',
  '/var/lib/mcp-dev-hub/protected-update'
];
const rows=()=>paths.map(path=>({
  path,uid:0,mode:path.endsWith('/protected-update')?0o700:0o755,
  directory:true,symlink:false
}));
const denied=r=>assert.throws(
  ()=>verifyProtectedLayoutEvidence(r),/protected_root_layout_denied/
);

test('synthetic fixed roots and private journal directory are structurally valid',()=>{
  assert.equal(verifyProtectedLayoutEvidence(rows()),true);
});
test('single path substitution is refused',()=>{
  const r=rows();r[4].path='/tmp/work';denied(r);
});
test('parent-order substitution is refused',()=>{
  const r=rows();[r[2],r[3]]=[r[3],r[2]];denied(r);
});
test('writable root ancestor is refused',()=>{
  const r=rows();r[2].mode=0o777;denied(r);
});
test('group writable journal ancestor is refused',()=>{
  const r=rows();r[8].mode=0o775;denied(r);
});
test('user-owned intermediate directory is refused',()=>{
  const r=rows();r[4].uid=1000;denied(r);
});
test('symlinked ancestor is refused even when directory is claimed',()=>{
  const r=rows();r[1].symlink=true;denied(r);
});
test('nondirectory special file is refused',()=>{
  const r=rows();r[7].directory=false;denied(r);
});
test('root-only journal must not permit group reading',()=>{
  const r=rows();r.at(-1).mode=0o750;denied(r);
});
test('root owner must retain read/search on ancestors',()=>{
  const r=rows();r[4].mode=0o400;denied(r);
});
test('unexpected fields and missing required ancestors are refused',()=>{
  const r=rows();r[3].unexpected=true;denied(r);
  denied(rows().slice(1));
});
test('untrusted test fixture must not impersonate real root preflight',()=>{
  if(typeof process.geteuid==='function'&&process.geteuid()!==0)
    assert.throws(assertFixedRootProtectedUpdateLayout,
      /protected_root_layout_denied/);
});
