import test from 'node:test';
import assert from 'node:assert/strict';
import {parseProtectedUpdateRequest} from '../src/ops/protected-update-request.mjs';
const good=()=>({
  version:1,repository:'al-hub/mcp-dev-hub',prNumber:39,
  head:'a'.repeat(40),base:'b'.repeat(40),ciRunId:42209800648,
  operationId:'c'.repeat(32),manifestJson:'{"version":1}',
  approvalJson:'{"version":1}',approvalSignatureBase64:'A'.repeat(86)+'==',
  reviewJson:'{"version":1}',reviewSignatureBase64:'B'.repeat(86)+'==',
  routineReviewJson:'{"version":1}',
  routineReviewSignatureBase64:'C'.repeat(86)+'=='
});
const decode=v=>parseProtectedUpdateRequest(JSON.stringify(v));
test('canonical request exposes only nonexecutable approved fields',()=>{
  const req=decode(good());
  assert.equal(req.head,'a'.repeat(40));
  assert.equal(Object.isFrozen(req),true);
  assert.equal(Object.hasOwn(req,'command'),false);
  assert.equal(Object.hasOwn(req,'path'),false);
  assert.equal(Object.hasOwn(req,'githubToken'),false);
  assert.equal(Object.hasOwn(req,'root'),false);
});
test('arbitrary code/path/key/permission fields and wrong scope denied',()=>{
  for(const add of [
    {path:'/usr/bin/bash'},{root:'/etc/sudoers'},{command:'sudo'},
    {githubToken:'secret'},{trustKey:'x'},
    {force:true},{user:'root'},{repo:'other/name'},
    {repository:'other/name'},{head:['a'.repeat(40)]},
    {base:'a'.repeat(40)},{operationId:'../escape'},
    {prNumber:0},{ciRunId:-1},{approvalJson:null},
    {reviewSignatureBase64:'AA=='},
    {routineReviewSignatureBase64:'AA=='},
    {routineReviewJson:null}
  ]) assert.throws(()=>decode({...good(),...add}),
    /protected_update_request_denied/);
});
test('duplicate keys, whitespace, oversized and malformed request denied',()=>{
  const raw=JSON.stringify(good());
  for(const item of [
    raw.replace('"version":1','"version":1,"version":1'),
    ' '+raw,raw.replace('"ciRunId":','"ciRunId": '),
    raw.replace('"operationId":"'+ 'c'.repeat(32)+'"',
      '"operationId":"../escape"'),
    raw.slice(0,-1),
    'x'.repeat(16001)
  ]) assert.throws(()=>parseProtectedUpdateRequest(item),
    /protected_update_request_denied/);
});
