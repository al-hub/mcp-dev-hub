import test from 'node:test';
import assert from 'node:assert/strict';
import {safeBearer} from '../src/dashboard/read-only-server.mjs';
const valid="sample-public-abcdefghij";
const short="sample-public-abcdefghi";
test('minimum 24-character public bearer token acceptance and 23 rejection',()=>{
 assert.equal(valid.length,24);
 assert.equal(short.length,23);
 assert.equal(safeBearer('Bearer '+valid,valid),true);
 assert.equal(safeBearer('Bearer '+short,short),false);
 assert.equal(safeBearer('bearer '+valid,valid),false);
 assert.equal(safeBearer('Bearer '+short,valid),false);
});
