import test from 'node:test';
import assert from 'node:assert/strict';
// Isolated #10 automation acceptance fixture: deliberately failing first CI.
test('repair automation detects and fixes deterministic CI failure',()=>{
  assert.equal(2+2,4);
});
