import test from 'node:test';
import assert from 'node:assert/strict';
import {EventStore,sanitize} from '../src/dashboard/events.mjs';
test('event state and sensitive output are validated',()=>{
 const s=new EventStore(2);assert.throws(()=>s.append({project:'x',cli:'unknown',state:'running'}));
 const e=s.append({project:'one',cli:'codex',state:'running',message:'token=abc Bearer xyz',source:'synthetic'});
 assert.doesNotMatch(e.message,/abc|xyz/);assert.match(e.message,/REDACTED/);
 s.append({project:'two',cli:'gemini',state:'failed'});s.append({project:'one',cli:'opencode',state:'succeeded'});
 assert.equal(s.list('one').length,1);assert.equal(s.list('two').length,1);
});
test('subscription only observes appended events',()=>{const s=new EventStore();let count=0;const off=s.subscribe(()=>count++);s.append({project:'p',cli:'gemini',state:'queued'});off();s.append({project:'p',cli:'gemini',state:'running'});assert.equal(count,1);});
