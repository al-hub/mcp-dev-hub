import { execFileSync } from 'node:child_process';
import { inspectFile } from './privacy-rules.mjs';

const files = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
if (!files.length) {
  console.error('Privacy check requires tracked/staged source files.');
  process.exit(1);
}
let failed = false;
for (const path of files) {
  let bytes;
  try { bytes = execFileSync('git', ['show', `:${path}`], { maxBuffer: 8 * 1024 * 1024 }); }
  catch { console.error('Tracked file unavailable; stage deletions before checking.'); failed = true; continue; }
  // This source-only bootstrap has no binary assets. Fail closed on unexpected binaries.
  const categories = bytes.includes(0) ? ['unexpected-binary'] : inspectFile(path, bytes.toString('utf8'));
  if (categories.length) {
    console.error(JSON.stringify({ path, categories }));
    failed = true;
  }
}
if (failed) process.exit(1);
console.log(`Privacy candidate check passed (${files.length} files); manual review remains required.`);
