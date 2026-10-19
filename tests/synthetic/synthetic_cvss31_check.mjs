import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const code = readFileSync(new URL('../../vulnassess/ui/static/cvss31.js', import.meta.url), 'utf8');
const cvss = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
const fixture = JSON.parse(readFileSync(process.argv[2], 'utf8'));
for (const row of fixture.vectors) assert.deepEqual(cvss.scoreVector(row.vector), {base: row.base, environmental: row.environmental}, row.vector);
assert.throws(() => cvss.scoreVector('CVSS:4.0/AV:N'));
assert.throws(() => cvss.scoreVector('CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
console.log(`JAVASCRIPT CVSS: ${fixture.vectors.length} of ${fixture.vectors.length} match Python`);
for (const row of fixture.sandbox_cases) assert.deepEqual(cvss.sandbox(row.vector, row.profile, row.changes, fixture.sandbox_weights), row.expected, JSON.stringify(row.changes));
console.log(`SANDBOX FORMULA: ${fixture.sandbox_cases.length} of ${fixture.sandbox_cases.length} context/threat cases match Python`);