// Records the real network answers for the fixtures into test/fixtures/responses.json, so the tests replay real data offline.
// Run: node scripts/record-fixtures.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { parseLock, parseManifest } from '../src/parse.js';
import { runCheck, resolveManifest } from '../src/check.js';

const F = new URL('../test/fixtures/', import.meta.url);
const tape = {};
const rec = async (url, opts = {}) => {
  const r = await fetch(url, opts);
  const body = await r.text();
  tape[url + (opts.body ? ' ' + opts.body : '')] = { status: r.status, body };
  return new Response(body, { status: r.status });
};
const head = parseLock(readFileSync(new URL('head.Cargo.lock', F), 'utf8'));
await runCheck({ packages: head, basePackages: [], fetch: rec, maxApiCalls: 100, tidx: null });
const res = await resolveManifest(rec, parseManifest(readFileSync(new URL('head.Cargo.toml', F), 'utf8')));
await runCheck({ packages: res.packages, fetch: rec, maxApiCalls: 100, tidx: null });
writeFileSync(new URL('responses.json', F), JSON.stringify(tape));
console.log(Object.keys(tape).length, 'responses recorded');
