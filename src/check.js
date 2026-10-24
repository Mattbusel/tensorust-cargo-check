// The checks. Network goes through an injected fetch so tests can run on fixtures with no network.
//   versions, yanked, MSRV  -> the crates.io sparse index (a CDN, no rate limit)
//   advisories              -> OSV querybatch (covers RustSec and GitHub-reviewed advisories) + one GET per advisory
//   licenses                -> tensorust.com's license table for the 1,000 most-used crates, then the crates.io API
//                              for the rest, one request a second as crates.io asks, capped by max-api-calls
import { parseVersion, compare, resolve, latestStable, breakingBehind } from './semver.js';
import { indexPath, parseIndex } from './parse.js';

export const UA = 'tensorust-cargo-check/1.0 (+https://tensorust.com/tools/cargo-check-action/)';
export const COPYLEFT = /\b(A?GPL|LGPL|MPL|EUPL|CDDL|OSL|SSPL|BUSL|CC-BY-SA)/i;
const TENSORUST_INDEX = 'https://tensorust.com/data/v1/cargo-check/index.json';

async function pool(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); }
  }));
  return out;
}

async function getText(fetch, url, opts = {}) {
  const r = await fetch(url, { ...opts, headers: { 'User-Agent': UA, ...(opts.headers || {}) } });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.text();
}

export async function loadTensorustIndex(fetch) {
  try {
    const t = await getText(fetch, TENSORUST_INDEX);
    if (!t) return null;
    const j = JSON.parse(t);
    return { advisories: new Set(j.advisories || []), features: new Set(j.features || []), crates: new Set(j.crates || []), licenses: j.licenses || {} };
  } catch { return null; }
}

export async function crateVersions(fetch, names) {
  const map = new Map();
  await pool([...new Set(names)], 8, async name => {
    try {
      const t = await getText(fetch, 'https://index.crates.io/' + indexPath(name));
      map.set(name, t == null ? null : parseIndex(t).map(v => ({ ...v, v: parseVersion(v.num) })).filter(v => v.v));
    } catch (e) { map.set(name, { error: String(e.message || e) }); }
  });
  return map;
}

// Returns, per input index, a list of advisory objects.
export async function advisories(fetch, pkgs) {
  const results = [];
  for (let s = 0; s < pkgs.length; s += 1000) {
    const chunk = pkgs.slice(s, s + 1000);
    const r = await fetch('https://api.osv.dev/v1/querybatch', { method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': UA },
      body: JSON.stringify({ queries: chunk.map(p => ({ package: { name: p.name, ecosystem: 'crates.io' }, version: p.version })) }) });
    if (!r.ok) throw new Error(`OSV querybatch: HTTP ${r.status}`);
    const j = await r.json();
    chunk.forEach((_, k) => results.push(((j.results || [])[k] || {}).vulns || []));
  }
  const ids = [...new Set(results.flat().map(v => v.id))].slice(0, 150);
  const det = {};
  await pool(ids, 8, async id => {
    try { const t = await getText(fetch, 'https://api.osv.dev/v1/vulns/' + encodeURIComponent(id)); if (t) det[id] = JSON.parse(t); } catch { /* summary missing is fine */ }
  });
  return results.map((vulns, k) => {
    const name = pkgs[k].name;
    const list = vulns.map(({ id }) => {
      const v = det[id] || {};
      if (v.withdrawn) return null;
      const fixed = [];
      for (const a of v.affected || []) {
        if (a.package && a.package.name && a.package.name !== name) continue;
        for (const rg of a.ranges || []) for (const e of rg.events || []) if (e.fixed) fixed.push(e.fixed);
      }
      const rs = [id, ...(v.aliases || [])].find(a => /^RUSTSEC-/.test(a)) || id;
      const informational = ((v.database_specific || {}).informational) || ((v.affected || [])[0]?.database_specific?.informational) || '';
      return { id, rs, summary: (v.summary || '').trim() || (v.details || '').split('\n')[0].slice(0, 140), informational, fixed: [...new Set(fixed)], aliases: v.aliases || [] };
    }).filter(Boolean);
    // One entry per RUSTSEC id: prefer the RustSec record itself over its GitHub alias, keep any informational flag.
    const by = new Map();
    for (const a of list) {
      const b = by.get(a.rs);
      if (!b) { by.set(a.rs, a); continue; }
      const keep = b.id === b.rs ? b : a.id === a.rs ? a : b;
      keep.informational = b.informational || a.informational;
      keep.fixed = [...new Set([...b.fixed, ...a.fixed])];
      if (!keep.summary) keep.summary = a.summary || b.summary;
      by.set(a.rs, keep);
    }
    return [...by.values()];
  });
}

// The smallest fixed version above the locked one: the least disruptive upgrade that clears the advisory.
export function upgradeTo(locked, fixed) {
  const v = parseVersion(locked);
  const up = fixed.map(f => ({ f, x: parseVersion(f) })).filter(o => o.x && v && compare(o.x, v) > 0).sort((a, b) => compare(a.x, b.x));
  return up.length ? up[0].f : null;
}

function licenseFromIndex(tidx, name, version) {
  const L = tidx && tidx.licenses && tidx.licenses[name];
  if (!L) return undefined;
  if (Object.prototype.hasOwnProperty.call(L, version)) return L[version];
  return L['*'];
}

export async function licenses(fetch, pkgs, tidx, { maxApiCalls = 60, sleep = ms => new Promise(r => setTimeout(r, ms)) } = {}) {
  const out = new Map();
  const todo = [];
  for (const p of pkgs) {
    const l = licenseFromIndex(tidx, p.name, p.version);
    if (l !== undefined) out.set(p.name + '@' + p.version, l);
    else todo.push(p);
  }
  let calls = 0, skipped = 0;
  for (const p of todo) {
    if (calls >= maxApiCalls) { skipped++; continue; }
    if (calls) await sleep(1000);
    calls++;
    try {
      const t = await getText(fetch, `https://crates.io/api/v1/crates/${encodeURIComponent(p.name)}/${encodeURIComponent(p.version)}`);
      const j = t ? JSON.parse(t) : null;
      out.set(p.name + '@' + p.version, j && j.version ? (j.version.license || null) : undefined);
    } catch { /* unknown */ }
  }
  return { map: out, skipped, calls };
}

// The whole check.
//   packages:     [{ name, version }] from the PR's Cargo.lock, or resolved from Cargo.toml requirements (see resolveManifest)
//   basePackages: same for the base branch (null when there is no base lock), to find new packages
//   directAdded:  [{ name, pkg, req, kind }] dependencies added to a Cargo.toml in this PR
export async function runCheck({ packages, basePackages = null, directAdded = [], fetch, maxApiCalls = 60, sleep, tidx }) {
  const notes = [];
  if (tidx === undefined) tidx = await loadTensorustIndex(fetch);
  const names = packages.map(p => p.name);
  const vers = await crateVersions(fetch, names);
  let adv = packages.map(() => []);
  try { adv = await advisories(fetch, packages); } catch (e) { notes.push(`Advisory lookup failed (${e.message}); advisories were not checked this run.`); adv = null; }
  const lic = await licenses(fetch, packages, tidx, { maxApiCalls, sleep });
  if (lic.skipped) notes.push(`Licenses not checked for ${lic.skipped} crates${tidx ? ' outside the 1,000 most used' : ''} (raise max-api-calls to check them; crates.io allows one request a second).`);

  if (adv) packages.forEach((p, k) => { for (const a of adv[k]) a.upgrade = upgradeTo(p.version, a.fixed); });
  const rows = packages.map((p, k) => {
    const vs = vers.get(p.name);
    const row = { name: p.name, version: p.version, advisories: adv ? adv[k] : [], license: lic.map.get(p.name + '@' + p.version) };
    if (Array.isArray(vs)) {
      const entry = vs.find(v => v.num === p.version);
      row.yanked = !!(entry && entry.yanked);
      row.msrv = entry ? entry.msrv : null;
      const latest = latestStable(vs);
      row.latest = latest ? latest.num : null;
      row.behind = !!(entry && latest && breakingBehind(entry, latest));
      if (!entry) row.unknownVersion = true;
    } else if (vs === null) row.missing = true;
    else row.indexError = true;
    return row;
  });

  let msrv = null;
  for (const r of rows) {
    if (!r.msrv) continue;
    const v = parseVersion(r.msrv);
    if (v && (!msrv || compare(v, msrv.v) > 0)) msrv = { v, version: r.msrv, crate: r.name };
  }
  const baseNames = basePackages ? new Set(basePackages.map(p => p.name)) : null;
  const newPackages = baseNames ? rows.filter(r => !baseNames.has(r.name)) : [];
  const security = rows.flatMap(r => r.advisories.filter(a => !a.informational).map(a => ({ row: r, a })));
  const notices = rows.flatMap(r => r.advisories.filter(a => a.informational).map(a => ({ row: r, a })));
  return {
    rows, notes, msrv: msrv && { version: msrv.version, crate: msrv.crate },
    security, notices,
    yanked: rows.filter(r => r.yanked),
    behind: rows.filter(r => r.behind),
    copyleft: rows.filter(r => r.license && COPYLEFT.test(r.license)),
    noLicense: rows.filter(r => r.license === null),
    missing: rows.filter(r => r.missing),
    newPackages, directAdded, advisoriesChecked: !!adv, tidx,
  };
}

// For a Cargo.toml with no Cargo.lock: resolve each requirement to the version Cargo would pick today.
export async function resolveManifest(fetch, deps) {
  const usable = deps.filter(d => !d.local);
  const vers = await crateVersions(fetch, usable.map(d => d.pkg));
  const out = [], unresolved = [];
  const seen = new Set();
  for (const d of usable) {
    const vs = vers.get(d.pkg);
    const r = Array.isArray(vs) ? resolve(d.req, vs) : null;
    if (!r) { unresolved.push(d); continue; }
    const key = d.pkg + '@' + r.num;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ name: d.pkg, version: r.num, req: d.req });
  }
  return { packages: out, unresolved };
}
