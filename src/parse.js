// Cargo.lock and Cargo.toml parsing, ported from the tensorust.com Cargo.toml checker.
// No TOML library: both files are regular enough that the same line rules as the browser tool hold, and the action
// stays a single small bundle.

const REGISTRY = /^(registry\+https:\/\/github\.com\/rust-lang\/crates\.io-index|sparse\+https:\/\/index\.crates\.io\/)$/;

// Every crates.io package in a Cargo.lock (any lockfile version). Path, git and other-registry packages are skipped.
export function parseLock(text) {
  const out = [];
  const seen = new Set();
  for (const block of String(text).replace(/\r/g, '').split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = /^\s*name\s*=\s*"([^"]+)"/m.exec(block);
    const version = /^\s*version\s*=\s*"([^"]+)"/m.exec(block);
    const source = /^\s*source\s*=\s*"([^"]+)"/m.exec(block);
    if (!name || !version) continue;
    if (!source || !REGISTRY.test(source[1])) continue;
    const key = name[1] + '@' + version[1];
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ name: name[1], version: version[1] });
  }
  return out;
}

// Direct dependencies declared in a Cargo.toml: [dependencies], [dev-dependencies], [build-dependencies],
// target-specific tables, [workspace.dependencies] and [dependencies.foo] sub-tables.
// Each: { name (key in the manifest), pkg (crates.io name, honours `package =`), req, kind, local? }.
export function parseManifest(text) {
  const deps = [];
  const lines = String(text).replace(/\r/g, '').split('\n');
  let sec = null, cur = null;
  for (let i = 0; i < lines.length; i++) {
    const L = lines[i].replace(/\s+#.*$/, '').trim();
    if (!L || L[0] === '#') continue;
    const h = /^\[([^\]]+)\]$/.exec(L);
    if (h) {
      const k = h[1].replace(/\s/g, '');
      cur = null;
      const mm = /(?:^|\.)((?:dev-|build-)?dependencies)(?:\.([A-Za-z0-9_-]+))?$/.exec(k);
      if (mm) {
        sec = mm[1] === 'dependencies' && /^workspace\./.test(k) ? 'workspace' : mm[1];
        if (mm[2]) { cur = { name: mm[2], pkg: mm[2], req: '*', kind: sec }; deps.push(cur); }
      } else sec = null;
      continue;
    }
    if (!sec) continue;
    if (cur) {
      const kv = /^([A-Za-z0-9_-]+)\s*=\s*(.*)$/.exec(L);
      if (kv) {
        const val = kv[2].replace(/^"|"$/g, '');
        if (kv[1] === 'version') cur.req = val;
        else if (kv[1] === 'package') cur.pkg = val;
        else if (/^(path|git|registry)$/.test(kv[1])) cur.local = kv[1];
        else if (kv[1] === 'workspace' && /true/.test(val)) cur.local = 'workspace';
      }
      continue;
    }
    const e = /^("?)([A-Za-z0-9_-]+)\1\s*=\s*(.*)$/.exec(L);
    if (!e) continue;
    const name = e[2];
    let rest = e[3];
    if (rest[0] === '{') {
      while ((rest.match(/{/g) || []).length > (rest.match(/}/g) || []).length && i + 1 < lines.length) rest += ' ' + lines[++i].trim();
    }
    const d = { name, pkg: name, req: '*', kind: sec };
    if (rest[0] === '"') d.req = rest.replace(/^"/, '').replace(/".*$/, '');
    else {
      const vv = /version\s*=\s*"([^"]*)"/.exec(rest), pk = /package\s*=\s*"([^"]*)"/.exec(rest);
      if (vv) d.req = vv[1];
      if (pk) d.pkg = pk[1];
      const lc = /\b(path|git|registry)\s*=|workspace\s*=\s*true/.exec(rest);
      if (lc) d.local = lc[1] || 'workspace';
    }
    deps.push(d);
  }
  return deps;
}

// Path of the sparse index file for a crate (https://index.crates.io/<this>).
export function indexPath(name) {
  const n = name.toLowerCase();
  if (n.length === 1) return `1/${n}`;
  if (n.length === 2) return `2/${n}`;
  if (n.length === 3) return `3/${n[0]}/${n}`;
  return `${n.slice(0, 2)}/${n.slice(2, 4)}/${n}`;
}

// One sparse index file (newline-delimited JSON, one line per published version).
export function parseIndex(text) {
  const out = [];
  for (const line of String(text).split('\n')) {
    if (!line.trim()) continue;
    try {
      const j = JSON.parse(line);
      out.push({ num: j.vers, yanked: !!j.yanked, msrv: j.rust_version || null });
    } catch { /* skip a bad line */ }
  }
  return out;
}
