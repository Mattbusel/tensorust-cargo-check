// Cargo's version requirement rules, ported from the tensorust.com Cargo.toml checker.
// A requirement like "1.2", "^0.3", "~1.4.2", "=0.3.20", ">=1, <2" or "1.*" becomes one range [lo, loInclusive, hi, allowPre].

export function parseVersion(s) {
  const m = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?/.exec(String(s).trim());
  if (!m) return null;
  return { M: +m[1], m: m[2] == null ? null : +m[2], p: m[3] == null ? null : +m[3], pre: m[4] || '' };
}

export function compare(a, b) {
  for (const k of ['M', 'm', 'p']) {
    const x = a[k] || 0, y = b[k] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  if (a.pre === b.pre) return 0;
  if (!a.pre) return 1;
  if (!b.pre) return -1;
  return a.pre < b.pre ? -1 : 1;
}

const V = (M, m, p) => ({ M, m, p, pre: '' });

export function ranges(req) {
  req = String(req || '*').trim();
  if (req === '' || req === '*') return [[V(0, 0, 0), true, null, false]];
  let lo = V(0, 0, 0), loi = true, hi = null, pre = false;
  const setlo = (x, inc) => { if (compare(x, lo) > 0 || (compare(x, lo) === 0 && !inc)) { lo = x; loi = inc; } };
  const sethi = x => { if (!hi || compare(x, hi) < 0) hi = x; };
  for (let c of req.split(',')) {
    c = c.trim();
    const m = /^(\^|~|=|>=|<=|>|<)?\s*(.*)$/.exec(c);
    let op = m[1] || '^';
    const s = m[2].replace(/\.\*$|\.x$/i, '');
    if (s === '*') continue;
    const v = parseVersion(s);
    if (!v) continue;
    if (v.pre) pre = true;
    const { M, m: mi, p } = v;
    const base = V(M, mi || 0, p || 0); base.pre = v.pre;
    if (/\*|x/i.test(m[2]) && op === '^') op = '=';
    if (op === '^') {
      setlo(base, true);
      if (M > 0) sethi(V(M + 1, 0, 0));
      else if (mi == null) sethi(V(1, 0, 0));
      else if (mi > 0) sethi(V(0, mi + 1, 0));
      else if (p == null) sethi(V(0, 1, 0));
      else sethi(V(0, 0, p + 1));
    } else if (op === '~') { setlo(base, true); sethi(mi == null ? V(M + 1, 0, 0) : V(M, mi + 1, 0)); }
    else if (op === '=') { setlo(base, true); sethi(mi == null ? V(M + 1, 0, 0) : p == null ? V(M, mi + 1, 0) : V(M, mi, p + 1)); }
    else if (op === '>=') setlo(base, true);
    else if (op === '>') setlo(base, false);
    else if (op === '<') sethi(base);
    else if (op === '<=') sethi(mi == null ? V(M + 1, 0, 0) : p == null ? V(M, mi + 1, 0) : V(M, mi, p + 1));
  }
  return [[lo, loi, hi, pre]];
}

export function satisfies(v, rs) {
  return rs.some(r => {
    const c = compare(v, r[0]);
    if (c < 0 || (c === 0 && !r[1])) return false;
    if (r[2] && compare(v, r[2]) >= 0) return false;
    if (v.pre && !r[3]) return false;
    return true;
  });
}

// Highest published, non-yanked version matching req (what `cargo update` would pick today).
export function resolve(req, versions) {
  const rs = ranges(req);
  const ok = versions.filter(v => v.v && !v.yanked && satisfies(v.v, rs)).sort((a, b) => compare(b.v, a.v));
  return ok[0] || null;
}

// Newest non-yanked stable release.
export function latestStable(versions) {
  return versions.filter(v => v.v && !v.yanked && !v.v.pre).sort((a, b) => compare(b.v, a.v))[0] || null;
}

// Cargo treats 1.x -> 2.x and 0.3 -> 0.4 (and 0.0.3 -> 0.0.4) as breaking.
export function breakingBehind(have, latest) {
  if (!have || !latest) return false;
  const a = have.v || have, b = latest.v || latest;
  if (compare(a, b) >= 0) return false;
  if (a.M !== b.M) return true;
  if (a.M === 0) {
    if ((a.m || 0) !== (b.m || 0)) return true;
    if ((a.m || 0) === 0) return (a.p || 0) !== (b.p || 0);
  }
  return false;
}
