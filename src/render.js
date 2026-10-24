// The pull request comment. One comment per PR, found again by MARKER and edited in place.
export const MARKER = '<!-- tensorust-cargo-check -->';
const SITE = 'https://tensorust.com';
const MAX_ROWS = 40;
const MAX_LEN = 60000;

const slug = n => n.toLowerCase().replace(/_/g, '-');
const esc = s => String(s == null ? '' : s).replace(/[|<>]/g, c => ({ '|': '\\|', '<': '&lt;', '>': '&gt;' })[c]).replace(/\r?\n/g, ' ');

export function crateLink(name, tidx) {
  if (!tidx || tidx.crates.has(slug(name))) return `[${esc(name)}](${SITE}/crates/${slug(name)}/)`;
  return `[${esc(name)}](https://crates.io/crates/${encodeURIComponent(name)})`;
}
export function featuresLink(name, tidx) {
  if (tidx && tidx.features.has(slug(name))) return ` · [features](${SITE}/rust/features/${slug(name)}/)`;
  return '';
}
export function advisoryLink(a, tidx) {
  if (/^RUSTSEC-/.test(a.rs) && (!tidx || tidx.advisories.has(a.rs.toLowerCase()))) return `[${a.rs}](${SITE}/rust/advisories/${a.rs.toLowerCase()}/)`;
  if (/^RUSTSEC-/.test(a.rs)) return `[${a.rs}](https://rustsec.org/advisories/${a.rs}.html)`;
  return `[${esc(a.id)}](https://osv.dev/vulnerability/${encodeURIComponent(a.id)})`;
}

function table(head, rows) {
  const shown = rows.slice(0, MAX_ROWS);
  let s = `| ${head.join(' | ')} |\n|${head.map(() => '---').join('|')}|\n` + shown.map(r => `| ${r.join(' | ')} |`).join('\n') + '\n';
  if (rows.length > shown.length) s += `\n_...and ${rows.length - shown.length} more._\n`;
  return s;
}
const fold = (title, body, open) => `<details${open ? ' open' : ''}><summary><b>${title}</b></summary>\n\n${body}\n</details>\n\n`;
const plural = (n, one, many) => `${n} ${n === 1 ? one : many || one + 's'}`;

export function headline(r) {
  const bits = [];
  if (r.security.length) bits.push(plural(r.security.length, 'security advisory', 'security advisories'));
  if (r.yanked.length) bits.push(plural(r.yanked.length, 'yanked version'));
  if (r.missing.length) bits.push(plural(r.missing.length, 'crate not on crates.io', 'crates not on crates.io'));
  if (r.notices.length) bits.push(plural(r.notices.length, 'unmaintained or unsound notice'));
  if (r.copyleft.length + r.noLicense.length) bits.push(plural(r.copyleft.length + r.noLicense.length, 'license to check', 'licenses to check'));
  if (r.behind.length) bits.push(`${r.behind.length} a breaking release behind`);
  return bits.length ? bits.join(', ') : 'nothing urgent';
}

export function renderReport(r, { source, checkedAt = new Date().toISOString().slice(0, 10), failOn = [] } = {}) {
  const t = r.tidx;
  const urgent = r.security.length || r.yanked.length || r.missing.length;
  let md = `${MARKER}\n### Cargo Check: ${urgent ? 'needs attention, ' : ''}${headline(r)}\n\n`;
  md += `${esc(source)} · ${plural(r.rows.length, 'crates.io package')} · checked ${checkedAt}`;
  if (r.msrv) md += ` · newest MSRV in the tree: **Rust ${esc(r.msrv.version)}** (${crateLink(r.msrv.crate, t)})`;
  md += '\n\n';

  if (r.security.length) {
    md += `#### Security advisories (${r.security.length})\n\n` + table(['Crate', 'Locked', 'Advisory', 'Upgrade to'],
      r.security.map(({ row, a }) => [crateLink(row.name, t), '`' + esc(row.version) + '`', `${advisoryLink(a, t)} ${esc(a.summary)}`, a.upgrade ? '`' + esc(a.upgrade) + '`' + (a.fixed.length > 1 ? ' (all fixes: ' + esc(a.fixed.join(', ')) + ')' : '') : 'no fix yet'])) + '\n';
  } else if (r.advisoriesChecked) md += `**Security advisories:** none for these exact versions (OSV, which includes RustSec).\n\n`;

  if (r.yanked.length) md += `#### Yanked versions (${r.yanked.length})\n\n` + table(['Crate', 'Locked', 'Newest'],
    r.yanked.map(row => [crateLink(row.name, t), '`' + esc(row.version) + '`', row.latest ? '`' + esc(row.latest) + '`' : ''])) + '\n';
  if (r.missing.length) md += `#### Not found on crates.io (${r.missing.length})\n\n` + r.missing.slice(0, MAX_ROWS).map(row => `- \`${esc(row.name)}\``).join('\n') + '\n\n';
  if (r.notices.length) md += fold(`Unmaintained or unsound (${r.notices.length})`, table(['Crate', 'Locked', 'Notice'],
    r.notices.map(({ row, a }) => [crateLink(row.name, t), '`' + esc(row.version) + '`', `${a.informational}: ${advisoryLink(a, t)} ${esc(a.summary)}`])), r.notices.length <= 5);

  const lic = [...r.copyleft.map(row => [crateLink(row.name, t), '`' + esc(row.version) + '`', `copyleft: \`${esc(row.license)}\``]),
    ...r.noLicense.map(row => [crateLink(row.name, t), '`' + esc(row.version) + '`', 'no license field'])];
  if (lic.length) md += fold(`Licenses to check (${lic.length})`, table(['Crate', 'Locked', 'Why'], lic), lic.length <= 5);
  else {
    const counts = {};
    for (const row of r.rows) if (row.license) counts[row.license] = (counts[row.license] || 0) + 1;
    const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([k, n]) => `${esc(k)} (${n})`).join(', ');
    if (top) md += `**Licenses:** no copyleft or missing licenses. Most common: ${top}.\n\n`;
  }

  if (r.behind.length) md += fold(`A breaking release behind (${r.behind.length})`, table(['Crate', 'Locked', 'Newest'],
    r.behind.map(row => [crateLink(row.name, t) + featuresLink(row.name, t), '`' + esc(row.version) + '`', '`' + esc(row.latest) + '`'])), false);

  if (r.directAdded.length || r.newPackages.length) {
    let body = '';
    if (r.directAdded.length) body += `**Added to Cargo.toml:** ${r.directAdded.slice(0, MAX_ROWS).map(d => `${crateLink(d.pkg, t)} \`${esc(d.req)}\`${d.kind && d.kind !== 'dependencies' ? ' (' + esc(d.kind) + ')' : ''}${featuresLink(d.pkg, t)}`).join(', ')}\n\n`;
    if (r.newPackages.length) body += table(['New in Cargo.lock', 'Version', 'License'], r.newPackages.map(row => [crateLink(row.name, t) + featuresLink(row.name, t), '`' + esc(row.version) + '`', esc(row.license || (row.license === null ? 'none' : ''))]));
    md += fold(`New dependencies in this PR (${r.directAdded.length} direct, ${r.newPackages.length} new in the lock file)`, body, r.newPackages.length <= 10);
  }

  if (r.notes.length) md += '\n' + r.notes.map(n => `> ${esc(n)}`).join('\n') + '\n';
  if (failOn.length) md += `\n<sub>This check fails on: ${failOn.join(', ')}.</sub>\n`;
  md += `\n<sub>[Tensorust Cargo Check](${SITE}/tools/cargo-check-action/) · advisories from [OSV](https://osv.dev/) (RustSec + GitHub) · versions from the crates.io index · paste any Cargo.toml into the [free checker](${SITE}/tools/cargo-toml-checker/)</sub>\n`;
  if (md.length > MAX_LEN) md = md.slice(0, MAX_LEN - 200) + `\n\n_Report cut to fit a GitHub comment. Full list in the job summary._\n`;
  return md;
}

export const LOCKED_MESSAGE = `${MARKER}\nTensorust Cargo Check is free on public repos. This repo is private, so it needs a license key ($9 a month per repo): get one at https://shop.tensorust.com/dev/cargo-check and add it as the \`license-key\` input.\n`;
