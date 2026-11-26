// Static sanity checks that a linter would not catch: the manifest must point at
// files that exist, and nothing in the extension may reach for the network.

import { readFile, readdir, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const problems = [];
const notes = [];

function fail(message) {
  problems.push(message);
}

async function walk(dir, out = []) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (['node_modules', '.git', 'dist'].includes(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) await walk(full, out);
    else out.push(full);
  }
  return out;
}

const manifest = JSON.parse(await readFile(path.join(root, 'manifest.json'), 'utf8'));

// 1. Every path the manifest references must exist.
const referenced = [
  manifest.background?.service_worker,
  manifest.options_page,
  manifest.action?.default_popup,
  ...Object.values(manifest.icons ?? {}),
  ...Object.values(manifest.action?.default_icon ?? {}),
].filter(Boolean);

for (const rel of referenced) {
  if (!existsSync(path.join(root, rel))) fail(`manifest references a missing file: ${rel}`);
}

// 2. Permissions should stay minimal; flag anything beyond what the code uses.
const ALLOWED_PERMISSIONS = new Set(['storage', 'alarms', 'activeTab', 'scripting']);
for (const permission of manifest.permissions ?? []) {
  if (!ALLOWED_PERMISSIONS.has(permission)) {
    fail(`unexpected permission "${permission}" — justify it or drop it`);
  }
}
if ((manifest.host_permissions ?? []).length > 0) {
  fail('host_permissions must stay empty: this extension never talks to a site');
}

// 3. No remote code, no network calls, no analytics.
const files = await walk(path.join(root, 'src'));
files.push(path.join(root, 'manifest.json'));
const NETWORK = [
  [/\bXMLHttpRequest\b/, 'XMLHttpRequest'],
  [/\bnavigator\.sendBeacon\b/, 'sendBeacon'],
  [/\bimportScripts\s*\(/, 'importScripts'],
  [/\beval\s*\(/, 'eval'],
  [/https?:\/\/(?!www\.w3\.org)[^\s'"`)]+/, 'remote URL'],
];
/** Drop comments so prose about fetch()/import() does not trip the scanners. */
function stripComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
    .replace(/<!--[\s\S]*?-->/g, '');
}

for (const file of files) {
  const source = stripComments(await readFile(file, 'utf8'));
  const rel = path.relative(root, file);
  for (const [pattern, label] of NETWORK) {
    const match = source.match(pattern);
    if (match) fail(`${rel}: contains ${label} (${match[0].slice(0, 60)})`);
  }
  if (/\bfetch\s*\(/.test(source)) fail(`${rel}: unexpected fetch()`);
  // Account labels come from whatever site issued the secret, so no HTML sinks.
  if (/\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b/.test(source)) {
    fail(`${rel}: builds DOM from a string — use createElement/textContent`);
  }
  // Dynamic import() is rejected inside an MV3 service worker.
  if (rel.startsWith('src/background') && /\bimport\s*\(/.test(source)) {
    fail(`${rel}: dynamic import() is not allowed in a service worker`);
  }
}

// 4. Every HTML page must only load local scripts.
for (const page of files.filter((f) => f.endsWith('.html'))) {
  const source = await readFile(page, 'utf8');
  for (const [, src] of source.matchAll(/<script[^>]*src="([^"]+)"/g)) {
    const resolved = path.resolve(path.dirname(page), src);
    if (!existsSync(resolved)) fail(`${path.relative(root, page)}: missing script ${src}`);
  }
}

// 5. Vendored code must ship with its licence.
if (existsSync(path.join(root, 'vendor/jsqr.js')) && !existsSync(path.join(root, 'vendor/jsqr-LICENSE.txt'))) {
  fail('vendor/jsqr.js ships without its licence file');
}

const totalBytes = (
  await Promise.all([...files, path.join(root, 'vendor/jsqr.js')].map(async (f) => (await stat(f)).size))
).reduce((a, b) => a + b, 0);
notes.push(`${files.length} source files, ${(totalBytes / 1024).toFixed(0)} KB unpacked`);
notes.push(`permissions: ${(manifest.permissions ?? []).join(', ') || 'none'}`);

for (const note of notes) console.log(`  ${note}`);
if (problems.length > 0) {
  console.error('\ncheck failed:');
  for (const problem of problems) console.error(`  ✖ ${problem}`);
  process.exit(1);
}
console.log('\ncheck passed');
