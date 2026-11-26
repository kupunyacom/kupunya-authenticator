// Build the .zip you upload to the Chrome Web Store (or keep for yourself).
// Uses the system `zip`, so there is nothing to install.

import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, readFileSync, existsSync } from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const { version } = JSON.parse(readFileSync(path.join(root, 'manifest.json'), 'utf8'));
const dist = path.join(root, 'dist');
const output = path.join(dist, `kupunya-authenticator-${version}.zip`);

execFileSync('node', ['tools/check.mjs'], { cwd: root, stdio: 'inherit' });

mkdirSync(dist, { recursive: true });
if (existsSync(output)) rmSync(output);

execFileSync(
  'zip',
  ['-r', '-q', output, 'manifest.json', 'src', 'vendor', 'LICENSE', '-x', '*.DS_Store'],
  { cwd: root, stdio: 'inherit' },
);

console.log(`\npackaged ${path.relative(root, output)}`);
