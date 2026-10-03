#!/usr/bin/env node
/**
 * Screenshot documentation pages, for eyeballing the build.
 *
 * Loads over file:// on purpose: that is the deployment target, so if a page
 * breaks when opened from disk (a blocked stylesheet, a missing script) this
 * shows it rather than hiding it behind a server.
 *
 * Usage:
 *   node tools/shoot.mjs docs/site/index.html out.png [--full] [--width 1440]
 *   node tools/shoot.mjs docs/site/plan.html out.png --theme light
 */
import { existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import puppeteer from 'puppeteer-core';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CHROME_CANDIDATES = [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
];

const args = process.argv.slice(2);
const flag = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : dflt;
};
const positional = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--')));
const [src, out] = positional;
if (!src || !out) {
  console.error('usage: node tools/shoot.mjs <page.html> <out.png> [--full] [--theme dark|light] [--width 1440] [--height 900]');
  process.exit(2);
}

const exe = CHROME_CANDIDATES.find((p) => existsSync(p));
if (!exe) {
  console.error('no Chrome found');
  process.exit(1);
}

const browser = await puppeteer.launch({
  executablePath: exe,
  headless: true,
  args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-first-run',
    '--allow-file-access-from-files'],
  protocolTimeout: 60000,
});

const page = await browser.newPage();
await page.setViewport({
  width: Number(flag('--width', 1440)),
  height: Number(flag('--height', 900)),
  deviceScaleFactor: 2,
});

const theme = flag('--theme', 'dark');
await page.evaluateOnNewDocument((t) => {
  try { localStorage.setItem('docs-theme', t); } catch (e) {}
}, theme);

// Allow `docs/site/plan.html#some-anchor` so a specific section can be framed.
const [srcPath, srcFrag] = src.split('#');
const url = pathToFileURL(resolve(ROOT, srcPath)).href + (srcFrag ? '#' + srcFrag : '');
const failures = [];
page.on('requestfailed', (r) => failures.push(`${r.url()} — ${r.failure()?.errorText}`));
page.on('pageerror', (e) => failures.push(`JS: ${e.message}`));

await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
await new Promise((r) => setTimeout(r, 400));

await page.screenshot({ path: resolve(ROOT, out), fullPage: args.includes('--full') });
await browser.close();

console.log(`wrote ${out}  (${theme}${args.includes('--full') ? ', full page' : ''})`);
if (failures.length) {
  console.error('page problems:');
  failures.forEach((f) => console.error('  - ' + f));
  process.exitCode = 1;
}
