#!/usr/bin/env node
/**
 * Pre-render Mermaid diagrams to inline SVG.
 *
 * Mermaid normally runs in the reader's browser, which would mean shipping a
 * ~5 MB library into pages that must work offline from `file://`. So we render
 * once, at build time, and commit the SVG. The reader gets crisp vector art and
 * downloads nothing.
 *
 * Both palettes are rendered because Mermaid bakes colours into the output and
 * CSS cannot re-theme it; docs.css shows whichever matches the active theme.
 *
 * Reuses the system Chrome — no browser download. Attaches to an existing
 * Chrome on the debug port if there is one, otherwise launches its own.
 *
 * Usage:
 *   cd tools && npm install          # once: mermaid + puppeteer-core
 *   node tools/render_diagrams.mjs
 *   node tools/render_diagrams.mjs --port 9222
 */
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync, rmSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import puppeteer from 'puppeteer-core';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'docs', 'site', 'diagrams');
const MERMAID_JS = join(ROOT, 'tools', 'node_modules', 'mermaid', 'dist', 'mermaid.min.js');

const CHROME_CANDIDATES = [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
];

const PORT = (() => {
  const i = process.argv.indexOf('--port');
  return i >= 0 ? Number(process.argv[i + 1]) : 9222;
})();
const CDP = `http://127.0.0.1:${PORT}`;

/**
 * Must match diagram_slug() in scripts/build_docs.py byte for byte.
 *
 * The content hash is not decoration: keying on the first line alone collides
 * ("sequenceDiagram" appears more than once), and a collision silently drops a
 * diagram. The hash also means edited source gets a fresh file instead of
 * serving a stale render.
 */
const slug = (code) => {
  const body = code.trim();
  const first = body.split('\n')[0] || 'diagram';
  const base = first.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '').slice(0, 40);
  const digest = createHash('sha256').update(body, 'utf8').digest('hex').slice(0, 8);
  return `${base}-${digest}`;
};

const FONT = 'ui-sans-serif, -apple-system, "Segoe UI", Inter, Roboto, Arial, sans-serif';

const THEMES = {
  dark: {
    darkMode: true,
    background: 'transparent',
    primaryColor: '#16233c',
    primaryTextColor: '#c3cedd',
    primaryBorderColor: '#2f4770',
    lineColor: '#4a5a75',
    secondaryColor: '#1b1730',
    tertiaryColor: '#0f2624',
    edgeLabelBackground: '#131a24',
    clusterBkg: '#0e131c',
    clusterBorder: '#24304a',
    titleColor: '#e8eef7',
    nodeTextColor: '#c3cedd',
  },
  light: {
    darkMode: false,
    background: 'transparent',
    primaryColor: '#e8f0ff',
    primaryTextColor: '#2a3a52',
    primaryBorderColor: '#b9cdf3',
    lineColor: '#9aabc4',
    secondaryColor: '#f0ecfe',
    tertiaryColor: '#e6f7f4',
    edgeLabelBackground: '#ffffff',
    clusterBkg: '#f4f7fb',
    clusterBorder: '#d7e0ee',
    titleColor: '#0f1724',
    nodeTextColor: '#2a3a52',
  },
};

function markdownFiles(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (e.name.startsWith('.') || e.name === 'node_modules') continue;
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.md')) out.push(p);
    }
  };
  if (existsSync(dir)) walk(dir);
  return out;
}

function collect() {
  const found = new Map();
  for (const dir of ['docs', 'lab'].map((d) => join(ROOT, d))) {
    for (const file of markdownFiles(dir)) {
      const text = readFileSync(file, 'utf8');
      const re = /```mermaid\n([\s\S]*?)```/g;
      let m;
      while ((m = re.exec(text)) !== null) {
        const code = m[1].trim();
        const name = slug(code);
        if (name && !found.has(name)) found.set(name, { code, file: relative(ROOT, file) });
      }
    }
  }
  return found;
}

/** Attach to a running Chrome, or start one we control. */
async function getBrowser() {
  try {
    const b = await puppeteer.connect({
      browserURL: CDP, defaultViewport: null, protocolTimeout: 60000,
    });
    console.log(`attached to Chrome on ${CDP}`);
    return { browser: b, owned: false };
  } catch {
    const exe = CHROME_CANDIDATES.find((p) => existsSync(p));
    if (!exe) {
      console.error('No Chrome/Chromium found. Install one, or start it on the debug port.');
      process.exit(1);
    }
    const b = await puppeteer.launch({
      executablePath: exe,
      headless: true,
      // --no-sandbox is required when Chrome's own sandbox cannot initialise,
      // which is the case inside the DSH sandbox.
      args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-first-run'],
      protocolTimeout: 60000,
    });
    console.log('launched a headless Chrome');
    return { browser: b, owned: true };
  }
}

async function main() {
  if (!existsSync(MERMAID_JS)) {
    console.error(`mermaid not found at ${relative(ROOT, MERMAID_JS)}`);
    console.error('Install it with:  cd tools && npm install');
    process.exit(1);
  }

  const diagrams = collect();
  if (diagrams.size === 0) {
    console.log('no mermaid diagrams found');
    return;
  }
  console.log(`found ${diagrams.size} diagram(s)`);

  const { browser, owned } = await getBrowser();
  const page = await browser.newPage();
  await page.setContent('<!DOCTYPE html><html><body><div id="host"></div></body></html>');
  await page.addScriptTag({ content: readFileSync(MERMAID_JS, 'utf8') });

  mkdirSync(OUT, { recursive: true });

  // Content-addressed names mean an edited diagram leaves its old render
  // behind. Clear stale SVGs so the directory always matches the sources.
  const expected = new Set();
  for (const name of diagrams.keys()) {
    expected.add(`${name}-dark.svg`);
    expected.add(`${name}-light.svg`);
  }
  for (const f of readdirSync(OUT)) {
    if (f.endsWith('.svg') && !expected.has(f)) {
      rmSync(join(OUT, f));
      console.log(`  removed stale ${f}`);
    }
  }

  let ok = 0;
  const failed = [];

  for (const [name, { code, file }] of diagrams) {
    const variants = [];
    for (const [variant, variables] of Object.entries(THEMES)) {
      const result = await page.evaluate(
        async (src, vars, id) => {
          try {
            window.mermaid.initialize({
              startOnLoad: false,
              theme: 'base',
              securityLevel: 'loose',
              fontFamily: vars.fontFamily,
              themeVariables: vars,
            });
            const { svg } = await window.mermaid.render(id, src);
            return { ok: true, svg };
          } catch (e) {
            return { ok: false, error: String(e && e.message ? e.message : e) };
          }
        },
        code,
        { ...variables, fontFamily: FONT },
        `d-${name}-${variant}`,
      );

      if (!result.ok) {
        console.error(`  FAIL ${name} (${variant}): ${result.error}`);
        failed.push(`${name}/${variant}`);
        continue;
      }
      // An XML prolog is invalid inside inline HTML.
      const svg = result.svg.replace(/^<\?xml[^>]*\?>\s*/, '').trim();
      writeFileSync(join(OUT, `${name}-${variant}.svg`), svg + '\n', 'utf8');
      variants.push(variant);
      ok++;
    }
    console.log(`  ${name} [${variants.join(', ')}]  from ${file}`);
  }

  await page.close();
  if (owned) await browser.close();
  else browser.disconnect();

  console.log(`\nwrote ${ok} SVG file(s) to docs/site/diagrams/`);
  if (failed.length) {
    console.error(`failed: ${failed.join(', ')}`);
    process.exitCode = 1;
  }
  console.log('next:  .venv/bin/python scripts/build_docs.py');
}

main().catch((e) => {
  console.error('FATAL:', e.message);
  process.exit(1);
});
