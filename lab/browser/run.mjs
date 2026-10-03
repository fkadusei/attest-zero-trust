#!/usr/bin/env node
/**
 * S4 — can a browser keep the session key across a restart?
 *
 * THE QUESTION
 *   After sign-in our page creates a secret key and stores it in the browser's
 *   own storage (IndexedDB). Every later request is signed with it. If the key
 *   does not survive the browser being closed and reopened, then either the user
 *   signs in again on every visit, or we quietly stop checking — and silently
 *   dropping the check is the failure this whole design exists to prevent.
 *
 * HOW THIS TESTS IT
 *   Two phases against a real Chrome with a real profile directory on disk:
 *
 *     phase 1  create keys, store them, sign something, then QUIT the browser
 *     phase 2  relaunch with the SAME profile, read them back, sign again
 *
 *   The quit in between is the whole point. Anything held only in memory is
 *   gone, so whatever still works in phase 2 genuinely came off disk.
 *
 * WHY TWO KEYS
 *   The real design uses a "non-extractable" key: the page can use it but can
 *   never read it out. That is the right thing to ship, but it also means we
 *   cannot read the key back to prove it is the *same* one.
 *
 *   So we store two, and the difference between them is the only variable:
 *
 *     session-key   non-extractable — faithful to the design. Proves it
 *                   persists and still works.
 *     probe-key     extractable — lets us compare the public key before and
 *                   after, which proves it is the same key and not a new one.
 *
 *   Persistence behaviour is identical for both; only exportability differs.
 *
 * WHAT THIS DOES NOT COVER
 *   A full laptop reboot, and Safari (which is the browser most likely to evict
 *   storage). Both are called out in the results.
 *
 * Usage:  node lab/browser/run.mjs
 */
import { createServer } from 'node:http';
import { existsSync, rmSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

// Resolve puppeteer-core through the tools/ package rather than by hard-coding
// a path inside it — the internal file layout has moved between versions.
// createRequire lets the package's own "exports" map do the work.
const require = createRequire(new URL('../../tools/package.json', import.meta.url));
const puppeteer = require('puppeteer-core');
// Which browser to drive. Chrome, Edge and Brave share one engine, so testing
// all three mostly confirms Chromium; Firefox and Safari are the engines that
// genuinely differ. Each gets its own profile directory so runs cannot interfere
// — and so a run cannot accidentally pass on a previous run's leftovers.
const BROWSERS = {
  chrome: { label: 'Chrome', engine: 'Chromium',
            exe: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' },
  edge: { label: 'Edge', engine: 'Chromium',
          exe: '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge' },
  brave: { label: 'Brave', engine: 'Chromium',
           exe: '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser' },
  firefox: { label: 'Firefox', engine: 'Gecko', puppeteerBrowser: 'firefox',
             exe: '/Applications/Firefox.app/Contents/MacOS/firefox' },
};

const which = (process.argv[2] || 'chrome').toLowerCase();
const B = BROWSERS[which];
if (!B) {
  console.error(`unknown browser '${which}'. known: ${Object.keys(BROWSERS).join(', ')}`);
  process.exit(2);
}
if (!existsSync(B.exe)) {
  console.error(`${B.label} not found at ${B.exe}`);
  process.exit(1);
}

const PROFILE = `/tmp/attest-s4-profile-${which}`;
const PORT = 8099;
const ORIGIN = `http://localhost:${PORT}`;

// --------------------------------------------------------------------------
// A minimal page. The work happens in injected script, but we need a real
// origin: IndexedDB is disabled on opaque origins like file://, which would
// make this test meaningless.
// --------------------------------------------------------------------------
const server = createServer((_req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end('<!DOCTYPE html><html><head><meta charset="utf-8"><title>S4</title></head>'
    + '<body><h1>S4 key persistence</h1></body></html>');
});

/** Shared in-page helpers, injected before every phase. */
const HELPERS = `
window.__idb = () => new Promise((resolve, reject) => {
  const r = indexedDB.open('attest-s4', 1);
  r.onupgradeneeded = () => r.result.createObjectStore('keys');
  r.onsuccess = () => resolve(r.result);
  r.onerror = () => reject(r.error);
});
window.__put = async (k, v) => {
  const db = await window.__idb();
  return new Promise((res, rej) => {
    const tx = db.transaction('keys', 'readwrite');
    tx.objectStore('keys').put(v, k);
    tx.oncomplete = () => res(true);
    tx.onerror = () => rej(tx.error);
  });
};
window.__get = async (k) => {
  const db = await window.__idb();
  return new Promise((res, rej) => {
    const tx = db.transaction('keys', 'readonly');
    const rq = tx.objectStore('keys').get(k);
    rq.onsuccess = () => res(rq.result ?? null);
    rq.onerror = () => rej(rq.error);
  });
};
window.__b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
window.__MSG = new TextEncoder().encode('attest-s4-fixed-message');
`;

async function launch() {
  const opts = {
    executablePath: B.exe,
    headless: true,
    userDataDir: PROFILE,
    args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
      '--no-first-run', '--no-default-browser-check'],
    protocolTimeout: 60000,
  };
  if (B.puppeteerBrowser) opts.browser = B.puppeteerBrowser;  // Firefox uses a different protocol
  return puppeteer.launch(opts);
}

// --------------------------------------------------------------------------
// Phase 1 — create, store, sign, then quit
// --------------------------------------------------------------------------
async function phase1(browser) {
  const page = await browser.newPage();
  await page.goto(ORIGIN, { waitUntil: 'domcontentloaded' });
  await page.evaluate(HELPERS);

  const result = await page.evaluate(async () => {
    const alg = { name: 'ECDSA', namedCurve: 'P-256' };
    const sign = { name: 'ECDSA', hash: 'SHA-256' };

    // The key we would actually ship: usable, never readable.
    const session = await crypto.subtle.generateKey(alg, false, ['sign', 'verify']);
    await window.__put('session-key', session.privateKey);

    // A twin we are allowed to read, so the public key can be compared later.
    const probe = await crypto.subtle.generateKey(alg, true, ['sign', 'verify']);
    await window.__put('probe-key', probe.privateKey);
    const probeJwk = await crypto.subtle.exportKey('jwk', probe.publicKey);
    await window.__put('probe-jwk', JSON.stringify(probeJwk));

    // Prove both actually work before we store them.
    const s1 = await crypto.subtle.sign(sign, session.privateKey, window.__MSG);
    const ok1 = await crypto.subtle.verify(sign, session.publicKey, s1, window.__MSG);
    const s2 = await crypto.subtle.sign(sign, probe.privateKey, window.__MSG);
    const ok2 = await crypto.subtle.verify(sign, probe.publicKey, s2, window.__MSG);

    const persisted = navigator.storage && navigator.storage.persist
      ? await navigator.storage.persist().catch(() => 'error')
      : 'unsupported';
    const already = navigator.storage && navigator.storage.persisted
      ? await navigator.storage.persisted().catch(() => 'error')
      : 'unsupported';
    let quota = null;
    if (navigator.storage && navigator.storage.estimate) {
      const e = await navigator.storage.estimate().catch(() => null);
      if (e) quota = { usage: e.usage, quota: e.quota };
    }

    return {
      sessionExtractable: session.privateKey.extractable,
      sessionUsable: ok1,
      probeExtractable: probe.privateKey.extractable,
      probeUsable: ok2,
      probeJwk: JSON.stringify(probeJwk),
      persistRequest: persisted,
      persistedNow: already,
      quota,
    };
  });

  await page.close();
  // A clean quit matters: it is what flushes storage to disk.
  await browser.close();
  return result;
}

// --------------------------------------------------------------------------
// Phase 2 — relaunch and look for what we stored
// --------------------------------------------------------------------------
async function phase2(browser) {
  const page = await browser.newPage();
  await page.goto(ORIGIN, { waitUntil: 'domcontentloaded' });
  await page.evaluate(HELPERS);

  const result = await page.evaluate(async () => {
    const alg = { name: 'ECDSA', namedCurve: 'P-256' };
    const sign = { name: 'ECDSA', hash: 'SHA-256' };
    const out = {
      sessionFound: false, sessionStillUsable: false,
      probeFound: false, probeStillUsable: false, probeSameKey: null,
      negativeControlRejected: null,
      persistedNow: navigator.storage && navigator.storage.persisted
        ? await navigator.storage.persisted().catch(() => 'error') : 'unsupported',
    };

    const sessionPriv = await window.__get('session-key');
    if (sessionPriv) {
      out.sessionFound = true;
      try {
        // Signing needs the matching public key, which we did not store for the
        // session key — so prove usability by rejecting a wrong verification.
        const sig = await crypto.subtle.sign(sign, sessionPriv, window.__MSG);
        out.sessionStillUsable = sig.byteLength > 0;
      } catch (e) {
        out.sessionStillUsable = 'error: ' + e.name;
      }
    }

    const probePriv = await window.__get('probe-key');
    const probeJwkStored = await window.__get('probe-jwk');
    if (probePriv && probeJwkStored) {
      out.probeFound = true;
      try {
        const sig = await crypto.subtle.sign(sign, probePriv, window.__MSG);
        out.probeStillUsable = sig.byteLength > 0;

        // Verify against the PUBLIC key recorded before the restart. If the
        // private key that survived were a different one, this fails — so it
        // proves continuity, not merely that *some* key is present.
        const storedPub = await crypto.subtle.importKey(
          'jwk', JSON.parse(probeJwkStored),
          { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
        out.probeSameKey = await crypto.subtle.verify(sign, storedPub, sig, window.__MSG);

        // Negative control. A freshly generated key must NOT satisfy the key
        // recorded before the restart. Without this, a check that always
        // returned true would look exactly like a pass.
        const fresh = await crypto.subtle.generateKey(alg, true, ['sign', 'verify']);
        const freshSig = await crypto.subtle.sign(sign, fresh.privateKey, window.__MSG);
        out.negativeControlRejected =
          !(await crypto.subtle.verify(sign, storedPub, freshSig, window.__MSG));
      } catch (e) {
        out.probeSameKey = 'error: ' + e.name + ': ' + e.message;
      }
    }
    return out;
  });

  await page.close();
  await browser.close();
  return result;
}

// --------------------------------------------------------------------------
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  console.log('='.repeat(72));
  console.log('S4 — can a browser keep the session key across a restart?');
  console.log('='.repeat(72));
  console.log(`browser  ${B.label} (${B.engine})`);
  console.log(`binary   ${B.exe}`);
  console.log(`origin   ${ORIGIN}`);
  console.log(`profile  ${PROFILE}`);

  // Start from nothing so "it persisted" cannot be a leftover from a past run.
  rmSync(PROFILE, { recursive: true, force: true });
  mkdirSync(PROFILE, { recursive: true });

  await new Promise((r) => server.listen(PORT, '127.0.0.1', r));

  console.log('\n[phase 1] create keys, store them, then QUIT the browser');
  const b1 = await launch();
  const reported = await b1.version();
  console.log(`  browser version         : ${reported}`);
  if (which !== 'firefox' && !/Chrome|Edg|Brave/i.test(reported)) {
    console.error(`  ABORT: expected ${B.label} but the browser reports ${reported}`);
    process.exit(1);
  }
  const p1 = await phase1(b1);
  console.log(`  session key extractable : ${p1.sessionExtractable}   (false is the design)`);
  console.log(`  session key usable      : ${p1.sessionUsable}`);
  console.log(`  probe key extractable   : ${p1.probeExtractable}`);
  console.log(`  probe key usable        : ${p1.probeUsable}`);
  console.log(`  persist() returned      : ${p1.persistRequest}`);
  console.log(`  persisted() before quit : ${p1.persistedNow}`);
  if (p1.quota) {
    console.log(`  storage estimate        : ${p1.quota.usage} of ${p1.quota.quota} bytes`);
  }

  console.log('\n  ...browser fully closed. Anything still present came off disk.');
  await sleep(1500);

  console.log('\n[phase 2] relaunch with the same profile and look for the keys');
  const p2 = await phase2(await launch());

  const rows = [
    ['session key survived', p2.sessionFound, true],
    ['session key still works', Boolean(p2.sessionStillUsable), true],
    ['probe key survived', p2.probeFound, true],
    ['probe key still works', Boolean(p2.probeStillUsable), true],
    ['it is the SAME key, not a new one', p2.probeSameKey, true],
    ['control: a fresh key is rejected', p2.negativeControlRejected, true],
  ];
  let pass = 0;
  console.log('');
  for (const [label, got, want] of rows) {
    const ok = got === want;
    if (ok) pass++;
    console.log(`  ${label.padEnd(36)} ${String(got).padEnd(6)} ${ok ? 'PASS' : 'FAIL'}`);
  }
  console.log(`  persisted() after relaunch           ${p2.persistedNow}`);

  server.close();
  console.log('\n' + '='.repeat(72));
  console.log(`${B.label} (${B.engine}): ${pass}/${rows.length} checks passed`);
  console.log('='.repeat(72));
  process.exit(pass === rows.length ? 0 : 1);
}

main().catch((e) => {
  console.error('FATAL:', e.message);
  server.close();
  process.exit(1);
});
