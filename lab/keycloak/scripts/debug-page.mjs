#!/usr/bin/env node
/**
 * Diagnostic: dump what the webauthn-register-passwordless page actually does.
 * Does NOT click. Captures page errors, console output, and the HTML so we can
 * see whether the ceremony is even reachable in headless Chrome.
 */
import puppeteer from 'puppeteer-core';
import { writeFileSync } from 'node:fs';

const KC = 'http://localhost:8080';
const CDP = 'http://127.0.0.1:9222';
const REALM = process.argv[2] || 'attest-users';
const TRANSPORT = process.argv[3] || 'usb';
const PASSWORD = 'Spike-Lab-Password-123!';

const sleep = ms => new Promise(r => setTimeout(r, ms));
let adminToken;
async function api(method, path, body) {
  const res = await fetch(`${KC}/admin/realms${path}`, {
    method,
    headers: { Authorization: `Bearer ${adminToken}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const t = await res.text();
  try { return t ? JSON.parse(t) : null; } catch { return t; }
}

async function main() {
  const tokRes = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: 'lab-only-not-a-secret' }),
  });
  adminToken = (await tokRes.json()).access_token;
  const users = await api('GET', `/${REALM}/users?username=spike-${REALM}&exact=true`);
  const user = users[0];
  console.log('user:', user?.username, user?.id);

  const browser = await puppeteer.connect({ browserURL: CDP, defaultViewport: null, protocolTimeout: 20000 });
  const page = await browser.newPage();
  const client = await page.createCDPSession();

  const logs = [], errors = [];
  page.on('console', m => logs.push(`[${m.type()}] ${m.text()}`));
  page.on('pageerror', e => errors.push(String(e)));

  await client.send('WebAuthn.enable');
  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: TRANSPORT,
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  console.log('authenticator:', authenticatorId, 'transport:', TRANSPORT);

  await page.goto(`${KC}/realms/${REALM}/account/`, { waitUntil: 'networkidle2', timeout: 30000 });
  if (page.url().includes('/protocol/openid-connect/auth')) {
    await page.waitForSelector('#username', { timeout: 15000 });
    await page.type('#username', user.username);
    await page.type('#password', PASSWORD);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 }).catch(() => {}),
      page.click('#kc-login'),
    ]);
  }
  console.log('url:', page.url());

  // Inspect the required-action page WITHOUT clicking.
  const info = await page.evaluate(() => ({
    title: document.title,
    forms: [...document.querySelectorAll('form')].map(f => ({
      id: f.id, action: f.getAttribute('action'),
      buttons: [...f.querySelectorAll('button,input[type=submit]')].map(b => ({ id: b.id, name: b.getAttribute('name'), value: b.value, text: (b.textContent || '').trim().slice(0, 40) })),
    })),
    scripts: [...document.querySelectorAll('script')].map(s => s.src || '(inline)').slice(0, 12),
    hasWebAuthn: typeof navigator.credentials?.create === 'function',
    isSecureContext: window.isSecureContext,
    bodyText: document.body.innerText.replace(/\s+/g, ' ').slice(0, 400),
  }));

  console.log('\n=== PAGE INFO ===');
  console.log(JSON.stringify(info, null, 2));

  // Inspect what navigator.credentials.create would be asked for, by reading
  // the challenge Keycloak embeds (if any).
  const pkOptions = await page.evaluate(() => {
    const el = document.getElementById('passkey-params') || document.querySelector('[data-passkey]');
    return el ? el.textContent.slice(0, 600) : null;
  }).catch(() => null);
  console.log('\nembedded passkey params:', pkOptions);

  console.log('\n=== CONSOLE ===');
  logs.slice(0, 25).forEach(l => console.log(' ', l));
  console.log('\n=== PAGE ERRORS ===');
  errors.slice(0, 10).forEach(l => console.log(' ', l));

  const html = await page.content();
  writeFileSync('/tmp/kc-required-action.html', html);
  console.log('\nHTML saved to /tmp/kc-required-action.html (' + html.length + ' bytes)');

  await client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId }).catch(() => {});
  await page.close();
  browser.disconnect();
  process.exit(0);
}
main().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
