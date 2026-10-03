#!/usr/bin/env node
/**
 * Spike #3 — does Keycloak ENFORCE WebAuthn policy at enrolment?
 *
 * Config persistence is not enforcement. This drives a real WebAuthn ceremony
 * in Chrome using a CDP virtual authenticator and observes whether Keycloak
 * accepts or rejects the enrolment.
 *
 * Why this works without a hardware key:
 *   Chrome's CDP VirtualAuthenticatorOptions exposes `transport`
 *   (usb|nfc|ble|internal|hybrid) and `defaultBackupEligibility` /
 *   `defaultBackupState`, but NOT `aaguid`. So we cannot pin an arbitrary
 *   AAGUID -- but we CAN test:
 *     - attachment enforcement      (internal vs cross-platform)
 *     - synced/backup-eligible creds (defaultBackupState)
 *     - allowlist rejection          (bogus allowlist must reject EVERYTHING)
 *
 * Usage: node spike3-enrolment-test.mjs <realm> <transport> [--backup] [--uv-bad]
 */

import puppeteer from 'puppeteer-core';

const KC = 'http://localhost:8080';
const ADMIN = { user: 'admin', pass: 'lab-only-not-a-secret' };
const CDP = 'http://127.0.0.1:9222';
const TEST_PASSWORD = 'Spike-Lab-Password-123!';

const [, , realmArg, transportArg, ...flags] = process.argv;
const REALM = realmArg || 'attest-users';
const TRANSPORT = transportArg || 'usb';
const BACKUP_ELIGIBLE = flags.includes('--backup');
const UV_BAD = flags.includes('--uv-bad');

let adminToken;

async function api(method, path, body) {
  const res = await fetch(`${KC}/admin/realms${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${adminToken}`,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let parsed;
  try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; }
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${text.slice(0, 300)}`);
  return parsed;
}

async function login() {
  const res = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password', client_id: 'admin-cli',
      username: ADMIN.user, password: ADMIN.pass,
    }),
  });
  adminToken = (await res.json()).access_token;
}

/** Create/reset a test user with the passkey-registration required action set. */
async function ensureTestUser(realm) {
  const username = `spike-${realm}`;
  const actions = await api('GET', `/${realm}/authentication/required-actions`);
  // Alias is lowercase in Keycloak ('webauthn-register-passwordless').
  const wa = actions.find(a => a.alias.toLowerCase() === 'webauthn-register-passwordless');
  if (!wa) throw new Error('webauthn-register-passwordless required action not found');
  if (!wa.enabled) {
    await api('PUT', `/${realm}/authentication/required-actions/${wa.alias}`,
      { ...wa, enabled: true });
  }

  let users = await api('GET', `/${realm}/users?username=${encodeURIComponent(username)}&exact=true`);
  let user = users[0];
  if (!user) {
    await api('POST', `/${realm}/users`, {
      username, enabled: true, emailVerified: true,
      firstName: 'Spike', lastName: 'Lab', email: `${username}@example.test`,
      requiredActions: ['webauthn-register-passwordless'],
    });
    users = await api('GET', `/${realm}/users?username=${encodeURIComponent(username)}&exact=true`);
    user = users[0];
  }
  await api('PUT', `/${realm}/users/${user.id}/reset-password`,
    { type: 'password', value: TEST_PASSWORD, temporary: false });
  await api('PUT', `/${realm}/users/${user.id}`, {
    ...user, requiredActions: ['webauthn-register-passwordless'],
  });
  return user;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function main() {
  await login();
  const user = await ensureTestUser(REALM);

  // Clean slate + baseline. Without this, a credential left over from an
  // earlier run makes ANY subsequent test report a false ACCEPTED.
  const before = await api('GET', `/${REALM}/users/${user.id}/credentials`);
  const stale = before.filter(c => c.type === 'webauthn-passwordless' || c.type === 'webauthn');
  for (const c of stale) {
    await api('DELETE', `/${REALM}/users/${user.id}/credentials/${c.id}`).catch(() => {});
  }
  const baselineIds = new Set(
    before.filter(c => !stale.includes(c)).map(c => c.id));
  console.log(`baseline webauthn credentials: ${stale.length} (deleted)`);

  console.log(`realm=${REALM}  user=${user.username}  transport=${TRANSPORT}` +
    `${BACKUP_ELIGIBLE ? '  backup-eligible' : ''}${UV_BAD ? '  uv-broken' : ''}`);

  const browser = await puppeteer.connect({
    browserURL: CDP, defaultViewport: null, protocolTimeout: 30000,
  });
  const page = await browser.newPage();
  const client = await page.createCDPSession();

  await client.send('WebAuthn.enable');
  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: TRANSPORT,
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: !UV_BAD,
      automaticPresenceSimulation: true,
      defaultBackupEligibility: BACKUP_ELIGIBLE,
      defaultBackupState: BACKUP_ELIGIBLE,
    },
  });
  console.log(`virtual authenticator: ${authenticatorId}`);

  const consoleErrors = [];
  page.on('console', m => { if (m.type() === 'error') consoleErrors.push(m.text()); });

  // CRITICAL for automation: Keycloak's webauthnRegister.js calls
  // window.prompt() to ask for the credential label (returnSuccess()).
  // In headless Chrome an UNHANDLED prompt blocks the renderer indefinitely,
  // so the ceremony never completes and no credential is ever created.
  // Accept every dialog automatically.
  page.on('dialog', async d => {
    try { await d.accept('Spike Lab Key'); } catch { /* already dismissed */ }
  });

  // --- Step 1: sign in (password path exists on attest-users) ---
  await page.goto(`${KC}/realms/${REALM}/account/`, { waitUntil: 'networkidle2', timeout: 30000 });
  const url1 = page.url();
  if (url1.includes('/protocol/openid-connect/auth')) {
    await page.waitForSelector('#username', { timeout: 15000 });
    await page.type('#username', user.username);
    await page.type('#password', TEST_PASSWORD);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 }).catch(() => {}),
      page.click('#kc-login'),
    ]);
  }
  console.log(`after login: ${page.url()}`);

  // --- Step 2: the required-action page runs navigator.credentials.create() ---
  //
  // IMPORTANT: do NOT call page.evaluate() after the ceremony starts. A pending
  // WebAuthn dialog can block the renderer's JS context, which hangs any
  // Runtime.callFunctionOn. We click the real element and then determine the
  // outcome by polling the Admin API instead of reading the DOM.
  let outcome = 'UNKNOWN';
  let detail = '';
  try {
    const handle = await page.evaluateHandle(() => {
      const cands = [...document.querySelectorAll('input[type=submit], button')];
      return cands.find(e => /register|save|continue|submit/i.test(e.value || e.textContent || '')) || null;
    });
    const el = handle.asElement();
    if (!el) throw new Error('no register button found on required-action page');
    console.log('clicking register button (fire and forget)');
    el.click().catch(() => {});

    // The credential appearing in the Admin API (or not) is the verdict.
    // Require a credential whose id was NOT present at baseline.
    const known = new Set([...baselineIds, ...stale.map(c => c.id)]);
    let webauthn = [];
    for (let i = 0; i < 16; i++) {
      await sleep(1500);
      const creds = await api('GET', `/${REALM}/users/${user.id}/credentials`);
      webauthn = creds.filter(c =>
        (c.type === 'webauthn-passwordless' || c.type === 'webauthn') && !known.has(c.id));
      if (webauthn.length > 0) break;
    }

    if (webauthn.length > 0) {
      outcome = 'ACCEPTED';
      detail = JSON.stringify(webauthn.map(c => ({
        type: c.type,
        aaguid: c.aaguid ?? '(not exposed)',
        createdAt: c.createdDate ? new Date(c.createdDate).toISOString() : null,
        userLabel: c.userLabel,
      })));
    } else {
      outcome = 'REJECTED';
      detail = 'no credential created (enrolment refused or ceremony blocked)';
    }
  } catch (e) {
    outcome = 'ERROR';
    detail = e.message.slice(0, 220);
  }

  console.log(`\nOUTCOME: ${outcome}`);
  console.log(`DETAIL : ${detail}`);
  if (consoleErrors.length) console.log(`BROWSER ERRORS: ${consoleErrors.slice(0, 3).join(' | ')}`);

  await client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId }).catch(() => {});
  await page.close();
  browser.disconnect();
  process.exit(0);
}

main().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
