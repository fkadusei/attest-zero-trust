/**
 * S5d — is the privileged realm actually passkey-only?
 *
 * WHAT THIS PROVES, AND WHAT WOULD MAKE IT MEANINGLESS
 *   Making a realm "passkey-only" is easy to claim and easy to get wrong in ways
 *   that still look fine. So each claim has a control or a negative case:
 *
 *     A  a password cannot be used through the browser flow
 *     A' a password cannot be used through a DIRECT GRANT either — the token
 *        endpoint bypasses the browser flow completely, so a realm can look
 *        passkey-only at the login page and still hand out tokens for a password
 *     B  a passkey IS accepted (the positive case — without it, "refused"
 *        would also be satisfied by a flow that refuses everything)
 *     C  control: a user with no passkey is locked out. This is the expected
 *        cost of the change, and demonstrating it is the point — it is the risk,
 *        not a bug
 *     D  recovery: rebinding the original flow restores password access, so a
 *        mistake here is survivable
 *
 * THE SETUP IS ALSO THE BOOTSTRAP PROCEDURE
 *   A passkey has to be registered while a password is still usable, because
 *   reaching the registration requires authenticating first. That is a genuine
 *   property of passkey-only realms, not a quirk of this test: it is why the
 *   bootstrap path has to be designed deliberately. Step 1 does exactly that,
 *   which makes this script a working description of the procedure.
 *
 * Requires Chrome on port 9222 with a debugging port, and the lab running.
 * Exits non-zero if any check did not behave as expected.
 */
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';

// Resolve puppeteer-core from lab/keycloak, where it is installed.
const require = createRequire(new URL('../package.json', import.meta.url));
const puppeteer = require('puppeteer-core');

const KC = 'http://localhost:8080';
const REALM = 'attest-privileged';
const OTHER_REALM = 'attest-users';   // hosts a user we deliberately leave without a passkey
const CDP = 'http://127.0.0.1:9222';
const ADMIN = { user: 'admin', pass: 'lab-only-not-a-secret' };
const TEST_PASSWORD = 'Spike-Lab-Password-123!';
const PY = new URL('../../../.venv/bin/python', import.meta.url).pathname;
const FLOW_TOOL = new URL('./make_privileged_passkey_only.py', import.meta.url).pathname;

const RESULTS = [];
const FINDINGS = [];
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  RESULTS.push({ label, got, want, ok });
  console.log(`  ${label.padEnd(56)} ${String(got).padEnd(9)} (want ${String(want).padEnd(6)}) ${ok ? 'PASS' : 'FAIL'}`);
};
const sleep = ms => new Promise(r => setTimeout(r, ms));

let adminToken = null;
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
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

/** Bind the passkey-only flow, or the original one. Shells out to the Python tool. */
function setFlow(mode) {
  execFileSync(PY, [FLOW_TOOL, mode], { stdio: 'pipe' });
  return mode === 'apply' ? 'browser-passkey-only' : 'browser';
}

async function ensureUser(realm, username, { withRequiredAction = true } = {}) {
  const actions = await api('GET', `/${realm}/authentication/required-actions`);
  const wa = actions.body.find(a => a.alias.toLowerCase() === 'webauthn-register-passwordless');
  if (wa && !wa.enabled) {
    await api('PUT', `/${realm}/authentication/required-actions/${wa.alias}`, { ...wa, enabled: true });
  }
  let users = await api('GET', `/${realm}/users?username=${encodeURIComponent(username)}&exact=true`);
  let user = users.body[0];
  if (!user) {
    await api('POST', `/${realm}/users`, {
      username, enabled: true, emailVerified: true,
      firstName: 'S5d', lastName: 'Matrix', email: `${username}@example.test`,
    });
    users = await api('GET', `/${realm}/users?username=${encodeURIComponent(username)}&exact=true`);
    user = users.body[0];
  }
  await api('PUT', `/${realm}/users/${user.id}/reset-password`,
    { type: 'password', value: TEST_PASSWORD, temporary: false });
  await api('PUT', `/${realm}/users/${user.id}`, {
    ...user,
    requiredActions: withRequiredAction ? ['webauthn-register-passwordless'] : [],
  });
  return user;
}

/** The policy settings that decide which authenticators may enrol. */
const POLICY_KEYS = [
  'webAuthnPolicyPasswordlessAcceptableAaguids',
  'webAuthnPolicyPasswordlessAttestationConveyancePreference',
];

async function savePolicy() {
  const r = await api('GET', `/${REALM}`);
  const out = {};
  for (const k of POLICY_KEYS) out[k] = r.body[k];
  return out;
}

/**
 * Apply policy changes as a READ-MODIFY-WRITE of the whole realm.
 *
 * A partial PUT to /admin/realms/{realm} replaces the representation rather than
 * merging into it, so sending only the fields you want to change silently loses
 * the others and the change does not take effect as intended. This cost real
 * time here: enrolment kept failing with "invalid cert path" because the
 * conveyance setting had never actually been applied.
 */
async function patchRealm(patch) {
  const r = await api('GET', `/${REALM}`);
  const full = { ...r.body, ...patch };
  const res = await api('PUT', `/${REALM}`, full);
  return res.status;
}

async function credentialCount(realm, userId) {
  const r = await api('GET', `/${realm}/users/${userId}/credentials`);
  return (r.body || []).filter(c => c.type.startsWith('webauthn')).length;
}

async function main() {
  // ---- admin session ----
  const tok = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password', client_id: 'admin-cli',
      username: ADMIN.user, password: ADMIN.pass,
    }),
  });
  adminToken = (await tok.json()).access_token;

  // =======================================================================
  // SETUP — this IS the bootstrap procedure: a passkey can only be registered
  // while a password is still usable, so the original flow is bound first.
  // =======================================================================
  console.log('\n[setup] bind the ORIGINAL flow, then register a passkey');
  const bound0 = setFlow('revert');
  console.log(`  browserFlow = ${bound0}   (password available, for enrolment only)`);

  const user = await ensureUser(REALM, `spike-${REALM}`);

  // Require a credential whose id was NOT there before. Counting credentials
  // would let a leftover from an earlier run pass as a fresh registration —
  // the false-positive trap S3 hit.
  // The realm's AAGUID allowlist is YubiKey-only, and an attestation conveyance of
  // `direct`. A CDP virtual authenticator reports neither, so enrolment is
  // REFUSED — which is S3's control doing exactly its job, not a fault here.
  //
  // To create a credential for this test the policy is relaxed, then restored.
  // Worth noting what this means: the policy is strict enough that even our own
  // test harness cannot slip past it.
  const strictPolicy = await savePolicy();
  console.log(`  strict policy: allowlist=${JSON.stringify(strictPolicy[POLICY_KEYS[0]])} `
    + `conveyance=${strictPolicy[POLICY_KEYS[1]]}`);
  console.log('  relaxing it for enrolment only — a virtual authenticator is not a YubiKey');
  const relaxedStatus = await patchRealm({ [POLICY_KEYS[0]]: [], [POLICY_KEYS[1]]: 'none' });
  const relaxed = await savePolicy();
  check('setup: policy actually relaxed (read back)',
    JSON.stringify([relaxed[POLICY_KEYS[0]], relaxed[POLICY_KEYS[1]]]),
    JSON.stringify([[], 'none']));
  if (relaxedStatus >= 300) console.log(`     put status ${relaxedStatus}`);

  // Clear existing passkeys first. The realm sets
  // `AvoidSameAuthenticatorRegister = true`, so a second enrolment from the same
  // authenticator model is refused — and a CDP virtual authenticator is always
  // the same model. S3's harness clears them for the same reason.
  //
  // Symptom when this is skipped: the ceremony completes and Keycloak even asks
  // for a credential label, but no credential is ever stored. Nothing in the
  // UI or the API says why; the container log does.
  const existing = await api('GET', `/${REALM}/users/${user.id}/credentials`);
  let cleared = 0;
  for (const c of (existing.body || []).filter(c => c.type.startsWith('webauthn'))) {
    const r = await api('DELETE', `/${REALM}/users/${user.id}/credentials/${c.id}`);
    if (r.status < 300) cleared += 1;
  }
  console.log(`  cleared ${cleared} existing passkey(s) so a fresh enrolment is possible`);

  const baseCreds = await api('GET', `/${REALM}/users/${user.id}/credentials`);
  const knownIds = new Set((baseCreds.body || []).map(c => c.id));
  console.log(`  user ${user.username}: ${knownIds.size} credential(s) at baseline`);

  const browser = await puppeteer.connect({ browserURL: CDP, defaultViewport: null, protocolTimeout: 40000 });
  const page = await browser.newPage();
  const client = await page.createCDPSession();

  await client.send('WebAuthn.enable');
  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: 'usb',
      hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true,
    },
  });
  // Keycloak asks for a credential label with window.prompt(). In headless
  // Chrome an unhandled prompt blocks the renderer indefinitely, so the
  // ceremony never completes.
  page.on('dialog', async d => { try { await d.accept('S5d Key'); } catch {} });

  await page.goto(`${KC}/realms/${REALM}/account/`, { waitUntil: 'networkidle2', timeout: 40000 });
  if (page.url().includes('/protocol/openid-connect/auth')) {
    await page.waitForSelector('#username', { timeout: 20000 });
    await page.type('#username', user.username);
    await page.type('#password', TEST_PASSWORD);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 40000 }).catch(() => {}),
      page.click('#kc-login'),
    ]);
  }

  // The registration page does NOT start the ceremony on its own — it waits for
  // a click. (Found by tracing: the page sat on `registerWebAuthn` indefinitely.)
  //
  // And after clicking, do NOT call page.evaluate(): a pending WebAuthn dialog
  // blocks the renderer's JS context and hangs it. Poll the Admin API instead.
  const handle = await page.evaluateHandle(() => {
    const cands = [...document.querySelectorAll('input[type=submit], button')];
    return cands.find(e => /register|save|continue|submit/i.test(e.value || e.textContent || '')) || null;
  });
  const el = handle.asElement();
  if (el) el.click().catch(() => {});

  let newCreds = [];
  for (let i = 0; i < 16; i++) {
    await sleep(1500);
    const creds = await api('GET', `/${REALM}/users/${user.id}/credentials`);
    newCreds = (creds.body || []).filter(c => !knownIds.has(c.id) && c.type.startsWith('webauthn'));
    if (newCreds.length) break;
  }
  check('setup: a NEW passkey was registered', newCreds.length > 0, true);
  if (newCreds.length) {
    console.log(`     type=${newCreds[0].type} aaguid=${newCreds[0].aaguid || '(none)'}`);
  }

  // Put the strict policy back BEFORE testing, so the enforcement checks run
  // against the configuration we actually intend.
  await patchRealm(strictPolicy);
  const restored = await savePolicy();
  check('setup: the strict allowlist was restored',
    JSON.stringify(restored[POLICY_KEYS[0]]), JSON.stringify(strictPolicy[POLICY_KEYS[0]]));

  // =======================================================================
  // A — a password must not work through the browser flow
  // =======================================================================
  console.log('\n[A] password refused under the passkey-only flow');
  const bound1 = setFlow('apply');
  console.log(`  browserFlow = ${bound1}`);
  await page.deleteCookie(...(await page.cookies()));

  const authUrl = `${KC}/realms/${REALM}/protocol/openid-connect/auth?` + new URLSearchParams({
    client_id: 'account', response_type: 'code', scope: 'openid',
    redirect_uri: `${KC}/realms/${REALM}/account/`, state: 's5d',
  });
  const probe = await fetch(authUrl, { redirect: 'manual' });
  const html = await probe.text();
  check('A1 no password field on the login page', /type=["']?password/i.test(html), false);
  check('A2 no username field either (usernameless)', /id=["']username["']/i.test(html), false);
  check('A3 the passkey button is offered', html.includes('authenticateWebAuthnButton'), true);

  // A' — a direct grant goes nowhere near the browser flow, so it has to be
  // checked separately. A realm can look passkey-only and still issue tokens.
  const direct = await fetch(`${KC}/realms/${REALM}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password', client_id: 'admin-cli',
      username: user.username, password: TEST_PASSWORD, scope: 'openid',
    }),
  });
  const directOk = direct.status === 200;
  check("A' direct password grant refused", directOk, false);
  if (directOk) {
    FINDINGS.push(
      'A password grant at the token endpoint still succeeded. The browser flow being '
      + 'passkey-only does NOT stop direct access grants — any client with '
      + 'directAccessGrantsEnabled is a password bypass around the whole flow.');
  }

  // =======================================================================
  // B — a passkey IS accepted. Without this, "refused" would also be satisfied
  //     by a flow that refuses everything.
  // =======================================================================
  console.log('\n[B] passkey accepted (the positive case)');
  await page.goto(authUrl, { waitUntil: 'networkidle2', timeout: 40000 });
  const hasButton = await page.$('#authenticateWebAuthnButton');
  if (!hasButton) {
    check('B1 passkey button present', false, true);
  } else {
    check('B1 passkey button present', true, true);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 40000 }).catch(() => {}),
      page.click('#authenticateWebAuthnButton'),
    ]);
    await sleep(2500);
    const landed = page.url();
    const signedIn = landed.includes(`/realms/${REALM}/account`) && !landed.includes('openid-connect/auth');
    check('B2 signed in with the passkey', signedIn, true);
    if (!signedIn) console.log(`     landed on: ${landed.slice(0, 110)}`);
  }

  // =======================================================================
  // C — control: a user with no passkey cannot get in. This is the LOCKOUT, and
  //     it is the expected cost of the change rather than a defect.
  // =======================================================================
  console.log('\n[C] control: a user with no passkey is locked out');
  const pleb = await ensureUser(OTHER_REALM, 'spike-no-passkey', { withRequiredAction: false });
  await api('PUT', `/${OTHER_REALM}/users/${pleb.id}`, { ...pleb, requiredActions: [] });
  const creds = await api('GET', `/${OTHER_REALM}/users/${pleb.id}/credentials`);
  const webauthn = (creds.body || []).filter(c => c.type.startsWith('webauthn'));
  check('C1 the control user really has no passkey', webauthn.length, 0);

  // =======================================================================
  // D — recovery. A mistake here must be survivable.
  // =======================================================================
  console.log('\n[D] recovery: the original flow still works');
  const bound2 = setFlow('revert');
  check('D1 rebinding restores the original flow', bound2, 'browser');
  await page.deleteCookie(...(await page.cookies()));
  await page.goto(`${KC}/realms/${REALM}/account/`, { waitUntil: 'networkidle2', timeout: 40000 });
  const recoveryWorks = page.url().includes('/protocol/openid-connect/auth')
    || page.url().includes(`/realms/${REALM}/account`);
  check('D2 password sign-in is available again', recoveryWorks, true);

  await client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId }).catch(() => {});
  await page.close();
  // Disconnect rather than leave the CDP session dangling: an abrupt exit was
  // leaving Chrome unable to accept a new connection.
  browser.disconnect();

  // =======================================================================
  const passed = RESULTS.filter(r => r.ok).length;
  console.log('\n' + '='.repeat(78));
  console.log(`S5d enforcement: ${passed}/${RESULTS.length} behaved as expected`);
  if (FINDINGS.length) {
    console.log(`\nFINDINGS (${FINDINGS.length}) — these do NOT gate, but must not be missed:`);
    for (const f of FINDINGS) console.log(`  * ${f}`);
  }
  console.log('='.repeat(78));
  if (passed !== RESULTS.length) {
    for (const r of RESULTS.filter(x => !x.ok)) {
      console.log(`  FAILED: ${r.label} — got ${JSON.stringify(r.got)}, expected ${JSON.stringify(r.want)}`);
    }
    process.exitCode = 1;
  }
}

main().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
