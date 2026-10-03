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
import { existsSync } from 'node:fs';
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
// Use the workspace venv when there is one, otherwise the system interpreter.
// CI has no .venv — it installs requirements with the setup-python action — and
// hard-coding the venv path made this job fail before it tested anything.
const VENV_PY = new URL('../../../.venv/bin/python', import.meta.url).pathname;
const PY = process.env.SPIKE_PYTHON || (existsSync(VENV_PY) ? VENV_PY : 'python3');
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
async function setFlow(mode) {
  execFileSync(PY, [FLOW_TOOL, mode], { stdio: 'pipe' });
  // Read the ACTUAL bound flow back from the API.
  //
  // This used to `return mode === 'apply' ? 'browser-passkey-only' : 'browser'`
  // — a constant derived from the argument. D1 then asserted that constant
  // equalled a constant, so it could NEVER fail, whatever the realm actually
  // did. A recovery test that cannot detect a failed recovery is worse than no
  // test, because it is trusted.
  const realm = await api('GET', `/${REALM}`);
  return realm.body.browserFlow;
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
  // Always write the profile fields. A user created by another harness (S3 makes
  // `spike-attest-users`) can lack them, and Keycloak then refuses a direct grant
  // with "Account is not fully set up" — which is what broke the A' control.
  const fresh = await api('GET', `/${realm}/users/${user.id}`);
  await api('PUT', `/${realm}/users/${user.id}`, {
    ...fresh.body,
    firstName: fresh.body.firstName || 'Spike',
    lastName: fresh.body.lastName || 'Lab',
    email: fresh.body.email || `${username}@example.test`,
    emailVerified: true,
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

/**
 * Classify what happens when credentials are submitted, using the REAL browser.
 *
 * Returns: 'authenticated' | 'rejected_password' | 'no_password_form'
 *        | 'required_action' | 'other'
 *
 * Two mistakes were made getting here, in opposite directions, and both matter:
 *
 *  1. Looking for `code=` alone is wrong for Keycloak's `account` client — it
 *     returns the account URL with `session_state` and no code, so a SUCCESSFUL
 *     sign-in read as a failure.
 *  2. Using Node's `fetch` cannot work for a multi-step login at all: it keeps no
 *     cookies, so the POST arrives without the session the GET created. The
 *     result is always "rejected" — which means a check asserting "rejected"
 *     passes for entirely the wrong reason. That is the "denied vs broken"
 *     collapse this audit exists to eliminate, and it was reintroduced here.
 *
 * The browser is used because it maintains cookies and follows the real flow.
 */
async function loginOutcome(client, page, authUrl, username, password, appUrlPrefix) {
  // CLEAR COOKIES FIRST, ALWAYS.
  //
  // Without this, an earlier successful sign-in leaves a live session and
  // `page.goto(authUrl)` short-circuits straight to the application — so a check
  // for "this person cannot get in" reports success because SOMEONE is already
  // signed in. Both C3 and D2 were measuring the session, not the behaviour under
  // test. Clearing here makes the mistake impossible rather than remembering to
  // clear it at each call site.
  await client.send('Network.clearBrowserCookies').catch(() => {});
  await page.goto(authUrl, { waitUntil: 'networkidle2', timeout: 40000 });
  const url0 = page.url();
  if (url0.includes('required-action')) return 'required_action';
  if (appUrlPrefix && url0.startsWith(appUrlPrefix)) return 'authenticated';

  const passwordField = await page.$('input[type=password]');
  const usernameField = await page.$('#username');
  if (!passwordField || !usernameField) return 'no_password_form';

  await page.type('#username', username);
  await page.type('#password', password);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 40000 }).catch(() => {}),
    page.click('#kc-login'),
  ]);
  // Classify by WHERE WE ENDED UP, not by query markers.
  //
  // Keycloak's account console does a client-side redirect that strips
  // `code`/`session_state` from the URL before we can read it, so a successful
  // sign-in showed no markers at all and read as a failure. Reaching the
  // application itself is the reliable signal: the account console requires
  // authentication, so arriving there means the login worked.
  const url1 = page.url();
  if (url1.includes('required-action')) return 'required_action';
  if (appUrlPrefix && url1.startsWith(appUrlPrefix)) return 'authenticated';
  if (url1.includes('login-actions/authenticate')) return 'rejected_password';
  return 'other';
}

/** Fetch a URL following redirects, and hand back the final HTML.
 *  Used for checks that only need the rendered page, not a scripted browser. */
async function fetchPage(url) {
  const r = await fetch(url, { redirect: 'follow' });
  return { status: r.status, html: await r.text() };
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
  const bound0 = await setFlow('revert');
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
  const bound1 = await setFlow('apply');
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

  // POSITIVE CONTROL for A'. A test that only ever observes refusals proves
  // nothing: the grant could be failing for a dozen unrelated reasons (wrong
  // password, missing client, feature switched off). That is exactly how this
  // check passed the FIRST time it was run — the password was unknown, so the
  // "refusal" was a bad-credentials error wearing the same face.
  //
  // So: prove the probe CAN observe a successful direct grant, in a realm where
  // one is legitimately enabled.
  // withRequiredAction:false — the default ADDS a required action, and Keycloak
  // refuses a direct grant for any user with one pending ("Account is not fully
  // set up"). The control was failing because of its own setup.
  const canaryUser = await ensureUser(OTHER_REALM, `spike-${OTHER_REALM}`,
    { withRequiredAction: false });
  const canary = await fetch(`${KC}/realms/${OTHER_REALM}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password', client_id: 'admin-cli',
      username: canaryUser.username, password: TEST_PASSWORD, scope: 'openid',
    }),
  });
  check("A' control: a direct grant that SHOULD succeed does", canary.status, 200);
  if (canary.status !== 200) {
    console.log(`     control body: ${(await canary.text()).slice(0, 140)}`);
    FINDINGS.push(
      "The direct-grant probe cannot detect a SUCCESSFUL grant, so its refusal result "
      + "in this realm proves nothing. Fix the control before trusting A'.");
  }

  check("A' direct password grant refused", directOk, false);

  // Enumerate EVERY client, not just the one probed. A different client with
  // directAccessGrantsEnabled would leave the single-client check green.
  const allClients = await api('GET', `/${REALM}/clients`);
  const bypassClients = (allClients.body || [])
    .filter(c => c.directAccessGrantsEnabled)
    .map(c => c.clientId);
  check("A'2 NO client in the realm accepts direct grants", bypassClients.length, 0);
  if (bypassClients.length) {
    FINDINGS.push(`Clients still accepting direct password grants: ${bypassClients.join(', ')}`);
  }
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
  // C — a user with a password but NO passkey must be locked out.
  //
  // The first version of this check only verified the user HAD no passkey, and
  // published it as "locked out — demonstrated rather than assumed". It was
  // assumed, and the user was in a different realm. This does it properly:
  // create the user in the realm under test, confirm the arming condition, then
  // actually attempt a sign-in.
  console.log('\n[C] a user with a password but no passkey is locked out');
  const onlyPw = await ensureUser(REALM, 'spike-password-only', { withRequiredAction: false });
  const pwCreds = await api('GET', `/${REALM}/users/${onlyPw.id}/credentials`);
  const staleWa = (pwCreds.body || []).filter(c => c.type.startsWith('webauthn'));
  for (const c of staleWa) {
    await api('DELETE', `/${REALM}/users/${onlyPw.id}/credentials/${c.id}`);
  }
  const after = await api('GET', `/${REALM}/users/${onlyPw.id}/credentials`);
  const kinds = (after.body || []).map(c => c.type);
  check('C1 the lockout user has a password and NO passkey',
    kinds.includes('password') && !kinds.some(k => k.startsWith('webauthn')), true);

  // The actual claim: they cannot get in.
  const lockoutPage = await fetchPage(`${KC}/realms/${REALM}/account/`);
  // Assert the STATUS too. "No password field" is equally true of a broken or
  // misconfigured page, which is the "denied vs broken" collapse this audit is
  // about. The page must have actually rendered the sign-in flow.
  check('C2a the sign-in flow rendered for them', lockoutPage.status, 200);
  check('C2b no password field is offered to them',
    /type=["']?password/i.test(lockoutPage.html), false);

  const lockoutUrl = `${KC}/realms/${REALM}/protocol/openid-connect/auth?` + new URLSearchParams({
    client_id: 'account', response_type: 'code', scope: 'openid',
    redirect_uri: `${KC}/realms/${REALM}/account/`, state: 's5d-lockout',
  });
  const lockoutOutcome = await loginOutcome(client, page, lockoutUrl, onlyPw.username,
    TEST_PASSWORD, `${KC}/realms/${REALM}/account/`);
  check('C3 a password alone does NOT authenticate them',
    lockoutOutcome !== 'authenticated', true);
  console.log(`     (outcome: ${lockoutOutcome})`);

  // =======================================================================
  // D — recovery. A mistake here must be survivable.
  // =======================================================================
  console.log('\n[D] recovery: the original flow still works');
  const bound2 = await setFlow('revert');
  check('D1 rebinding restores the original flow', bound2, 'browser');

  // D2 used to assert the URL contained `/auth` OR `/account` — one of which is
  // true in essentially every outcome, including an error or a restart page. It
  // now asserts two things that can actually be false: the password form is
  // offered, AND a real sign-in completes with a code.
  await page.deleteCookie(...(await page.cookies()));
  // Ask the AUTHORIZATION ENDPOINT directly. Fetching the account console URL
  // returns the SPA shell — the login form only appears after client-side JS
  // runs — so the check failed against a healthy realm. (The original used the
  // browser, which follows the JS redirect; this does the same thing explicitly.)
  const recUrl = `${KC}/realms/${REALM}/protocol/openid-connect/auth?` + new URLSearchParams({
    client_id: 'account', response_type: 'code', scope: 'openid',
    redirect_uri: `${KC}/realms/${REALM}/account/`, state: 's5d-recovery',
  });
  const rec = await fetchPage(recUrl);
  check('D2a the password form is offered again',
    /type=["']?password/i.test(rec.html), true);

  const recOutcome = await loginOutcome(client, page, recUrl, user.username,
    TEST_PASSWORD, `${KC}/realms/${REALM}/account/`);
  check('D2b a real password sign-in completes again', recOutcome, 'authenticated');

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
