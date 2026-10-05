#!/usr/bin/env node
/**
 * The console, end to end, in a real browser.
 *
 * WHAT THIS PROVES THAT NO UNIT TEST CAN
 *
 * Every console test so far stubs the provider. The flow logic is covered; whether a
 * real browser can actually complete the round trip is not. This drives the whole
 * thing for real:
 *
 *   browser → /console → /console/login → Keycloak → passkey ceremony
 *           → /console/callback → code exchange → session cookie → /console
 *
 * It covers three things that only exist when all the parts are connected:
 *
 *   1. **A real redirect and a real `state`.** The browser leaves this service,
 *      authenticates somewhere else, and comes back. The return trip is verified,
 *      not simulated.
 *   2. **A real passkey ceremony**, with a virtual authenticator over CDP, on a
 *      secure context. No mocking of WebAuthn.
 *   3. **A real cookie.** `Set-Cookie` from a response, stored by a browser, sent
 *      back on the next request. A stubbed test asserts on the header; this asserts
 *      on the browser's behaviour.
 *
 * WHAT IT STILL DOES NOT PROVE
 *
 * It runs on `localhost` over plain HTTP, which is a secure context for WebAuthn but
 * is not a deployed environment. DNS, certificates and a real proxy are not
 * exercised. It is the cheap half of the deployment question, and the results doc
 * says so.
 *
 * The realm flow is switched to passkey-only for the sign-in and back afterwards,
 * because a realm with a password path will not offer the passkey ceremony — the
 * same cycle the S9 work established.
 */
import { createRequire } from "node:module";
import { spawn, spawnSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { KEYCLOAK_ADMIN_PASSWORD } from "../lab-env.mjs";

const require = createRequire("/Users/felixadusei/Development/AI_Engineering/DeepSeek/passwordless/lab/keycloak/package.json");
const puppeteer = require("puppeteer-core");

// Both are overridable so this can point at a REAL origin through a tunnel, not just
// at localhost. Everything here has only ever run on http://localhost, where WebAuthn
// is a secure context by convention and the origin is not a variable — so the harness
// could not previously test the one thing most likely to differ in a deployment.
const KC = process.env["E2E_KEYCLOAK_URL"] ?? "http://localhost:8080";
const REALM = process.env["E2E_REALM"] ?? "attest-privileged";
const CONSOLE_URL = (process.env["E2E_CONSOLE_URL"] ?? "http://localhost:3000").replace(/\/+$/, "");
// When the console is already running elsewhere (a tunnel), do NOT start a second one:
// it would bind :3000 and the harness would silently test the local instance while
// believing it was testing the deployed one.
const EXTERNAL_CONSOLE = Boolean(process.env["E2E_CONSOLE_URL"]);
const CDP_PORT = 9333;
const CHROME = process.env["CHROME_BIN"] ??
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PY = "/Users/felixadusei/Development/AI_Engineering/DeepSeek/passwordless/.venv/bin/python";
const PASSKEY_TOOL = "/Users/felixadusei/Development/AI_Engineering/DeepSeek/passwordless/lab/keycloak/scripts/make_privileged_passkey_only.py";

const USERNAME = process.env["E2E_USER"] ?? "console-e2e";
const PASSWORD = process.env["E2E_PASSWORD"] ?? "Console-E2E-Password-123!";
let server = null;   // null when the console is external
const results = [];
const check = (label, got, want) => {
  const ok = got === want;
  results.push({ label, got, want, ok });
  console.log(`  ${label.padEnd(58)} ${String(got).padEnd(16)} (want ${String(want).padEnd(12)}) ${ok ? "PASS" : "FAIL"}`);
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Keycloak admin helpers
// ---------------------------------------------------------------------------
async function adminToken() {
  const res = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "password", client_id: "admin-cli",
      username: "admin", password: KEYCLOAK_ADMIN_PASSWORD,
    }),
  });
  return (await res.json()).access_token;
}

async function admin(method, path, body) {
  const token = await adminToken();
  const res = await fetch(`${KC}/admin/realms${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : undefined };
}

async function consoleClient() {
  const { body } = await admin("GET", `/${REALM}/clients?clientId=attest-console`);
  if (!body?.length) throw new Error("attest-console client not found — create it first");
  return body[0];
}

/** A user with a known password and no passkey yet. */
async function ensureUser(username, password) {
  const { body } = await admin("GET", `/${REALM}/users?username=${encodeURIComponent(username)}&exact=true`);
  let user = body?.[0];
  if (!user) {
    await admin("POST", `/${REALM}/users`, {
      username, enabled: true, emailVerified: true,
      email: `${username}@example.test`, firstName: "Console", lastName: "E2E",
    });
    user = (await admin("GET", `/${REALM}/users?username=${encodeURIComponent(username)}&exact=true`)).body[0];
  }
  await admin("PUT", `/${REALM}/users/${user.id}/reset-password`, {
    type: "password", value: password, temporary: false,
  });
  const { body: fresh } = await admin("GET", `/${REALM}/users/${user.id}`);
  await admin("PUT", `/${REALM}/users/${user.id}`, { ...fresh, requiredActions: [] });
  return user.id;
}

async function webauthnCount(userId) {
  const { body } = await admin("GET", `/${REALM}/users/${userId}/credentials`);
  return (body ?? []).filter((c) => (c.type ?? "").startsWith("webauthn")).length;
}

function setFlow(mode) {
  spawnSync(PY, [PASSKEY_TOOL, mode], { stdio: "pipe" });
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------
const PASSKEY_ONLY = (process.env["E2E_PASSKEY_ONLY"] ?? "1") === "1";


/**
 * Point the realm's WebAuthn policy at whatever origin we are actually testing.
 *
 * THIS WAS MISSING, AND ITS ABSENCE COST A RUN. The harness never configured the RP ID
 * at all, so it stayed `localhost` from earlier local work. On http://localhost that
 * happens to be correct and everything passes. On a real host the RP ID is no longer a
 * suffix of the origin, WebAuthn refuses with a SecurityError, and the failure reads as
 * "ensure you are on the correct site" — a message about the SITE, which is about the
 * RP ID, which was the thing nobody had set.
 *
 * Derived from the Keycloak URL rather than hardcoded, so one harness tests both.
 */
async function setRealmWebAuthn() {
  const rpId = new URL(KC).hostname;
  const realm = (await admin("GET", `/${REALM}`)).body;
  const extraOrigins = [...new Set([CONSOLE_URL, KC])];
  await admin("PUT", `/${REALM}`, {
    ...realm,
    webAuthnPolicyPasswordlessRpId: rpId,
    webAuthnPolicyPasswordlessExtraOrigins: extraOrigins,
    webAuthnPolicyPasswordlessAcceptableAaguids: [],
    webAuthnPolicyPasswordlessAttestationConveyancePreference: "none",
  });
  const after = (await admin("GET", `/${REALM}`)).body;
  // ASSERT IT LANDED. A scripted edit that silently does nothing is how the RP ID came
  // to be missing in the first place, and a realm policy that did not apply produces a
  // confusing browser error rather than a configuration error.
  if (after.webAuthnPolicyPasswordlessRpId !== rpId) {
    throw new Error(`RP ID did not apply: wanted ${rpId}, realm has ${after.webAuthnPolicyPasswordlessRpId}`);
  }
  console.log(`      realm WebAuthn RP ID = ${rpId}  (origin ${new URL(KC).origin})`);
}

async function main() {
  console.log("=".repeat(84));
  console.log("The console, end to end, in a real browser");
  console.log("=".repeat(84));

  const client = await consoleClient();
  console.log(`\n  console client: redirectUris=${JSON.stringify(client.redirectUris)}`);

  const userId = await ensureUser(USERNAME, PASSWORD);
  console.log(`  realm: ${REALM}   passkey-only: ${PASSKEY_ONLY}   user: ${USERNAME}`);

  // ------------------------------------------------------------------ server
  if (EXTERNAL_CONSOLE) {
    console.log(`\n[1] using the EXTERNAL console at ${CONSOLE_URL}`);
    const up = (await fetch(`${CONSOLE_URL}/health`, { signal: AbortSignal.timeout(8000) })
      .then((r) => r.ok).catch(() => false));
    check("the external console is reachable", up, true);
    if (!up) return finish();
  } else {
    console.log("\n[1] start the API and console on :3000");
  // Refuse to run if something already owns the port. A previous run whose cleanup
  // failed leaves a server behind, the health check below then passes against THAT
  // server, and the whole test silently measures the wrong configuration — which is
  // exactly what happened here: the browser was sent to `attest-api-test` while the
  // script believed it had configured `attest-privileged`.
  const squatter = spawnSync("lsof", ["-nP", "-iTCP:3000", "-sTCP:LISTEN"], { encoding: "utf8" });
  if ((squatter.stdout ?? "").trim() !== "") {
    console.log("  PORT 3000 IS ALREADY IN USE — killing the previous run");
    spawnSync("pkill", ["-f", "src/index.ts"]);
    await sleep(2000);
  }

  server = spawn("node", ["--experimental-strip-types", "src/index.ts"], {
    cwd: "/Users/felixadusei/Development/AI_Engineering/DeepSeek/passwordless/apps/api",
    env: {
      ...process.env,
      KEYCLOAK_ISSUER: `${KC}/realms/${REALM}`,
      API_AUDIENCE: "attest-api",
      PUBLIC_BASE_URL: CONSOLE_URL,
      TENANT_CLAIM: "tenant_id",
      HTTP_HOST: "127.0.0.1",
      HTTP_PORT: "3000",
      OIDC_ISSUER: `${KC}/realms/${REALM}`,
      OIDC_CLIENT_ID: "attest-console",
      OIDC_CLIENT_SECRET: client.secret,
      OIDC_REDIRECT_URI: `${CONSOLE_URL}/console/callback`,
      CONSOLE_BASE_URL: CONSOLE_URL,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serverLog = "";
  server.stdout.on("data", (d) => { serverLog += d.toString(); });
  server.stderr.on("data", (d) => { serverLog += d.toString(); });

  let up = false;
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(`${CONSOLE_URL}/health`, { signal: AbortSignal.timeout(2000) });
      if (r.ok) { up = true; break; }
    } catch { /* not yet */ }
    await sleep(500);
  }
  check("the server is listening on :3000", up, true);
  // Prove the running server is the one this script started, by checking the issuer
  // it redirects to. A health check alone cannot tell one process from another.
  const probe = await fetch(`${CONSOLE_URL}/console/login`, { redirect: "manual" });
  const probeLocation = probe.headers.get("location") ?? "";
  check("the running server points at the realm under test", probeLocation.includes(REALM), true);
  if (!probeLocation.includes(REALM)) {
    console.log(`      redirect was: ${probeLocation.slice(0, 120)}`);
    if (!EXTERNAL_CONSOLE) server.kill();
    return finish();
  }
  if (!up) {
    console.log("\n  server output:\n" + serverLog.slice(-1500));
    if (!EXTERNAL_CONSOLE) server.kill();
    return finish();
  }

  // ------------------------------------------------------------------ chrome
  }

  console.log("\n[2] launch Chrome with a virtual authenticator");
  // Clear any leftover instance first. A previous run that failed before its
  // cleanup leaves Chrome holding the debug port, and the next run then connects to
  // the WRONG browser — or cannot connect at all, which is what happened here and
  // looked like "Chrome will not start".
  spawnSync("pkill", ["-f", `user-data-dir=/tmp/console-e2e-chrome`]);
  spawnSync("rm", ["-rf", "/tmp/console-e2e-chrome"]);
  await sleep(1000);

  const chrome = spawn(CHROME, [
    "--headless=new", "--disable-gpu", "--no-sandbox",
    `--remote-debugging-port=${CDP_PORT}`,
    "--user-data-dir=/tmp/console-e2e-chrome",
    "--no-first-run",
  ], { stdio: "ignore" });

  // Poll for the debug port rather than sleeping a fixed amount. A hard-coded sleep
  // is a race that passes on a fast machine and fails in CI, which this project has
  // already paid for more than once.
  let debugReady = false;
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`, { signal: AbortSignal.timeout(1500) });
      if (r.ok) { debugReady = true; break; }
    } catch { /* not yet */ }
    await sleep(500);
  }
  check("Chrome exposes its debugging port", debugReady, true);
  if (!debugReady) { chrome.kill(); server.kill(); return finish(); }

  const browser = await puppeteer.connect({
    browserURL: `http://127.0.0.1:${CDP_PORT}`,
    defaultViewport: null,
    protocolTimeout: 60000,
  });
  const page = await browser.newPage();
  const cdp = await page.createCDPSession();
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2", transport: "usb", hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    },
  });
  page.on("dialog", async (d) => { try { await d.accept("Console E2E"); } catch { /* ignore */ } });
  check("a virtual authenticator is attached", typeof authenticatorId === "string", true);

  try {
    // ---------------------------------------------------------------- register
    // The realm needs a password path to enrol a passkey, and a passkey-only realm
    // has none. The S9 work established this cycle; it is repeated here rather than
    // assumed.
    console.log("\n[3] register a passkey for the test user");
    await setRealmWebAuthn();
    setFlow("revert");
    // Clear any credential from an earlier run FIRST. `AvoidSameAuthenticatorRegister`
    // is enabled on this realm and refuses a duplicate registration SILENTLY, so a
    // leftover credential can make the count look right while nothing new was
    // registered — and the harness then signs in with a credential the fresh
    // authenticator does not hold. The standing rule: the harness creates its own
    // fixtures and starts from a known state.
    for (const c of (await admin("GET", `/${REALM}/users/${userId}/credentials`))?.body ?? []) {
      if ((c.type ?? "").startsWith("webauthn")) {
        await admin("DELETE", `/${REALM}/users/${userId}/credentials/${c.id}`);
      }
    }
    await admin("PUT", `/${REALM}/users/${userId}`, {
      ...(await admin("GET", `/${REALM}/users/${userId}`)).body,
      requiredActions: ["webauthn-register-passwordless"],
    });

    const authUrl = `${KC}/realms/${REALM}/protocol/openid-connect/auth?` + new URLSearchParams({
      client_id: "attest-console", response_type: "code",
      redirect_uri: `${CONSOLE_URL}/console/callback`,
      scope: "openid", state: "enrol", nonce: "enrol",
    });
    await page.goto(authUrl, { waitUntil: "networkidle2", timeout: 45000 });
    if (await page.$("#username")) {
      await page.type("#username", USERNAME);
      await page.type("#password", PASSWORD);
      await Promise.all([
        page.waitForNavigation({ waitUntil: "networkidle2", timeout: 45000 }).catch(() => {}),
        page.click("#kc-login"),
      ]);
    }
    await sleep(1200);
    const register = await page.evaluateHandle(() => {
      const candidates = [...document.querySelectorAll("input[type=submit], button")];
      return candidates.find((e) => /register|save|continue/i.test(e.value || e.textContent || "")) ?? null;
    });
    const registerEl = register.asElement();
    if (registerEl) { await registerEl.click().catch(() => {}); await sleep(7000); }
    check("a passkey is registered for the user", await webauthnCount(userId), 1);

    // Clear the required action. Leaving it pending makes the NEXT sign-in stop at
    // the registration page — the harness's own setup interfering with what it is
    // trying to measure, which is how a test reports a console defect that is
    // actually its own leftover state.
    await admin("PUT", `/${REALM}/users/${userId}`, {
      ...(await admin("GET", `/${REALM}/users/${userId}`)).body,
      requiredActions: [],
    });

    // ---------------------------------------------------------------- sign in
    console.log("\n[4] sign in to the CONSOLE with a real redirect and a real passkey");
    setFlow(PASSKEY_ONLY ? "apply" : "revert");
    await cdp.send("Network.clearBrowserCookies");

    await page.goto(`${CONSOLE_URL}/console`, { waitUntil: "networkidle2", timeout: 45000 });
    check("an unauthenticated visit lands on the provider's sign-in page",
      page.url().startsWith(KC), true);

    // Capture what the browser is actually looking at. Without this, "no passkey
    // button" is indistinguishable from "the wrong page entirely" — and in a browser
    // test those have completely different causes.
    const seen = await page.evaluate(() => ({
      url: location.href.slice(0, 120),
      title: document.title,
      ids: [...document.querySelectorAll("[id]")].map((e) => e.id).filter(Boolean).slice(0, 12),
      buttons: [...document.querySelectorAll("input[type=submit], button")].map((e) => e.id || e.value || e.textContent?.trim().slice(0, 20)),
    })).catch((e) => ({ error: String(e).slice(0, 80) }));
    console.log("      page seen:", JSON.stringify(seen).slice(0, 320));

    // Before clicking, show what the authenticator ACTUALLY holds. Keycloak's admin
    // API omits `userHandle` from `credentialData`, so it is not a way to tell
    // whether a handle exists — and reading it as one produced a wrong diagnosis.
    const held = await cdp.send("WebAuthn.getCredentials", { authenticatorId }).catch(() => ({ credentials: [] }));
    for (const c of held.credentials) {
      console.log(`      authenticator holds: resident=${c.isResidentCredential} userHandle=${c.userHandle ? `"${c.userHandle}"` : "ABSENT"}`);
    }

    // Whichever path this realm offers. A passkey-only realm shows the ceremony; a
    // realm with a password shows a form. Asserting on the wrong one would report a
    // provider misconfiguration as a console defect.
    const passkeyButton = await page.$("#authenticateWebAuthnButton");
    if (PASSKEY_ONLY) {
      check("the provider offers the passkey ceremony", passkeyButton !== null, true);
    }
    if (passkeyButton) {
      await Promise.all([
        page.waitForNavigation({ waitUntil: "networkidle2", timeout: 30000 }).catch(() => {}),
        passkeyButton.click(),
      ]);
      await sleep(4000);
    } else if (await page.$("#username")) {
      console.log("      (this realm offers a password form, not the passkey ceremony)");
      await page.type("#username", USERNAME);
      await page.type("#password", PASSWORD);
      await Promise.all([
        page.waitForNavigation({ waitUntil: "networkidle2", timeout: 30000 }).catch(() => {}),
        page.click("#kc-login"),
      ]);
      await sleep(3000);
    }

    const afterLogin = page.url();
    if (!afterLogin.startsWith(CONSOLE_URL)) {
      const stuck = await page.evaluate(() => ({
        title: document.title,
        errors: [...document.querySelectorAll(".kc-feedback-text, .pf-c-alert__title, #input-error, .alert-error")]
          .map((e) => e.textContent?.trim().slice(0, 120)).filter(Boolean),
        body: document.body.innerText.replace(/\s+/g, " ").slice(0, 300),
      })).catch((e) => ({ error: String(e).slice(0, 100) }));
      console.log("      STUCK AT:", JSON.stringify(stuck).slice(0, 400));
    }
    check("the browser is returned to the console, not left at the provider",
      afterLogin.startsWith(CONSOLE_URL), true);
    check("the callback completed and the console rendered",
      afterLogin === `${CONSOLE_URL}/console` || afterLogin.startsWith(`${CONSOLE_URL}/console?`), true);

    const body = await page.evaluate(() => document.body.innerText);
    check("the rendered page is the evidence list", /Evidence|No evidence yet/i.test(body), true);

    // ---------------------------------------------------------------- session
    console.log("\n[5] the session is a cookie the browser holds, not a token");
    const cookies = await page.cookies(`${CONSOLE_URL}/console`);
    const session = cookies.find((c) => c.name === "attest_session");
    check("the session cookie exists in the browser", session !== undefined, true);
    check("it is HttpOnly", session?.httpOnly, true);
    check("it is scoped to /console", session?.path, "/console");
    check("its value is not a JWT", session ? !session.value.includes(".") : false, true);

    // ---------------------------------------------------------------- survive
    console.log("\n[6] the session survives a fresh navigation");
    await page.goto(`${CONSOLE_URL}/console`, { waitUntil: "networkidle2", timeout: 30000 });
    check("a second visit does NOT bounce back to the provider",
      page.url().startsWith(`${CONSOLE_URL}/console`) && !page.url().includes("login"), true);

    // ---------------------------------------------------------------- sign out
    console.log("\n[7] signing out ends the session");
    const signedOut = await page.evaluate(async () => {
      // Report what is actually on the page when the form is missing. "no-form" on
      // its own is indistinguishable from "the wrong page entirely", and the two
      // have completely different causes.
      const forms = [...document.querySelectorAll("form")].map((f) => f.getAttribute("action"));
      const form = document.querySelector("form[action='/console/logout']")
        ?? [...document.querySelectorAll("form")].find((f) => (f.getAttribute("action") ?? "").includes("logout"));
      if (!form) {
        return `no-form url=${location.pathname} forms=${JSON.stringify(forms)} HTML=${document.body.innerHTML.replace(/\s+/g, " ").slice(0, 420)}`;
      }
      form.submit();
      return "submitted";
    });
    check("the sign-out form is present and submits", signedOut, "submitted");
    await sleep(3000);
    const afterLogoutUrl = page.url();

    // Was the CONSOLE's session actually destroyed? Ask the browser, not the server.
    const cookiesAfter = await page.cookies(`${CONSOLE_URL}/console`);
    const sessionAfter = cookiesAfter.find((c) => c.name === "attest_session");
    check("the session cookie is gone from the browser after signing out", sessionAfter === undefined, true);

    await page.goto(`${CONSOLE_URL}/console`, { waitUntil: "networkidle2", timeout: 30000 });
    const finalUrl = page.url();

    // With an SSO session still alive at the provider, re-visiting signs the user
    // back in SILENTLY — no prompt — and lands them on /console. That is correct SSO
    // behaviour, and asserting "must show a login form" would fail on a correct
    // system. What must NOT happen is landing on /console with the SAME session that
    // was just destroyed.
    const isConsole = finalUrl.startsWith(`${CONSOLE_URL}/console`) && !finalUrl.includes("login");
    const cookiesFinal = await page.cookies(`${CONSOLE_URL}/console`);
    const sessionFinal = cookiesFinal.find((c) => c.name === "attest_session");
    const isSameSession = sessionAfter !== undefined && sessionFinal?.value === sessionAfter.value;

    console.log(`      after logout: url=${afterLogoutUrl.slice(0, 60)}`);
    console.log(`      revisit:      url=${finalUrl.slice(0, 60)}  newSession=${sessionFinal ? "yes" : "no"}`);
    check("signing out did not leave the user on the console with the same session",
      isConsole && isSameSession, false);
  } finally {
    await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => {});
    await page.close().catch(() => {});
    browser.disconnect();
    chrome.kill();
    if (!EXTERNAL_CONSOLE) server.kill();
    setFlow("revert");
    spawnSync("pkill", ["-f", "user-data-dir=/tmp/console-e2e-chrome"]);
  }

  return finish();
}

function finish() {
  const passed = results.filter((r) => r.ok).length;
  console.log("\n" + "=".repeat(84));
  console.log(`Console end to end: ${passed}/${results.length} behaved as expected`);
  if (passed !== results.length) {
    console.log("\n  FAILURES:");
    for (const r of results.filter((x) => !x.ok)) {
      console.log(`    ${r.label}: got ${r.got}, wanted ${r.want}`);
    }
  }
  console.log("=".repeat(84));
  process.exit(passed === results.length ? 0 : 1);
}

main().catch((error) => {
  console.error("  harness error:", error.message);
  process.exit(1);
});
void existsSync;
void readFileSync;
