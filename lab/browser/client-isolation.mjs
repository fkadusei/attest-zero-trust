#!/usr/bin/env node
/**
 * E2E-3 — the client, or the origin?
 *
 * The console's passkey sign-in fails with `webauthn-error-user-not-found`, and every
 * layer of the credential has been ruled out: the user handle exists, is well-formed,
 * decodes to the right user id, the user is enabled, and exactly one credential
 * exists. S9's flow works on the SAME realm with the SAME authenticator approach.
 *
 * Two variables differ between the working case and the failing one:
 *
 *   working:  client `phishing-lab`,  origin `app.localhost:8080`,  rpId `app.localhost`
 *   failing:  client `attest-console`, origin `localhost:8080`,     rpId `localhost`
 *
 * This isolates the CLIENT by removing the console entirely: a browser signs in
 * directly against the authorization endpoint with `client_id=attest-console`. If
 * that fails, the client is responsible and the console is irrelevant. If it
 * succeeds, the console's own handling is responsible — which would be a very
 * different bug, and one the console's code could fix.
 *
 * The origin is held fixed at `localhost`, where S9's own approach is known to work
 * when the rpId matches.
 */
import { createRequire } from "node:module";
import { spawn, spawnSync } from "node:child_process";

const require = createRequire("/Users/felixadusei/Development/AI_Engineering/DeepSeek/passwordless/lab/keycloak/package.json");
const puppeteer = require("puppeteer-core");

const KC = "http://localhost:8080";
const REALM = "attest-privileged";
const USERNAME = process.env["E2E_USER"] ?? "client-probe-user";
const PASSWORD = "Client-Probe-Password-123!";
const CDP_PORT = 9355;
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PY = "/Users/felixadusei/Development/AI_Engineering/DeepSeek/passwordless/.venv/bin/python";
const PASSKEY_TOOL = "/Users/felixadusei/Development/AI_Engineering/DeepSeek/passwordless/lab/keycloak/scripts/make_privileged_passkey_only.py";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function tok() {
  const res = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "password", client_id: "admin-cli",
      username: "admin", password: "lab-only-not-a-secret" }),
  });
  return (await res.json()).access_token;
}
async function admin(method, path, body) {
  const t = await tok();
  const res = await fetch(`${KC}/admin/realms${path}`, {
    method, headers: { authorization: `Bearer ${t}`, "content-type": "application/json" },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  return text ? JSON.parse(text) : undefined;
}

/** Run a full register-then-sign-in cycle for one client id. */
async function cycle(page, cdp, authenticatorId, clientId, redirectUri) {
  // ---- register ----
  spawnSync(PY, [PASSKEY_TOOL, "revert"]);
  let users = await admin("GET", `/${REALM}/users?username=${USERNAME}&exact=true`);
  if (!users?.length) {
    await admin("POST", `/${REALM}/users`, { username: USERNAME, enabled: true,
      emailVerified: true, email: `${USERNAME}@example.test`, firstName: "Client", lastName: "Probe" });
    users = await admin("GET", `/${REALM}/users?username=${USERNAME}&exact=true`);
  }
  const userId = users[0].id;
  await admin("PUT", `/${REALM}/users/${userId}/reset-password`, {
    type: "password", value: PASSWORD, temporary: false });
  for (const c of (await admin("GET", `/${REALM}/users/${userId}/credentials`)) ?? []) {
    if ((c.type ?? "").startsWith("webauthn")) {
      await admin("DELETE", `/${REALM}/users/${userId}/credentials/${c.id}`);
    }
  }
  await admin("PUT", `/${REALM}/users/${userId}`, {
    ...(await admin("GET", `/${REALM}/users/${userId}`)),
    requiredActions: ["webauthn-register-passwordless"] });

  await cdp.send("Network.clearBrowserCookies");
  const enrolUrl = `${KC}/realms/${REALM}/protocol/openid-connect/auth?` + new URLSearchParams({
    client_id: clientId, response_type: "code", redirect_uri: redirectUri,
    scope: "openid", state: "enrol", nonce: "enrol" });
  await page.goto(enrolUrl, { waitUntil: "networkidle2", timeout: 45000 }).catch(() => {});
  if (await page.$("#username")) {
    await page.type("#username", USERNAME);
    await page.type("#password", PASSWORD);
    await Promise.all([
      page.waitForNavigation({ waitUntil: "networkidle2", timeout: 45000 }).catch(() => {}),
      page.click("#kc-login") ]);
  }
  await sleep(1500);
  const h = await page.evaluateHandle(() => {
    const c = [...document.querySelectorAll("input[type=submit], button")];
    return c.find((e) => /register|save|continue/i.test(e.value || e.textContent || "")) ?? null; });
  const el = h.asElement();
  if (el) { await el.click().catch(() => {}); await sleep(8000); }

  const creds = (await admin("GET", `/${REALM}/users/${userId}/credentials`)) ?? [];
  const registered = creds.filter((c) => (c.type ?? "").startsWith("webauthn")).length;

  // Clear the required action, or the sign-in stops at the registration page.
  await admin("PUT", `/${REALM}/users/${userId}`, {
    ...(await admin("GET", `/${REALM}/users/${userId}`)), requiredActions: [] });

  // ---- sign in with the passkey ----
  spawnSync(PY, [PASSKEY_TOOL, "apply"]);
  await cdp.send("Network.clearBrowserCookies");
  const authUrl = `${KC}/realms/${REALM}/protocol/openid-connect/auth?` + new URLSearchParams({
    client_id: clientId, response_type: "code", redirect_uri: redirectUri,
    scope: "openid", state: "signin", nonce: "signin" });
  await page.goto(authUrl, { waitUntil: "networkidle2", timeout: 45000 }).catch(() => {});

  const held = await cdp.send("WebAuthn.getCredentials", { authenticatorId }).catch(() => ({ credentials: [] }));
  const withHandle = held.credentials.filter((c) => c.userHandle && c.userHandle.length > 0).length;

  const button = await page.$("#authenticateWebAuthnButton");
  if (!button) {
    return { registered, withHandle, outcome: "no-passkey-button", url: page.url().slice(0, 70) };
  }
  await Promise.all([
    page.waitForNavigation({ waitUntil: "networkidle2", timeout: 30000 }).catch(() => {}),
    button.click() ]);
  await sleep(4000);

  const url = page.url();
  const error = await page.evaluate(() =>
    document.querySelector(".kc-feedback-text, #input-error, .alert-error")?.textContent?.trim() ?? null
  ).catch(() => null);

  // Success means we left the provider for the redirect target.
  const succeeded = url.startsWith(redirectUri.split("/").slice(0, 3).join("/")) && !url.includes("/protocol/openid-connect/auth");
  return { registered, withHandle, outcome: succeeded ? "AUTHENTICATED" : (error ?? "still at provider"), url: url.slice(0, 70) };
}

async function main() {
  console.log("=".repeat(84));
  console.log("E2E-3 — the client, or the origin?");
  console.log("=".repeat(84));

  spawnSync("pkill", ["-f", "user-data-dir=/tmp/client-probe-chrome"]);
  spawnSync("rm", ["-rf", "/tmp/client-probe-chrome"]);
  await sleep(1000);
  const chrome = spawn(CHROME, ["--headless=new", "--disable-gpu", "--no-sandbox",
    `--remote-debugging-port=${CDP_PORT}`, "--user-data-dir=/tmp/client-probe-chrome",
    "--no-first-run"], { stdio: "ignore" });
  let ready = false;
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`, { signal: AbortSignal.timeout(1500) });
      if (r.ok) { ready = true; break; }
    } catch { /* not yet */ }
    await sleep(500);
  }
  if (!ready) { chrome.kill(); throw new Error("Chrome did not expose its debugging port"); }

  const browser = await puppeteer.connect({ browserURL: `http://127.0.0.1:${CDP_PORT}`,
    defaultViewport: null, protocolTimeout: 60000 });
  const page = await browser.newPage();
  const cdp = await page.createCDPSession();
  await cdp.send("WebAuthn.enable");
  // A FRESH authenticator per client, so the second run cannot be helped or hindered
  // by the first run's credential. Without this the comparison is not a comparison.
  let { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "usb", hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  page.on("dialog", async (d) => { try { await d.accept("Probe"); } catch { /* ignore */ } });

  const CASES = [
    { clientId: "attest-console", redirectUri: "http://localhost:3000/console/callback", label: "attest-console (confidential, the failing one)" },
    { clientId: "phishing-lab",   redirectUri: "http://app.localhost:8080/callback",  label: "phishing-lab   (public, S9's working one)" },
  ];

  // The realm's RP ID and extra origins must suit whichever origin the client uses.
  // Set once, to the values that make EACH case's redirect origin a valid WebAuthn
  // origin — otherwise the comparison measures the RP ID, which has already been
  // ruled out.
  const realm = await admin("GET", `/${REALM}`);
  await admin("PUT", `/${REALM}`, { ...realm,
    webAuthnPolicyPasswordlessRpId: "localhost",
    webAuthnPolicyPasswordlessExtraOrigins: ["http://localhost:3000", "http://app.localhost:8080"],
    webAuthnPolicyPasswordlessAcceptableAaguids: [],
    webAuthnPolicyPasswordlessAttestationConveyancePreference: "none" });

  const rows = [];
  for (const c of CASES) {
    console.log(`\n  --- ${c.label}`);
    await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => {});
    ({ authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: { protocol: "ctap2", transport: "usb", hasResidentKey: true,
        hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } }));
    const r = await cycle(page, cdp, authenticatorId, c.clientId, c.redirectUri);
    console.log(`      registered=${r.registered}  handles=${r.withHandle}`);
    console.log(`      outcome: ${r.outcome}`);
    console.log(`      url:     ${r.url}`);
    rows.push({ ...c, ...r });
  }

  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => {});
  await page.close().catch(() => {});
  browser.disconnect();
  chrome.kill();
  spawnSync("pkill", ["-f", "user-data-dir=/tmp/client-probe-chrome"]);
  spawnSync(PY, [PASSKEY_TOOL, "revert"]);

  console.log("\n" + "=".repeat(84));
  console.log("  client                          registered  handle  outcome");
  for (const r of rows) {
    console.log(`  ${r.clientId.padEnd(30)}  ${String(r.registered).padEnd(10)}  ${String(r.withHandle).padEnd(6)}  ${r.outcome}`);
  }
  const working = rows.filter((r) => r.outcome === "AUTHENTICATED");
  console.log(`\n  clients that completed a passkey sign-in: ${working.length}/${rows.length}`);
  if (working.length === rows.length) {
    console.log("  => the CLIENT is not the cause; the difference is elsewhere (the console itself, or the origin)");
  } else if (working.length === 0) {
    console.log("  => NEITHER client works here; the difference is the ORIGIN, not the client");
  } else {
    console.log(`  => the CLIENT is the cause: ${working.map((r) => r.clientId).join(", ")} works, the other does not`);
  }
  console.log("=".repeat(84));
  process.exit(0);
}

main().catch((e) => { console.error("  harness error:", e.message); process.exit(1); });
