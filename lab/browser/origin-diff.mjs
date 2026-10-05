#!/usr/bin/env node
/**
 * origin-diff — what about the origin makes the passkey fail on localhost?
 *
 * Established so far:
 *
 *   http://localhost:8080      (RP ID `localhost`)          -> user-not-found
 *   https://id.210security.com (RP ID `id.210security.com`) -> AUTHENTICATED
 *
 * The client, the credential, the user, the realm policy and the console's code have all
 * been ruled out individually. The origin is the only variable left.
 *
 * This runs the SAME registration and the SAME sign-in against both, with a FRESH
 * authenticator each time, and records what differs. The point is not to make one pass:
 * it is to find the variable, so the candidates are measured rather than reasoned about.
 *
 * Candidates, and how each is separated here:
 *
 *   SCHEME        http vs https. Tested by running the same hostname over the tunnel.
 *   RP ID WIDTH   `localhost` is one label, `id.210security.com` is three.
 *   EXTRA ORIGINS whether the console's origin sits under the same RP ID.
 *   PORT          both origins here are :8080, differing only in scheme and host, so a
 *                 port effect would show up as a scheme/host effect.
 *
 * Each case reports the credential the AUTHENTICATOR actually holds — including the
 * userHandle, which Keycloak's admin API does not expose and which was misread once
 * already as "absent".
 */
import { createRequire } from "node:module";
import { spawn, spawnSync } from "node:child_process";

const require = createRequire("/Users/felixadusei/Development/AI_Engineering/DeepSeek/passwordless/lab/keycloak/package.json");
const puppeteer = require("puppeteer-core");

const REALM = process.env["E2E_REALM"] ?? "attest-privileged";
// Overridable so the console end-to-end harness OWN user can be tested here.
// If it fails in this harness while another user succeeds, the user is the variable.
const USERNAME = process.env["E2E_USER"] ?? "origin-diff-user";
const PASSWORD = process.env["E2E_PASSWORD"] ?? "Origin-Diff-Password-123!";
const CDP_PORT = 9366;
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PY = "/Users/felixadusei/Development/AI_Engineering/DeepSeek/passwordless/.venv/bin/python";
const PASSKEY_TOOL = "/Users/felixadusei/Development/AI_Engineering/DeepSeek/passwordless/lab/keycloak/scripts/make_privileged_passkey_only.py";
const ADMIN_API = "http://localhost:8080";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

import { KEYCLOAK_ADMIN_PASSWORD } from "../lab-env.mjs";

async function adminToken() {
  const password = KEYCLOAK_ADMIN_PASSWORD;
  const res = await fetch(`${ADMIN_API}/realms/master/protocol/openid-connect/token`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "password", client_id: "admin-cli",
      username: "admin", password }),
  });
  return (await res.json()).access_token;
}
async function admin(method, path, body) {
  const token = await adminToken();
  const res = await fetch(`${ADMIN_API}/admin/realms${path}`, {
    method, headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status} ${text.slice(0, 120)}`);
  return text ? JSON.parse(text) : undefined;
}

/** Configure the realm for one origin, and CONFIRM it applied. */
async function configureRealm(rpId, extraOrigins) {
  const realm = await admin("GET", `/${REALM}`);
  await admin("PUT", `/${REALM}`, {
    ...realm,
    webAuthnPolicyPasswordlessRpId: rpId,
    webAuthnPolicyPasswordlessExtraOrigins: extraOrigins,
    webAuthnPolicyPasswordlessAcceptableAaguids: [],
    webAuthnPolicyPasswordlessAttestationConveyancePreference: "none",
  });
  const after = await admin("GET", `/${REALM}`);
  if (after.webAuthnPolicyPasswordlessRpId !== rpId) {
    throw new Error(`RP ID did not apply: wanted ${rpId}, got ${after.webAuthnPolicyPasswordlessRpId}`);
  }
  return after.webAuthnPolicyPasswordlessRpId;
}

async function runCase(cdp, page, label, kcOrigin, rpId, extraOrigins, scope = "openid") {
  console.log(`\n  ── ${label}`);
  console.log(`     keycloak    : ${kcOrigin}`);
  console.log(`     rpId        : ${rpId}`);
  console.log(`     extraOrigins: ${JSON.stringify(extraOrigins)}`);
  console.log(`     scope       : ${scope}`);

  const applied = await configureRealm(rpId, extraOrigins);

  // Fresh authenticator per case, so neither case is helped by the other's credential.
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "usb", hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });

  // ---- fixtures: this user, with no credential, needing to register one ----
  let users = await admin("GET", `/${REALM}/users?username=${USERNAME}&exact=true`);
  if (!users?.length) {
    await admin("POST", `/${REALM}/users`, { username: USERNAME, enabled: true,
      emailVerified: true, email: `${USERNAME}@example.test`, firstName: "Origin", lastName: "Diff" });
    users = await admin("GET", `/${REALM}/users?username=${USERNAME}&exact=true`);
  }
  const userId = users[0].id;
  await admin("PUT", `/${REALM}/users/${userId}/reset-password`,
    { type: "password", value: PASSWORD, temporary: false });
  for (const c of (await admin("GET", `/${REALM}/users/${userId}/credentials`)) ?? []) {
    if ((c.type ?? "").startsWith("webauthn")) {
      await admin("DELETE", `/${REALM}/users/${userId}/credentials/${c.id}`);
    }
  }

  const result = { label, kcOrigin, rpId, extraOrigins, scope, applied };

  try {
    // ---- register ----
    spawnSync(PY, [PASSKEY_TOOL, "revert"]);
    await admin("PUT", `/${REALM}/users/${userId}`,
      { ...(await admin("GET", `/${REALM}/users/${userId}`)),
        requiredActions: ["webauthn-register-passwordless"] });

    await cdp.send("Network.clearBrowserCookies");
    await page.goto(`${kcOrigin}/realms/${REALM}/protocol/openid-connect/auth?` + new URLSearchParams({
      client_id: "attest-console", response_type: "code",
      redirect_uri: "http://localhost:3000/console/callback",
      scope, state: "reg", nonce: "reg" }), { waitUntil: "networkidle2", timeout: 45000 })
      .catch(() => {});
    if (await page.$("#username")) {
      await page.type("#username", USERNAME);
      await page.type("#password", PASSWORD);
      await Promise.all([
        page.waitForNavigation({ waitUntil: "networkidle2", timeout: 45000 }).catch(() => {}),
        page.click("#kc-login") ]);
    }
    await sleep(1500);
    const handle = await page.evaluateHandle(() => {
      const c = [...document.querySelectorAll("input[type=submit], button")];
      return c.find((e) => /register|save|continue/i.test(e.value || e.textContent || "")) ?? null; });
    const button = handle.asElement();
    if (button) { await button.click().catch(() => {}); await sleep(9000); }

    const regPage = await page.evaluate(() => ({
      error: document.querySelector(".kc-feedback-text, #input-error, .alert-error")?.textContent?.trim() ?? null,
      url: location.pathname.slice(0, 60),
    })).catch(() => ({}));
    result.registerPageError = regPage.error;

    const creds = (await admin("GET", `/${REALM}/users/${userId}/credentials`)) ?? [];
    result.storedCredentials = creds.filter((c) => (c.type ?? "").startsWith("webauthn")).length;

    // ---- what the AUTHENTICATOR holds (not what the admin API shows) ----
    const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
    result.authenticatorCredentials = credentials.length;
    result.credentials = credentials.map((c) => ({
      resident: c.isResidentCredential,
      credentialId: String(c.credentialId).slice(0, 24),
      userHandle: c.userHandle ?? null,
    }));

    // Clear the required action, or the sign-in stops at the registration page.
    await admin("PUT", `/${REALM}/users/${userId}`,
      { ...(await admin("GET", `/${REALM}/users/${userId}`)), requiredActions: [] });

    // ---- sign in ----
    spawnSync(PY, [PASSKEY_TOOL, "apply"]);
    await cdp.send("Network.clearBrowserCookies");
    await page.goto(`${kcOrigin}/realms/${REALM}/protocol/openid-connect/auth?` + new URLSearchParams({
      client_id: "attest-console", response_type: "code",
      redirect_uri: "http://localhost:3000/console/callback",
      scope, state: "signin", nonce: "signin" }), { waitUntil: "networkidle2", timeout: 45000 })
      .catch(() => {});

    const passkeyButton = await page.$("#authenticateWebAuthnButton");
    result.ceremonyOffered = passkeyButton !== null;
    if (!passkeyButton) {
      result.outcome = "no-passkey-button";
      result.error = (await page.evaluate(() => document.title)).slice(0, 60);
    } else {
      await Promise.all([
        page.waitForNavigation({ waitUntil: "networkidle2", timeout: 30000 }).catch(() => {}),
        passkeyButton.click() ]);
      await sleep(4000);
      const after = page.url();
      const error = await page.evaluate(() =>
        document.querySelector(".kc-feedback-text, #input-error, .alert-error")?.textContent?.trim() ?? null
      ).catch(() => null);
      const left = !after.includes("/protocol/openid-connect/auth");
      result.outcome = left ? "AUTHENTICATED" : "REFUSED";
      result.error = error;
      result.finalUrl = after.slice(0, 80);
    }
  } catch (error) {
    result.outcome = "HARNESS ERROR";
    result.error = String(error).slice(0, 140);
  } finally {
    await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => {});
  }
  return result;
}

async function main() {
  console.log("=".repeat(86));
  console.log("origin-diff — what makes the passkey fail on localhost?");
  console.log("=".repeat(86));

  spawnSync("pkill", ["-f", "user-data-dir=/tmp/origin-diff-chrome"]);
  spawnSync("rm", ["-rf", "/tmp/origin-diff-chrome"]);
  await sleep(1000);
  const chrome = spawn(CHROME, ["--headless=new", "--disable-gpu", "--no-sandbox",
    `--remote-debugging-port=${CDP_PORT}`, "--user-data-dir=/tmp/origin-diff-chrome",
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
  page.on("dialog", async (d) => { try { await d.accept("Probe"); } catch { /* ignore */ } });

  const CASES = [
    // SAME origin, SAME user, SAME client, SAME redirect_uri. Only the scope differs.
    // The console sends `openid profile email`; every probe that has ever passed sent
    // `openid`. If that is the variable, this shows it and nothing else can explain it.
    { label: "D. localhost, scope=openid          (probe: passes)",
      kcOrigin: "http://localhost:8080", rpId: "localhost",
      extraOrigins: [], scope: "openid" },
    { label: "E. localhost, scope=openid profile email  (console)",
      kcOrigin: "http://localhost:8080", rpId: "localhost",
      extraOrigins: [], scope: "openid profile email" },
  ];

  const results = [];
  for (const c of CASES) {
    results.push(await runCase(cdp, page, c.label, c.kcOrigin, c.rpId, c.extraOrigins, c.scope));
  }

  await page.close().catch(() => {});
  browser.disconnect();
  chrome.kill();
  spawnSync("pkill", ["-f", "user-data-dir=/tmp/origin-diff-chrome"]);
  spawnSync(PY, [PASSKEY_TOOL, "revert"]);

  console.log("\n" + "=".repeat(86));
  console.log("RESULTS");
  console.log("=".repeat(86));
  console.log(`  ${"case".padEnd(44)} ${"ceremony".padEnd(9)} ${"authCreds".padEnd(10)} ${"stored".padEnd(7)} outcome`);
  for (const r of results) {
    console.log(`  ${r.label.padEnd(44)} ${String(r.ceremonyOffered).padEnd(9)} ${String(r.authenticatorCredentials ?? "-").padEnd(10)} ${String(r.storedCredentials ?? "-").padEnd(7)} ${r.outcome}`);
  }

  console.log("\n  what the AUTHENTICATOR held, and the handle it used:");
  for (const r of results) {
    for (const c of r.credentials ?? []) {
      console.log(`    ${r.label.slice(0, 3)} resident=${c.resident} id=${c.credentialId}... userHandle=${c.userHandle ? c.userHandle.slice(0, 44) : "ABSENT"}`);
    }
    if (!(r.credentials ?? []).length) console.log(`    ${r.label.slice(0, 3)} (no credential on the authenticator)`);
  }

  console.log("\n  errors reported:");
  for (const r of results) {
    if (r.error) console.log(`    ${r.label.slice(0, 3)} register="${(r.registerPageError ?? "").slice(0, 70)}" signin="${String(r.error).slice(0, 70)}"`);
  }

  console.log("\n" + "=".repeat(86));
  const local = results.find((r) => r.label.startsWith("A"));
  const real = results.find((r) => r.label.startsWith("C"));
  if (local?.outcome === "AUTHENTICATED" && real?.outcome === "AUTHENTICATED") {
    console.log("  => BOTH origins authenticated. The difference was NOT the origin as such;");
    console.log("     compare extraOrigins between A and B to see which variable flipped it.");
  } else if (local?.outcome !== "AUTHENTICATED" && real?.outcome === "AUTHENTICATED") {
    console.log("  => REPRODUCED: localhost refuses, the real origin authenticates.");
    console.log("     A and B differ ONLY in extraOrigins. If B authenticates, that is the variable.");
  } else {
    console.log("  => unexpected combination — read the rows above before concluding.");
  }
  console.log("=".repeat(86));
  process.exit(0);
}

main().catch((e) => { console.error("  harness error:", e.message); process.exit(1); });
