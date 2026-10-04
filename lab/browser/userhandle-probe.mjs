#!/usr/bin/env node
/**
 * E2E-2 — why does the console's passkey have no userHandle?
 *
 * Keycloak's passwordless flow is a DISCOVERABLE-CREDENTIAL flow: it identifies the
 * user from the passkey's `userHandle`, with no username typed. A credential
 * carrying none can never sign anyone in, which is what the console's passkey sign-in
 * hits with `webauthn-error-user-not-found`.
 *
 * There are exactly three layers that could be responsible, and they are
 * distinguishable:
 *
 *   1. **Keycloak's request.** `navigator.credentials.create({publicKey:{user:{id}}}`
 *      — if Keycloak does not send a `user.id`, the authenticator has nothing to
 *      store and every credential it makes will be anonymous.
 *   2. **The authenticator.** CDP's virtual authenticator is asked to store a
 *      resident key. `WebAuthn.getCredentials` reports what it ACTUALLY holds.
 *   3. **Keycloak's storage.** What ends up in `credentialData` via the admin API.
 *
 * This measures all three, in order, so the answer is a measurement rather than a
 * guess. The existing end-to-end run only observes layer 3.
 */
import { createRequire } from "node:module";
import { spawn, spawnSync } from "node:child_process";

const require = createRequire("/Users/felixadusei/Development/AI_Engineering/DeepSeek/passwordless/lab/keycloak/package.json");
const puppeteer = require("puppeteer-core");

const KC = "http://localhost:8080";
const REALM = process.env["E2E_REALM"] ?? "attest-privileged";
const USERNAME = "userhandle-probe";
const PASSWORD = "Probe-Password-123!";
const CDP_PORT = 9344;
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

async function main() {
  console.log("=".repeat(84));
  console.log(`E2E-2 — where is the userHandle lost?   (realm: ${REALM})`);
  console.log("=".repeat(84));

  // ---- fixtures -----------------------------------------------------------
  let users = await admin("GET", `/${REALM}/users?username=${USERNAME}&exact=true`);
  if (!users?.length) {
    await admin("POST", `/${REALM}/users`, {
      username: USERNAME, enabled: true, emailVerified: true,
      email: `${USERNAME}@example.test`, firstName: "Handle", lastName: "Probe",
    });
    users = await admin("GET", `/${REALM}/users?username=${USERNAME}&exact=true`);
  }
  const userId = users[0].id;
  await admin("PUT", `/${REALM}/users/${userId}/reset-password`, {
    type: "password", value: PASSWORD, temporary: false });
  // Remove any credential from an earlier probe, so what is measured is new.
  for (const c of (await admin("GET", `/${REALM}/users/${userId}/credentials`)) ?? []) {
    if ((c.type ?? "").startsWith("webauthn")) {
      await admin("DELETE", `/${REALM}/users/${userId}/credentials/${c.id}`);
    }
  }
  console.log(`\n  user id: ${userId}`);

  // ---- chrome -------------------------------------------------------------
  spawnSync("pkill", ["-f", "user-data-dir=/tmp/handle-probe-chrome"]);
  spawnSync("rm", ["-rf", "/tmp/handle-probe-chrome"]);
  await sleep(1000);
  const chrome = spawn(CHROME, ["--headless=new", "--disable-gpu", "--no-sandbox",
    `--remote-debugging-port=${CDP_PORT}`, "--user-data-dir=/tmp/handle-probe-chrome",
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
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "usb", hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  page.on("dialog", async (d) => { try { await d.accept("Probe"); } catch { /* ignore */ } });

  // ---- LAYER 1: what does Keycloak ASK FOR? -------------------------------
  // Hook create() before any script runs. This records the exact publicKey options
  // Keycloak builds, which is the only way to see whether it sends `user.id`.
  await page.evaluateOnNewDocument(() => {
    window.__createCalls = [];
    const original = navigator.credentials?.create?.bind(navigator.credentials);
    if (!original) return;
    navigator.credentials.create = async function (options) {
      const pk = options?.publicKey;
      if (pk) {
        const record = {
          hasUser: Boolean(pk.user),
          userName: pk.user?.name ?? null,
          displayName: pk.user?.displayName ?? null,
          userIdType: pk.user?.id?.constructor?.name ?? null,
          userIdLength: pk.user?.id?.byteLength ?? pk.user?.id?.length ?? null,
          userIdRaw: (() => {
            try {
              const id = pk.user?.id;
              if (!id) return null;
              return Array.from(new Uint8Array(id)).map((b) => b.toString(16).padStart(2, "0")).join("");
            } catch { return "unreadable"; }
          })(),
          // These are in `authenticatorSelection`, not at the top level.
          residentKey: pk.authenticatorSelection?.residentKey ?? null,
          requireResidentKey: pk.authenticatorSelection?.requireResidentKey ?? null,
          userVerification: pk.authenticatorSelection?.userVerification ?? null,
          rpId: pk.rp?.id ?? null,
        };
        window.__createCalls.push(record);
      }
      return original(options);
    };
  });

  const results = [];
  const check = (label, got, want) => {
    const ok = got === want;
    results.push({ label, got, want, ok });
    console.log(`  ${label.padEnd(56)} ${String(got).padEnd(22)} ${ok ? "PASS" : "FAIL"}`);
  };

  try {
    spawnSync(PY, [PASSKEY_TOOL, "revert"]);
    await admin("PUT", `/${REALM}/users/${userId}`, {
      ...(await admin("GET", `/${REALM}/users/${userId}`)),
      requiredActions: ["webauthn-register-passwordless"],
    });

    console.log("\n[1] register a passkey through Keycloak");
    const authUrl = `${KC}/realms/${REALM}/protocol/openid-connect/auth?` + new URLSearchParams({
      client_id: "account", response_type: "code",
      redirect_uri: `${KC}/realms/${REALM}/account/`, scope: "openid", state: "p", nonce: "p",
    });
    await page.goto(authUrl, { waitUntil: "networkidle2", timeout: 45000 }).catch(() => {});
    if (await page.$("#username")) {
      await page.type("#username", USERNAME);
      await page.type("#password", PASSWORD);
      await Promise.all([
        page.waitForNavigation({ waitUntil: "networkidle2", timeout: 45000 }).catch(() => {}),
        page.click("#kc-login"),
      ]);
    }
    await sleep(1500);

    const registerHandle = await page.evaluateHandle(() => {
      const c = [...document.querySelectorAll("input[type=submit], button")];
      return c.find((e) => /register|save|continue/i.test(e.value || e.textContent || "")) ?? null;
    });
    const registerEl = registerHandle.asElement();
    if (registerEl) { await registerEl.click().catch(() => {}); await sleep(8000); }
    const pageAfter = await page.evaluate(() => ({
      title: document.title,
      error: document.querySelector(".kc-feedback-text, #input-error, .alert-error")?.textContent?.trim() ?? null,
    })).catch(() => ({}));
    console.log(`      page: ${JSON.stringify(pageAfter).slice(0, 160)}`);

    // ---- LAYER 1 result ---------------------------------------------------
    console.log("\n[2] LAYER 1 — what Keycloak asked the authenticator for");
    const calls = await page.evaluate(() => window.__createCalls ?? []).catch(() => []);
    console.log(`      create() calls observed: ${calls.length}`);
    for (const c of calls) console.log(`      ${JSON.stringify(c)}`);

    if (calls.length === 0) {
      check("Keycloak called navigator.credentials.create", false, true);
    } else {
      const call = calls[calls.length - 1];
      check("Keycloak SENT a user.id", call.hasUser && call.userIdLength > 0, true);
      check("it requested a RESIDENT (discoverable) key",
        call.residentKey === "required" || call.requireResidentKey === true, true);
      check("it requested user verification", call.userVerification === "required", true);
      console.log(`      user.id hex: ${String(call.userIdRaw).slice(0, 80)}`);
      // Keycloak uses the user id, base64url-ish, as the handle. Compare.
      const expected = Buffer.from(userId.replaceAll("-", ""), "hex").toString("hex");
      console.log(`      user uuid hex: ${expected.slice(0, 80)}`);
    }

    // ---- LAYER 2: what did the AUTHENTICATOR store? -----------------------
    console.log("\n[3] LAYER 2 — what the AUTHENTICATOR actually stored");
    const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
    console.log(`      credentials on the authenticator: ${credentials.length}`);
    for (const c of credentials) {
      console.log(`      credentialId=${String(c.credentialId).slice(0, 24)}... resident=${c.isResidentCredential}`);
      console.log(`      userHandle=${c.userHandle ? `"${c.userHandle}" (${c.userHandle.length} chars)` : "ABSENT"}`);
    }
    if (credentials.length > 0) {
      const withHandle = credentials.filter((c) => c.userHandle && c.userHandle.length > 0);
      check("the authenticator holds a credential WITH a userHandle", withHandle.length > 0, true);
    }

    // ---- LAYER 3: what did Keycloak STORE? --------------------------------
    console.log("\n[4] LAYER 3 — what KEYCLOAK stored");
    const creds = (await admin("GET", `/${REALM}/users/${userId}/credentials`)) ?? [];
    const webauthn = creds.filter((c) => (c.type ?? "").startsWith("webauthn"));
    check("Keycloak stored a webauthn credential", webauthn.length, 1);
    for (const c of webauthn) {
      const data = JSON.parse(c.credentialData);
      console.log(`      credentialData keys: ${Object.keys(data).join(", ")}`);
      console.log(`      userHandle: ${data.userHandle ? `"${data.userHandle}"` : "ABSENT"}`);
      check("Keycloak stored a userHandle", Boolean(data.userHandle), true);
    }
  } finally {
    await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => {});
    await page.close().catch(() => {});
    browser.disconnect();
    chrome.kill();
    spawnSync("pkill", ["-f", "user-data-dir=/tmp/handle-probe-chrome"]);
    spawnSync(PY, [PASSKEY_TOOL, "revert"]);
  }

  const passed = results.filter((r) => r.ok).length;
  console.log("\n" + "=".repeat(84));
  console.log(`userHandle probe: ${passed}/${results.length}`);
  console.log("=".repeat(84));
  process.exit(0);
}

main().catch((e) => { console.error("  harness error:", e.message); process.exit(1); });
