#!/usr/bin/env node
/**
 * Diagnostic: does navigator.credentials.create() work at all against a CDP
 * virtual authenticator in this Chrome, on the localhost origin?
 *
 * This isolates the WebAuthn plumbing from Keycloak's page logic.
 */
import puppeteer from 'puppeteer-core';

const CDP = 'http://127.0.0.1:9222';
const ORIGIN = 'http://localhost:8080';
const TRANSPORT = process.argv[2] || 'usb';

const browser = await puppeteer.connect({ browserURL: CDP, defaultViewport: null, protocolTimeout: 30000 });
const page = await browser.newPage();
const client = await page.createCDPSession();
const errors = [];
page.on('pageerror', e => errors.push(String(e)));

await client.send('WebAuthn.enable');
const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
  options: {
    protocol: 'ctap2',
    transport: TRANSPORT,
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
});
console.log(`virtual authenticator ${authenticatorId} transport=${TRANSPORT}`);

// Any page on the origin works for an RP-ID check.
await page.goto(`${ORIGIN}/realms/master/account/`, { waitUntil: 'domcontentloaded', timeout: 20000 });
console.log('origin:', await page.evaluate(() => window.location.origin));
console.log('isSecureContext:', await page.evaluate(() => window.isSecureContext));
console.log('hasPublicKeyCredential:', await page.evaluate(() => typeof window.PublicKeyCredential !== 'undefined'));

const result = await page.evaluate(async () => {
  const b64 = u8 => btoa(String.fromCharCode(...u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { id: 'localhost', name: 'Attest' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'probe', displayName: 'Probe' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
        timeout: 15000,
      },
    });
    const att = cred.response;
    return {
      ok: true,
      credentialId: b64(new Uint8Array(cred.rawId)).slice(0, 24) + '...',
      attachment: cred.authenticatorAttachment,
      transports: att.getTransports ? att.getTransports() : null,
      attestationObjectBytes: new Uint8Array(att.attestationObject).length,
      clientDataJSONBytes: new Uint8Array(att.clientDataJSON).length,
    };
  } catch (e) {
    return { ok: false, name: e.name, message: e.message };
  }
});

console.log('\n=== create() result ===');
console.log(JSON.stringify(result, null, 2));
if (errors.length) console.log('page errors:', errors.slice(0, 3));

// Ask the authenticator what it holds, to see if the AAGUID is discoverable.
const creds = await client.send('WebAuthn.getCredentials', { authenticatorId });
console.log('\n=== credentials held by virtual authenticator ===');
console.log(JSON.stringify(creds, null, 2));

await client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId }).catch(() => {});
await page.close();
browser.disconnect();
process.exit(0);
