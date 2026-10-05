/**
 * S1b — does a real proxy chain preserve the `DPoP` header?
 *
 * THE QUESTION, AND WHAT IT ACTUALLY SAYS
 *
 * S1b was written as "does the DPoP header survive CloudFront → ALB → API Gateway". That
 * specific chain needs AWS. But the thing being worried about is not AWS — it is whether a
 * real CDN/WAF in the path forwards an unfamiliar request header, and Cloudflare's edge is
 * exactly that kind of hop. So this answers the question for Cloudflare and is honest that
 * it does not answer it for CloudFront.
 *
 * WHY IT MATTERS MORE THAN IT LOOKS
 *
 * A proxy that drops `DPoP` does not produce a partial failure. The token is bound, so the
 * API correctly refuses it — and the user sees a sign-in that works and an application that
 * rejects everything. The failure is silent in the one place it would be diagnosed, because
 * the component that dropped the header is not the component reporting the error.
 *
 * HOW IT IS MEASURED
 *
 * The API distinguishes the two cases with different messages, which is what makes this
 * measurable rather than a guess:
 *
 *   header STRIPPED   -> "bound token presented without a DPoP proof"
 *   header ARRIVED    -> a proof-specific outcome (accepted, or a reason naming the proof)
 *
 * Both runs use a real DPoP-bound token from the live provider and a real proof.
 *
 * THE CONTROL
 *
 * The same request, the same token, the same proof, sent directly to `localhost:3000` with
 * no proxy in the path. Without it, a refusal through the tunnel would be indistinguishable
 * from a broken proof. The control must SUCCEED for the comparison to mean anything.
 *
 * Note the request URI is what the proof's `htu` must match, and the API derives that from
 * its own `PUBLIC_BASE_URL` rather than from forwarded headers — deliberately, because
 * trusting `X-Forwarded-*` for the value you are validating is circular. So each run needs
 * the API configured for the base it is being called on.
 */
import { setupBoundToken } from "../../apps/api/test/dpop-harness.ts";

const BASE = process.argv[2];
const LABEL = process.argv[3] ?? BASE;
if (!BASE) {
  console.error("usage: node s1b-dpop-proxy.mts <base-url> [label]");
  process.exit(2);
}

const PATH = "/v1/evidence";

async function main() {
  console.log(`\n  ── ${LABEL}`);
  console.log(`     base: ${BASE}`);

  const { key, token, payload, thumbprint } = await setupBoundToken();
  console.log(`     token: DPoP-bound, cnf.jkt=${thumbprint.slice(0, 16)}...`);
  console.log(`     iss:   ${String(payload["iss"]).slice(0, 60)}`);

  const url = `${BASE}${PATH}`;
  // `ath` binds the proof to THIS access token. A resource request MUST carry it —
  // omitting it produced "DPoP proof is missing the ath claim", which looks like a proxy
  // problem and is a probe bug. The harness only adds `ath` when the token is passed in.
  const proof = await key.proof({ method: "GET", uri: url, accessToken: token });

  // Confirm we are actually sending a header before concluding anything about whether it
  // arrives. A probe whose request never carried the header would "prove" stripping.
  if (!proof || proof.length < 20) throw new Error("the harness produced no proof — nothing to send");

  const res = await fetch(url, {
    headers: { authorization: `DPoP ${token}`, DPoP: proof },
    signal: AbortSignal.timeout(20_000),
  });
  const body = await res.text();

  let parsed: Record<string, unknown> = {};
  try { parsed = JSON.parse(body) as Record<string, unknown>; } catch { /* not json */ }
  const error = String(parsed["error"] ?? "").slice(0, 80);
  const detail = String(parsed["message"] ?? parsed["detail"] ?? "").slice(0, 120);

  console.log(`     sent  : proof ${proof.length} chars, DPoP scheme`);
  console.log(`     status: ${res.status}`);
  console.log(`     error : ${error || "(none)"}`);
  if (detail) console.log(`     detail: ${detail}`);

  // Classify, so the comparison does not depend on reading.
  let verdict: string;
  if (res.status === 200) verdict = "PROOF ARRIVED — request authorised";
  else if (/without a DPoP proof/i.test(`${error} ${detail} ${body}`)) verdict = "HEADER STRIPPED — proof never arrived";
  else if (/scheme/i.test(`${error} ${detail}`)) verdict = "HEADER ARRIVED but the scheme was altered";
  else verdict = `ARRIVED (refused for another reason: ${error || res.status})`;

  console.log(`     verdict: ${verdict}`);

  // Print the headers Cloudflare added, since their presence is what shows the request
  // really did traverse the edge rather than going direct.
  const cf = [...res.headers.entries()].filter(([k]) => k.startsWith("cf-"));
  if (cf.length) console.log(`     cloudflare headers: ${cf.map(([k]) => k).join(", ").slice(0, 90)}`);

  return { label: LABEL, status: res.status, error, verdict, throughCloudflare: cf.length > 0 };
}

main()
  .then((r) => { console.log(`\n  RESULT ${JSON.stringify(r)}`); process.exit(0); })
  .catch((e) => { console.error(`  probe error: ${String(e).slice(0, 200)}`); process.exit(1); });
