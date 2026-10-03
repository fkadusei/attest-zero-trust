/**
 * Failure modes for token verification.
 *
 * These are distinguished INTERNALLY so that logs and tests can tell one failure
 * from another. They must NOT be returned to a caller as-is: a verifier that
 * reports "bad signature" versus "unknown key" versus "expired" is an oracle that
 * tells an attacker which part of a forgery to fix next.
 *
 * The caller sees one opaque rejection. The log sees the reason.
 */
export type FailureReason =
  | "malformed"
  | "unsupported_algorithm"
  | "unknown_key"
  | "bad_signature"
  | "wrong_issuer"
  | "wrong_audience"
  | "expired"
  | "not_yet_valid"
  | "wrong_token_type"
  | "jwks_unavailable"
  | "missing_tenant";

export class TokenVerificationError extends Error {
  readonly reason: FailureReason;

  constructor(reason: FailureReason, detail?: string) {
    // The message is for logs only. It is never sent to a client.
    super(detail ? `${reason}: ${detail}` : reason);
    this.name = "TokenVerificationError";
    this.reason = reason;
  }
}

/**
 * The fail-closed gate.
 *
 * Anything that is not an explicitly recognised, fully-verified token is refused.
 * Written as a single helper so no call site can accidentally treat an ambiguous
 * result as success — the shape of this project's past mistakes.
 */
export function isVerified<T>(
  result: { ok: true; value: T } | { ok: false; reason: FailureReason },
): result is { ok: true; value: T } {
  return result.ok;
}
