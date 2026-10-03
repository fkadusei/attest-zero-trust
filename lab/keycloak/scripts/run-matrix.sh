#!/usr/bin/env bash
# Spike #3 test matrix. Each cell changes ONE variable, so every rejection has
# a single possible cause. Results are only trustworthy because the harness
# deletes stale credentials and requires a NEW credential id.
#
#   test                              realm              allowlist    attach        transport  expect
#   A  baseline, unrestricted         attest-users       []           not specified usb        ACCEPT
#   B  allowlist enforced             attest-privileged  [YubiKey]    cross-platform usb       REJECT
#   C  control: allowlist empty       attest-privileged  []           cross-platform usb       ACCEPT
#   D  attachment enforced            attest-privileged  []           cross-platform internal  REJECT
#   E  control: internal unrestricted attest-privileged  []           not specified internal   ACCEPT
set -u
cd "$(dirname "$0")/.." || exit 1

YUBIKEY='fa2b99dc-9e39-4257-8f92-4a30d23c4118'

configure() {  # configure <allowlist-json> <attachment> <conveyance>
  python3 scripts/patch-realm.py attest-privileged \
    "{\"webAuthnPolicyPasswordlessAcceptableAaguids\":$1,\"webAuthnPolicyPasswordlessAuthenticatorAttachment\":\"$2\",\"webAuthnPolicyPasswordlessAttestationConveyancePreference\":\"$3\"}" \
    >/dev/null 2>&1
}

run() {  # run <label> <realm> <transport> <expected>
  local label="$1" realm="$2" transport="$3" expect="$4"
  local out verdict
  out=$(node scripts/spike3-enrolment-test.mjs "$realm" "$transport" 2>&1)
  verdict=$(printf '%s\n' "$out" | sed -n 's/^OUTCOME: //p' | tail -1)
  local mark="??"
  [ "$verdict" = "$expect" ] && mark="PASS" || mark="FAIL"
  printf '%-42s %-8s (expected %-8s) %s\n' "$label" "$verdict" "$expect" "$mark"
}

echo "=== Spike #3 enforcement matrix ==="
echo

printf '%-42s %-8s %-16s %s\n' "TEST" "RESULT" "EXPECTED" "VERDICT"
printf '%-42s %-8s %-16s %s\n' "------------------------------------------" "--------" "----------------" "-------"

configure '[]' 'not specified' 'none'
run "A. baseline (unrestricted)" attest-users usb ACCEPTED

configure "[\"$YUBIKEY\"]" 'cross-platform' 'none'
run "B. allowlist=[YubiKey], usb" attest-privileged usb REJECTED

configure '[]' 'cross-platform' 'none'
run "C. control: allowlist=[], usb" attest-privileged usb ACCEPTED

configure '[]' 'cross-platform' 'none'
run "D. attachment=cross-platform, internal" attest-privileged internal REJECTED

configure '[]' 'not specified' 'none'
run "E. control: internal unrestricted" attest-privileged internal ACCEPTED

# Restore the documented production-intent configuration.
configure "[\"$YUBIKEY\"]" 'cross-platform' 'direct'
echo
echo "restored privileged realm: allowlist=[YubiKey], attachment=cross-platform, conveyance=direct"
