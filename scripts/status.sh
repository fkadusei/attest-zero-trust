#!/usr/bin/env bash
# Print the actual current state of the project.
#
# HANDOFF.md tells a fresh session what it needs to know. This script exists so
# that a fresh session does not have to *believe* it: the claims in that file are
# checkable, and this checks the ones that can rot.
#
# It never fails hard and never changes anything. If it disagrees with
# HANDOFF.md, trust this script and fix the file.
#
#   scripts/status.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PY="./.venv/bin/python"
[ -x "$PY" ] || PY="python3"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
dim()  { printf '  \033[2m%s\033[0m\n' "$1"; }
ok()   { printf '  %-17s \033[32m%s\033[0m %s\n' "$1" "$2" "${3:-}"; }
bad()  { printf '  %-17s \033[31m%s\033[0m %s\n' "$1" "$2" "${3:-}"; }
warn() { printf '  %-17s \033[33m%s\033[0m %s\n' "$1" "$2" "${3:-}"; }
info() { printf '  %-17s %s %s\n' "$1" "$2" "${3:-}"; }
rule() { printf '\n\033[1m%s\033[0m\n' "$1"; }

printf '\033[1mAttest — current state\033[0m   %s\n' "$(date '+%Y-%m-%d %H:%M')"

# ---------------------------------------------------------------- repository
rule "Repository"
info "workspace" "$(pwd)"
src_count=$(find docs/src -name '*.md' 2>/dev/null | wc -l | tr -d ' ')
eng_count=$(find docs -maxdepth 1 -name '*.md' 2>/dev/null | wc -l | tr -d ' ')
site_count=$(find docs/site -maxdepth 1 -name '*.html' 2>/dev/null | wc -l | tr -d ' ')
info "sources" "${src_count} narrative pages, ${eng_count} engineering documents"
info "generated site" "${site_count} pages"
for f in HANDOFF.md WORK.md README.md; do
  [ -f "$f" ] || bad "missing" "$f"
done

# ------------------------------------------------------------- documentation
rule "Documentation"
if [ -x "./.venv/bin/python" ] || command -v python3 >/dev/null 2>&1; then
  out=$("$PY" scripts/check_docs.py 2>&1)
  if [ $? -eq 0 ]; then
    ok "build check" "PASS" "$(printf '%s' "$out" | head -1 | sed 's/^checked/— checked/')"
  else
    bad "build check" "FAIL" "run: scripts/docs.sh check"
    printf '%s\n' "$out" | sed 's/^/      /' | head -8
  fi
else
  warn "build check" "SKIPPED" "no python available"
fi

if [ -f .docs-server.pid ]; then
  read -r dspid dsport < .docs-server.pid 2>/dev/null || true
  if [ -n "${dspid:-}" ] && kill -0 "$dspid" 2>/dev/null; then
    ok "docs served" "http://localhost:${dsport}" "(pid ${dspid})"
  else
    dim "stale pidfile; run: scripts/docs.sh stop"
  fi
else
  dim "not being served; open docs/site/index.html, or: scripts/docs.sh serve"
fi

# -------------------------------------------------------------------- the lab
rule "Verification lab"
if ! command -v docker >/dev/null 2>&1; then
  warn "docker" "NOT INSTALLED"
elif ! docker info >/dev/null 2>&1; then
  bad "docker engine" "NOT RUNNING" "start Docker Desktop"
else
  info "docker engine" "running"
  if [ -f lab/keycloak/compose.yaml ]; then
    running=$(docker compose -f lab/keycloak/compose.yaml ps --status running -q 2>/dev/null | wc -l | tr -d ' ')
    if [ "$running" -ge 2 ]; then
      ok "lab containers" "${running} running"
    elif [ "$running" -eq 0 ]; then
      dim "lab not running — start with: cd lab/keycloak && docker compose up -d"
    else
      warn "lab containers" "${running} running" "(expected 2)"
    fi
  fi
fi

kc_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
  http://localhost:8080/realms/master/.well-known/openid-configuration 2>/dev/null || echo 000)
if [ "$kc_code" = "200" ]; then
  ok "identity provider" "responding" "http://localhost:8080"
else
  dim "identity provider not responding on :8080"
fi

# -------------------------------------------------------------- experiments
rule "Experiments"
found_any=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  found_any=1
  n=$(basename "$f" | sed 's/SPIKE-\(.*\)-RESULTS.md/\1/')
  # Read the experiment's OWN verdict rather than assuming a results file means
  # success — a failed experiment also writes one, and reporting it as resolved
  # is exactly the kind of misleading output this script exists to prevent.
  verdict=$(sed -n 's/.*\*\*Status: \([^*]*\)\*\*.*/\1/p' "$f" 2>/dev/null | head -1)
  verdict=${verdict%%.}
  [ ${#verdict} -gt 46 ] && verdict="${verdict:0:44}…"
  case "$verdict" in
    UNRESOLVED*|FAILED*|BLOCKED*) bad "Spike #${n}" "${verdict:-see file}" ;;
    RESOLVED*)                    ok  "Spike #${n}" "$verdict" ;;
    "")                           warn "Spike #${n}" "NO STATUS LINE" "$f" ;;
    *)                            warn "Spike #${n}" "$verdict" ;;
  esac
done < <(find lab -name 'SPIKE-*-RESULTS.md' 2>/dev/null | sort)
[ "$found_any" -eq 1 ] || dim "no experiment results recorded yet"

if [ -f WORK.md ]; then
  # Matches "## ▶ S4 — title — **NEXT**" at any heading depth.
  nxt=$(grep -m1 '^#\{2,\}[[:space:]]*▶' WORK.md 2>/dev/null \
        | sed 's/^#*[[:space:]]*▶[[:space:]]*//; s/[[:space:]]*—[[:space:]]*\*\*NEXT\*\*//')
  if [ -n "${nxt:-}" ]; then
    printf '  %-17s \033[36m%s\033[0m\n' "NEXT" "$nxt"
  else
    warn "next slice" "NOT MARKED" "add a ▶ line to WORK.md"
  fi
  printf '  %-17s %s\n' "full roadmap" "WORK.md"
fi

# -------------------------------------------------------------- environment
rule "Environment"
if command -v python3 >/dev/null 2>&1; then
  v=$(python3 -V 2>&1 | awk '{print $2}')
  if [ -x "./.venv/bin/python" ]; then info "python" "$v" "(venv present)"; else warn "python" "$v" "(no venv — see requirements-docs.txt)"; fi
fi
command -v node >/dev/null 2>&1 && info "node" "$(node -v 2>/dev/null)"
if command -v docker >/dev/null 2>&1; then
  info "docker" "$(docker --version 2>/dev/null | sed 's/Docker version //; s/,.*//')"
fi

# AWS: credentials expire, and several slices depend on them.
if command -v aws >/dev/null 2>&1; then
  awsv=$(aws --version 2>&1 | awk '{print $1}' | sed 's|aws-cli/||')
  if aws sts get-caller-identity >/tmp/.attest-aws 2>/tmp/.attest-awserr; then
    acct=$(python3 -c "import json;print(json.load(open('/tmp/.attest-aws'))['Account'])" 2>/dev/null)
    region=$(aws configure get region 2>/dev/null)
    ok "aws credentials" "valid" "account ${acct:-?} region ${region:-unset}"
  else
    bad "aws credentials" "EXPIRED" "run: aws login   (needed for S1b, S2, S7, S8)"
  fi
  rm -f /tmp/.attest-aws /tmp/.attest-awserr
else
  warn "aws cli" "NOT INSTALLED"
fi

for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
         "/Applications/Chromium.app/Contents/MacOS/Chromium" \
         "/usr/bin/google-chrome"; do
  if [ -x "$c" ]; then
    info "chrome" "present" "(needs --no-sandbox in this environment)"
    break
  fi
done

# ------------------------------------------------------------------ blockers
rule "Blockers for the next slice"
if [ -f WORK.md ]; then
  dim "S4 and S5 need nothing beyond this machine"
  dim "S3b needs a physical hardware key"
  dim "S1b, S2, S7, S8 need AWS credentials"
  if [ "$kc_code" != "200" ]; then
    dim "note: the identity provider is down, which some slices will need"
  fi
fi

printf '\n'
dim "Slices and estimates: WORK.md     Project state and traps: HANDOFF.md"
printf '\n'
