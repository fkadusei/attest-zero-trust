#!/usr/bin/env bash
# Start, stop and inspect the lab.
#
# EXISTS FOR ONE REASON: `docker compose` looks for `.env` beside the compose file or
# in the working directory, and the credentials live at `lab/.env` — a directory above
# both compose files. Every invocation therefore needs `--env-file`, and a rule that
# has to be remembered is a rule that will be forgotten. One wrapper, one place.
#
# Usage:
#   scripts/lab.sh up      [keycloak|app]   start the labs (both by default)
#   scripts/lab.sh down    [keycloak|app]   stop them
#   scripts/lab.sh status                   what is running
#   scripts/lab.sh env                      print the credential variables
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/lab/.env"

# Generate the credentials on first use rather than requiring a setup step that
# would only be discovered by failing.
if [ ! -f "$ENV_FILE" ]; then
  python3 "$ROOT/lab/keycloak/scripts/lab_env.py" >/dev/null
  echo "generated $ENV_FILE" >&2
fi

compose() {
  local which="$1"; shift
  docker compose --env-file "$ENV_FILE" -f "$ROOT/lab/$which/compose.yaml" "$@"
}

targets() {
  if [ "$#" -gt 0 ] && [ -n "$1" ]; then echo "$@"; else echo "keycloak app"; fi
}

case "${1:-}" in
  up)     shift; for t in $(targets "$@"); do compose "$t" up -d; done ;;
  down)   shift; for t in $(targets "$@"); do compose "$t" down; done ;;
  status) for t in keycloak app; do
            echo "== $t"
            compose "$t" ps --format '  {{.Name}}  {{.Status}}' 2>/dev/null || true
          done ;;
  logs)   shift; compose "${1:-keycloak}" logs --tail "${2:-50}" ;;
  env)    grep -v '^#' "$ENV_FILE" | grep . ;;
  reset)  # Regenerate the credentials AND rebuild the containers.
          #
          # Regenerating lab/.env on its own ORPHANS every running container: they hold
          # the credentials they were created with, the scripts read the new ones, and
          # the result is `invalid_grant` and "password authentication failed" — which
          # look like an identity-provider fault and a database fault respectively, and
          # are neither. Discovered by regenerating the file and watching 106 tests
          # fail. The two steps belong together, so they are one command.
          rm -f "$ENV_FILE"
          python3 "$ROOT/lab/keycloak/scripts/lab_env.py" >/dev/null
          for t in keycloak app; do compose "$t" down -v; done
          for t in keycloak app; do compose "$t" up -d; done
          echo "credentials regenerated and containers rebuilt" >&2 ;;
  *)      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//' ; exit 1 ;;
esac
