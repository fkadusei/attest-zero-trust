#!/usr/bin/env bash
# Convenience wrapper for the documentation pipeline.
#
#   scripts/docs.sh build     regenerate docs/site from the Markdown sources
#   scripts/docs.sh diagrams  re-render Mermaid diagrams to SVG  (needs Node)
#   scripts/docs.sh check     verify links, anchors, offline-safety and freshness
#   scripts/docs.sh serve     build, then serve on the first free port from 8082
#   scripts/docs.sh stop      stop a server started by `serve`
#   scripts/docs.sh all       diagrams + build + check
#
# The generated site is committed, so readers never need to run any of this.
set -euo pipefail
cd "$(dirname "$0")/.."

# The docs build is pinned to Python 3.12, because the rendered HTML depends on the
# interpreter minor and not only on the library versions:
#
#   Python 3.12 + markdown 3.11.1  ->  <strong>is</strong>     (correct)
#   Python 3.14 + markdown 3.11.1  ->  </em><em>is</em><em>   (mis-rendered)
#
# build_docs.py refuses to run on anything else, so pick a 3.12 interpreter rather than
# producing bytes that another machine will report as STALE.
if [ -x ".venv-docs/bin/python" ] && .venv-docs/bin/python -c 'import sys; raise SystemExit(0 if sys.version_info[:2]==(3,12) else 1)' 2>/dev/null; then
  PY="./.venv-docs/bin/python"
elif [ -x ".venv/bin/python" ] && .venv/bin/python -c 'import sys; raise SystemExit(0 if sys.version_info[:2]==(3,12) else 1)' 2>/dev/null; then
  PY="./.venv/bin/python"
elif command -v python3.12 >/dev/null 2>&1; then
  PY="python3.12"
else
  PY="./.venv/bin/python"   # let build_docs.py explain why it refuses
fi

PIDFILE=".docs-server.pid"

cmd="${1:-build}"
shift || true

case "$cmd" in
  diagrams)
    node tools/render_diagrams.mjs
    ;;
  build)
    "$PY" scripts/build_docs.py
    ;;
  check)
    "$PY" scripts/check_docs.py
    ;;
  all)
    node tools/render_diagrams.mjs
    "$PY" scripts/build_docs.py
    "$PY" scripts/check_docs.py
    ;;
  serve)
    exec "$PY" scripts/serve_docs.py "$@"
    ;;
  stop)
    if [ ! -f "$PIDFILE" ]; then
      echo "no docs server recorded ($PIDFILE not found)."
      # Fall back to finding anything else that looks like one.
      if command -v pgrep >/dev/null 2>&1; then
        pids=$(pgrep -f "serve_docs.py" || true)
        if [ -n "$pids" ]; then
          echo "but these look like docs servers: $pids"
          echo "kill them with:  kill $pids"
        fi
      fi
      exit 0
    fi
    pid=$(awk '{print $1}' "$PIDFILE")
    if kill "$pid" 2>/dev/null; then
      echo "stopped docs server (pid $pid)"
    else
      echo "pid $pid was not running; removing stale $PIDFILE"
    fi
    rm -f "$PIDFILE"
    ;;
  *)
    sed -n '2,12p' "$0"
    exit 2
    ;;
esac
