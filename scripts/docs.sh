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

PY="./.venv/bin/python"
[ -x "$PY" ] || PY="python3"

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
