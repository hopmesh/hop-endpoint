#!/usr/bin/env sh
# example.hopme.sh container entrypoint (DESIGN.md §30): run the tiny origin backend on a
# private localhost port, then run the hop-endpoint in front of it on Cloud Run's $PORT.
#
# services-14: supervise BOTH processes. The endpoint is useless without its origin - a crashed
# origin turns example.hopme.sh into a permanent 502 ("backend unreachable") until someone manually
# restarts the revision. So if EITHER process exits (origin or endpoint), we exit the whole
# container non-zero, which makes Cloud Run restart the instance and bring both back up together.
#
# Env (from infra/cloud_run.tf):
#   PORT              - Cloud Run's serving port; the endpoint's WebSocket bearer.
#   HOP_DOMAIN        - the single domain this endpoint is authorized to serve.
#   HOP_IDENTITY_FILE - 32-byte identity seed (mounted secret) -> stable published address.
set -eu

ORIGIN_PORT=8081
DOMAIN="${HOP_DOMAIN:-example.hopme.sh}"
IDENTITY="${HOP_IDENTITY_FILE:-/etc/hop/identity}"

# PIDs of the supervised children, filled in as we start them.
ORIGIN_PID=""
ENDPOINT_PID=""

# On any signal or exit, tear down both children so we never leak an orphaned process into a
# restarting container.
shutdown() {
  [ -n "${ORIGIN_PID}" ] && kill "${ORIGIN_PID}" 2>/dev/null || true
  [ -n "${ENDPOINT_PID}" ] && kill "${ENDPOINT_PID}" 2>/dev/null || true
}
trap shutdown INT TERM EXIT

# Backend origin on localhost only - never exposed; the endpoint is the only front door.
hop-example-origin --listen "127.0.0.1:${ORIGIN_PORT}" &
ORIGIN_PID=$!

# The endpoint terminates hops:// for exactly $DOMAIN and fetches ONLY this origin.
hop-endpoint \
  --listen "0.0.0.0:${PORT}" \
  --domain "${DOMAIN}" \
  --origin "http://127.0.0.1:${ORIGIN_PORT}" \
  --identity-file "${IDENTITY}" &
ENDPOINT_PID=$!

# Wait for whichever child exits FIRST, capture its status, and exit with it. `wait -n` isn't in
# POSIX sh, so poll: as soon as either PID is no longer alive, reap it and propagate a failure so
# Cloud Run restarts the instance (bringing the missing half back).
while true; do
  if ! kill -0 "${ORIGIN_PID}" 2>/dev/null; then
    wait "${ORIGIN_PID}" 2>/dev/null || true
    echo "entrypoint: origin (pid ${ORIGIN_PID}) exited; restarting container" >&2
    exit 1
  fi
  if ! kill -0 "${ENDPOINT_PID}" 2>/dev/null; then
    wait "${ENDPOINT_PID}" 2>/dev/null || true
    echo "entrypoint: endpoint (pid ${ENDPOINT_PID}) exited; restarting container" >&2
    exit 1
  fi
  sleep 1
done
