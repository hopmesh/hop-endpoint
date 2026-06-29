#!/usr/bin/env sh
# example.hopme.sh container entrypoint (DESIGN.md §30): run the tiny origin backend on a
# private localhost port, then exec the hop-endpoint in front of it on Cloud Run's $PORT.
#
# Env (from infra/cloud_run.tf):
#   PORT              - Cloud Run's serving port; the endpoint's WebSocket bearer.
#   HOP_DOMAIN        - the single domain this endpoint is authorized to serve.
#   HOP_IDENTITY_FILE - 32-byte identity seed (mounted secret) → stable published address.
set -eu

ORIGIN_PORT=8081
DOMAIN="${HOP_DOMAIN:-example.hopme.sh}"
IDENTITY="${HOP_IDENTITY_FILE:-/etc/hop/identity}"

# Backend origin on localhost only — never exposed; the endpoint is the only front door.
hop-example-origin --listen "127.0.0.1:${ORIGIN_PORT}" &

# The endpoint terminates hops:// for exactly $DOMAIN and fetches ONLY this origin.
exec hop-endpoint \
  --listen "0.0.0.0:${PORT}" \
  --domain "${DOMAIN}" \
  --origin "http://127.0.0.1:${ORIGIN_PORT}" \
  --identity-file "${IDENTITY}"
