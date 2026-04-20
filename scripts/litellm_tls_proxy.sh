#!/usr/bin/env bash
# Terminate TLS locally so agentscoped can observe traffic destined for a
# plain-HTTP LiteLLM endpoint. agents connect to https://127.0.0.1:4443/..,
# socat decrypts and forwards plaintext to $LITELLM_UPSTREAM.
#
# Usage:
#   LITELLM_UPSTREAM=10.10.0.54:4000 LITELLM_KEY=sk-... ./litellm_tls_proxy.sh
set -euo pipefail

: "${LITELLM_UPSTREAM:?set LITELLM_UPSTREAM=host:port}"
CERT_DIR="${CERT_DIR:-/tmp/agtest}"
PEM="$CERT_DIR/litellm_proxy.pem"
LISTEN_PORT="${LISTEN_PORT:-4443}"

mkdir -p "$CERT_DIR"
if [[ ! -f "$PEM" ]]; then
    if [[ ! -f "$CERT_DIR/cert.pem" ]]; then
        openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/key.pem" \
            -out "$CERT_DIR/cert.pem" -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
    fi
    cat "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem" > "$PEM"
    chmod 600 "$PEM"
fi

echo "socat HTTPS terminator: :${LISTEN_PORT} -> ${LITELLM_UPSTREAM}"
exec socat \
    "OPENSSL-LISTEN:${LISTEN_PORT},reuseaddr,fork,cert=${PEM},verify=0" \
    "TCP:${LITELLM_UPSTREAM}"
