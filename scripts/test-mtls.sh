#!/bin/bash
set -e

SERVER="${1:-https://localhost:8443}"
CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"

echo "=== Testing mTLS Setup ==="
echo "Server: $SERVER"
echo ""

echo "1. Health check (no client cert)..."
RESP=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER/health" 2>/dev/null || echo "000")
if [ "$RESP" = "200" ]; then
    echo "   ✓ Server accessible without client cert (HTTP $RESP)"
else
    echo "   ✗ Server returned HTTP $RESP"
fi

echo ""
echo "2. Health check (with valid client cert)..."
RESP=$(curl -s -o /dev/null -w "%{http_code}" \
    --cert "$CERT_DIR/client.crt" --key "$CERT_DIR/client.key" \
    "$SERVER/health" 2>/dev/null || echo "000")
if [ "$RESP" = "200" ]; then
    echo "✓ Server accessible with client cert (HTTP $RESP)"
else
    echo "   ✗ Server returned HTTP $RESP"
fi

echo ""
echo "3. Health check (with revoked client cert)..."
RESP=$(curl -s -o /dev/null -w "%{http_code}" \
    --cert "$CERT_DIR/revoked-client.crt" --key "$CERT_DIR/revoked-client.key" \
    "$SERVER/health" 2>/dev/null || echo "000")
if [ "$RESP" = "200" ]; then
    echo "   ⚠ Server accessible with revoked cert (HTTP $RESP) - CRL may not be enforced"
else
    echo "   ✓ Server rejected revoked cert (HTTP $RESP)"
fi

echo ""
echo "4. Token endpoint with mTLS..."
TOKEN_RESP=$(curl -s \
    --cert "$CERT_DIR/client.crt" --key "$CERT_DIR/client.key" \
    -X POST "$SERVER/oauth/token" \
    -d "grant_type=client_credentials&scope=openid" 2>/dev/null || echo "{}")
echo "   Response: $TOKEN_RESP"

echo ""
echo "5. Token endpoint without mTLS (should fail if require_for_token=true)..."
RESP=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$SERVER/oauth/token" \
    -d "grant_type=client_credentials&scope=openid" 2>/dev/null || echo "000")
echo "   HTTP Status: $RESP"

echo ""
echo "=== mTLS Tests Complete ==="
