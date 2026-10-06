#!/bin/bash
set -e

SERVER="${1:-http://localhost:8080}"

echo "=== Testing DPoP Functionality ==="
echo "Server: $SERVER"
echo ""

echo "1. Register client with DPoP support..."
CLIENT=$(curl -s -X POST "$SERVER/oauth/register" \
    -H "Content-Type: application/json" \
    -d '{
        "client_name": "DPoP Test Client",
        "redirect_uris": ["https://example.com/callback"],
        "grant_types": ["authorization_code", "client_credentials"],
        "scope": "openid profile",
        "dpop_bound_access_tokens": true
    }')
CLIENT_ID=$(echo "$CLIENT" | grep -o '"client_id":"[^"]*"' | cut -d'"' -f4)
CLIENT_SECRET=$(echo "$CLIENT" | grep -o '"client_secret":"[^"]*"' | cut -d'"' -f4)
echo "   Client ID: $CLIENT_ID"

echo ""
echo "2. Create test user..."
if [ -z "$MGMT_TOKEN" ]; then
    echo "   Set MGMT_TOKEN to a management access token. Skipping user creation."
else
curl -s -X POST "$SERVER/api/users" \
    -H "Authorization: Bearer $MGMT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"username":"dpopuser","password":"pass123","email":"dpop@example.com"}' > /dev/null
fi

echo ""
echo "3. Generate DPoP key pair (simulated)..."
echo "   In production, client generates EC P-256 key pair"

echo ""
echo "4. Test DPoP token request (simulated)..."
echo "   In production, client sends DPoP header with JWT proof"

echo ""
echo "5. Check server supports DPoP..."
DISCOVERY=$(curl -s "$SERVER/.well-known/openid-configuration" 2>/dev/null)
DPOP_SUPPORT=$(echo "$DISCOVERY" | grep -o '"dpop_signing_alg_values_supported"' || echo "")
if [ -n "$DPOP_SUPPORT" ]; then
    echo "   ✓ Server advertises DPoP support"
else
    echo "   ✗ Server does not advertise DPoP support"
fi

echo ""
echo "=== DPoP Tests Complete ==="
