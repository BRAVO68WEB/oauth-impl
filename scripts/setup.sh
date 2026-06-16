#!/bin/bash
set -e

SERVER_URL="${1:-http://127.0.0.1:8080}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              OAuth Server Setup Script                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if server is running
echo "1. Checking server status..."
if ! curl -s "$SERVER_URL/health" > /dev/null 2>&1; then
    echo "   Server not reachable at $SERVER_URL"
    echo "   Starting server..."
    go run ./cmd/oauth-server/ &
    SERVER_PID=$!
    sleep 3
    echo "   Server started (PID: $SERVER_PID)"
else
    echo "   Server is running"
fi

# Create master client
echo ""
echo "2. Creating master client..."
RESPONSE=$(curl -s -X POST "$SERVER_URL/api/clients" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Master Client",
        "redirect_uris": [
            "https://localhost/callback",
            "http://localhost:3000/callback",
            "http://localhost:8080/callback"
        ],
        "grant_types": [
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "password",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:openid:params:grant-type:ciba",
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ],
        "scopes": [
            "openid", "profile", "email", "address", "phone", "offline_access",
            "read", "write", "admin"
        ],
        "token_endpoint_auth_method": "client_secret_basic",
        "dpop_bound_access_tokens": false,
        "require_pushed_authorization_requests": false,
        "backchannel_token_delivery_mode": "poll"
    }')

CLIENT_ID=$(echo "$RESPONSE" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
CLIENT_SECRET=$(echo "$RESPONSE" | grep -o '"secret":"[^"]*"' | cut -d'"' -f4)

echo "   Master client created!"
echo ""

# Create test user
echo "3. Creating test user..."
curl -s -X POST "$SERVER_URL/api/users" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "admin",
        "password": "admin123",
        "email": "admin@example.com"
    }' > /dev/null 2>&1 || true

echo "   Test user created (admin/admin123)"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Setup Complete                            ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Server URL:     $SERVER_URL"
echo "║  Client ID:      $CLIENT_ID"
echo "║  Client Secret:  $CLIENT_SECRET"
echo "║  Test User:      admin / admin123"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Quick Test:                                                 ║"
echo "║  curl -u $CLIENT_ID:$CLIENT_SECRET \\"
echo "║    -X POST $SERVER_URL/oauth/token \\"
echo "║    -d 'grant_type=client_credentials&scope=openid'"
echo "╚══════════════════════════════════════════════════════════════╝"
