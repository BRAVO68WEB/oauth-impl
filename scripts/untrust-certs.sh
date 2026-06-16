#!/bin/bash
set -e

CERT_DIR="${1:-./certs}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              Untrust / Remove CA Certificate                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

OS=$(uname -s)

case "$OS" in
    Darwin)
        echo "Detected: macOS"
        echo ""
        echo "Removing from System Keychain..."
        sudo security delete-certificate -c "OAuth Test CA" /Library/Keychains/System.keychain 2>/dev/null && {
            echo "  ✓ Removed from System Keychain"
        } || echo "  ⚠ Not found in System Keychain"

        echo "Removing from login Keychain..."
        security delete-certificate -c "OAuth Test CA" ~/Library/Keychains/login.keychain-db 2>/dev/null && {
            echo "  ✓ Removed from login Keychain"
        } || echo "  ⚠ Not found in login Keychain"
        ;;

    Linux)
        echo "Detected: Linux"
        echo ""

        if [ -f /etc/debian_version ]; then
            echo "Removing from system trust store (Debian/Ubuntu)..."
            sudo rm -f /usr/local/share/ca-certificates/oauth-test-ca.crt
            sudo update-ca-certificates 2>/dev/null
            echo "  ✓ Removed"
        elif [ -f /etc/redhat-release ]; then
            echo "Removing from system trust store (RHEL/Fedora)..."
            sudo rm -f /etc/pki/ca-trust/source/anchors/oauth-test-ca.crt
            sudo update-ca-trust 2>/dev/null
            echo "  ✓ Removed"
        fi
        ;;

    MINGW*|MSYS*|CYGWIN*|Windows_NT)
        echo "Detected: Windows"
        echo ""
        echo "Removing from Windows Trusted Root store..."
        certutil -delstore "Root" "OAuth Test CA" 2>/dev/null && {
            echo "  ✓ Removed"
        } || echo "  ⚠ Not found (run as Administrator)"
        ;;

    *)
        echo "Unknown OS: $OS"
        ;;
esac

echo ""
echo "Also remove from Firefox manually:"
echo "  Settings → Privacy & Security → Certificates → View Certificates"
echo "  → Authorities → Find 'OAuth Test CA' → Delete or Distrust"
echo ""
echo "Done!"
