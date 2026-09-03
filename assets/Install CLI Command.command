#!/bin/bash
set -e

echo "=========================================="
echo "  Rune Authenticator - CLI Setup"
echo "=========================================="
echo ""
echo "This will install the 'rune' CLI command into /usr/local/bin/rune."
echo "You may be prompted for your administrator password."
echo ""

sudo mkdir -p /usr/local/bin
sudo ln -sf "/Applications/Rune.app/Contents/MacOS/rune" /usr/local/bin/rune

echo ""
echo "✓ Success! 'rune' command is installed."
echo "You can now open any Terminal and type: rune --help"
echo ""
read -p "Press [Enter] to exit..."
