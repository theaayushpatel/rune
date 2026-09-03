#!/usr/bin/env bash
set -e

echo "Installing Rune (Desktop & CLI)..."

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
DESKTOP_DIR="${DESKTOP_DIR:-/usr/local/share/applications}"
ICON_DIR="${ICON_DIR:-/usr/local/share/icons/hicolor/512x512/apps}"

if [ ! -w "$INSTALL_DIR" ]; then
    SUDO="sudo"
else
    SUDO=""
fi

$SUDO mkdir -p "$INSTALL_DIR"
$SUDO mkdir -p "$DESKTOP_DIR"
$SUDO mkdir -p "$ICON_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check binaries exist in current directory or target/release
if [ -f "$SCRIPT_DIR/rune-desktop" ]; then
    BIN_DIR="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/../target/release/rune-desktop" ]; then
    BIN_DIR="$SCRIPT_DIR/../target/release"
else
    BIN_DIR="."
fi

# Install Desktop and CLI binaries
$SUDO cp "$BIN_DIR/rune-desktop" "$INSTALL_DIR/rune-desktop"
$SUDO chmod 755 "$INSTALL_DIR/rune-desktop"

$SUDO cp "$BIN_DIR/rune" "$INSTALL_DIR/rune"
$SUDO chmod 755 "$INSTALL_DIR/rune"

# Install Desktop Entry & Icon
if [ -f "$SCRIPT_DIR/../assets/rune.desktop" ]; then
    $SUDO cp "$SCRIPT_DIR/../assets/rune.desktop" "$DESKTOP_DIR/rune.desktop"
elif [ -f "$SCRIPT_DIR/rune.desktop" ]; then
    $SUDO cp "$SCRIPT_DIR/rune.desktop" "$DESKTOP_DIR/rune.desktop"
fi

if [ -f "$SCRIPT_DIR/../assets/rune.png" ]; then
    $SUDO cp "$SCRIPT_DIR/../assets/rune.png" "$ICON_DIR/rune.png"
elif [ -f "$SCRIPT_DIR/rune.png" ]; then
    $SUDO cp "$SCRIPT_DIR/rune.png" "$ICON_DIR/rune.png"
fi

which update-desktop-database >/dev/null 2>&1 && $SUDO update-desktop-database "$DESKTOP_DIR" || true
which gtk-update-icon-cache >/dev/null 2>&1 && $SUDO gtk-update-icon-cache -f -t "/usr/local/share/icons/hicolor" || true

echo "✓ Rune installed successfully!"
echo "  • GUI App: Available in your application launcher ('Rune')"
echo "  • CLI Tool: Run 'rune --help' from any terminal"
