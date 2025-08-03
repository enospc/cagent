#!/bin/bash

# Test script to validate AUR setup fixes
echo "========================================"
echo "AUR Setup Validation Test"
echo "========================================"

# Check if container directory exists
CONTAINER_PATH="$HOME/.config/cagent/container"
if [ ! -d "$CONTAINER_PATH" ]; then
    echo "❌ Container not found at $CONTAINER_PATH"
    exit 1
fi

echo "✓ Container found at $CONTAINER_PATH"

# Check sudoers configuration
SUDOERS_FILE="$CONTAINER_PATH/etc/sudoers.d/99-container-user"
if [ ! -f "$SUDOERS_FILE" ]; then
    echo "❌ Sudoers file not found: $SUDOERS_FILE"
    exit 1
fi

echo "✓ Sudoers file found"

# Check if the sudoers contains the new AUR-friendly rules
echo "Checking sudoers configuration..."

# Check for essential pacman permissions
if grep -q "pacman -S --noconfirm" "$SUDOERS_FILE"; then
    echo "✓ pacman -S --noconfirm permission found"
else
    echo "❌ Missing pacman -S --noconfirm permission"
fi

if grep -q "pacman -S --asdeps" "$SUDOERS_FILE"; then
    echo "✓ pacman -S --asdeps permission found (needed for makepkg)"
else
    echo "❌ Missing pacman -S --asdeps permission (needed for makepkg)"
fi

if grep -q "pacman -U" "$SUDOERS_FILE"; then
    echo "✓ pacman -U permission found (needed for installing built packages)"
else
    echo "❌ Missing pacman -U permission (needed for installing built packages)"
fi

# Check if Go is likely to be installed (look for go in the container)
if [ -f "$CONTAINER_PATH/usr/bin/go" ]; then
    echo "✓ Go compiler found in container"
else
    echo "⚠️  Go compiler not found (may need to be installed during AUR setup)"
fi

# Check if base-devel is likely installed
if [ -f "$CONTAINER_PATH/usr/bin/makepkg" ]; then
    echo "✓ makepkg found (base-devel package)"
else
    echo "❌ makepkg not found (base-devel package missing)"
fi

# Check if git is installed
if [ -f "$CONTAINER_PATH/usr/bin/git" ]; then
    echo "✓ git found"
else
    echo "❌ git not found (required for AUR)"
fi

echo "========================================"
echo "Test Summary:"
echo "This script checks if the container has the"
echo "necessary components for AUR package building."
echo ""
echo "Key requirements for AUR to work:"
echo "1. Proper sudoers configuration (checked above)"
echo "2. Go compiler (for building yay)"
echo "3. base-devel package (includes makepkg)"
echo "4. git (for cloning AUR repositories)"
echo "5. Network access during container setup"
echo "========================================"

# Display current sudoers content for manual verification
echo ""
echo "Current sudoers configuration:"
echo "-----------------------------"
cat "$SUDOERS_FILE" 2>/dev/null || echo "Could not read sudoers file"