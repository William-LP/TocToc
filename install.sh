#!/bin/bash

set -e

BINARY_URL="https://github.com/William-LP/TocToc/releases/download/main/toctoc"
BINARY_NAME="toctoc"
INSTALL_PATH="/usr/local/bin/$BINARY_NAME"

echo "Downloading $BINARY_NAME from GitHub..."
curl -L "$BINARY_URL" -o "$BINARY_NAME"

echo "Making it executable..."
chmod +x "$BINARY_NAME"

echo "Moving to $INSTALL_PATH..."
sudo mv "$BINARY_NAME" "$INSTALL_PATH"

echo "Running '$BINARY_NAME install'..."
sudo "$INSTALL_PATH" install

