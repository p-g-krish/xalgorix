#!/bin/bash
# Xalgorix Build Script

set -e

echo "Building Xalgorix..."

cd "$(dirname "$0")"

# Build with flags to avoid VCS errors
go build -ldflags "-s -w" -buildvcs=false -o xalgorix ./cmd/xalgorix/

echo "Build successful: xalgorix"

if [ "$1" = "--install" ] || [ "$1" = "-i" ]; then
    echo "Installing to /usr/local/bin..."
    sudo cp xalgorix /usr/local/bin/
    echo "Installed!"
fi
