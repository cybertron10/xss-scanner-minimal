#!/bin/bash

# XSS Scanner Build Script
# This script builds the XSS scanner for Linux

set -e  # Exit on any error

echo "🔨 Building XSS Scanner..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please run ./install-dependencies.sh first"
    exit 1
fi

# Download dependencies
echo "📦 Downloading Go dependencies..."
go mod download

# Build the scanner
echo "🔨 Building XSS scanner binary..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o xss-scanner ./cmd/xss-scanner

# Make executable
chmod +x xss-scanner

echo "✅ Build completed successfully!"
echo "📋 Binary created: ./xss-scanner"
echo "📋 Test the scanner: ./xss-scanner -help"
