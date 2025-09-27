#!/bin/bash

# XSS Scanner Dependencies Installation Script
# This script installs all required dependencies for the XSS scanner

set -e  # Exit on any error

echo "🚀 Installing XSS Scanner dependencies..."

# Update package list
echo "📦 Updating package list..."
sudo apt-get update

# Install system dependencies for Playwright
echo "🔧 Installing Playwright dependencies..."
sudo apt-get install -y \
    libgtk-4-1 \
    libgraphene-1.0-0 \
    libwoff1 \
    libvpx9 \
    libevent-2.1-7t64 \
    libopus0 \
    libgstreamer1.0-0 \
    libgstreamer-plugins-base1.0-0 \
    libgstreamer-plugins-bad1.0-0 \
    libflite1 \
    libwebpdemux2 \
    libavif16 \
    libharfbuzz-icu0 \
    libwebpmux3 \
    libenchant-2-2 \
    libsecret-1-0 \
    libhyphen0 \
    libmanette-0.2-0 \
    libx264-164 \
    libgstreamer-gl1.0-0 \
    libnss3-dev \
    libatk-bridge2.0-dev \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libxss1 \
    libasound2t64 \
    chromium-browser \
    wget \
    curl \
    git \
    python3-pip

# Install wafw00f
echo "🛡️ Installing wafw00f..."
sudo apt-get install -y wafw00f

# Install Go (if not already installed)
if ! command -v go &> /dev/null; then
    echo "🔧 Installing Go..."
    wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    source ~/.bashrc
    rm go1.22.3.linux-amd64.tar.gz
fi

# Install Playwright browsers
echo "🌐 Installing Playwright browsers..."
go run github.com/playwright-community/playwright-go/cmd/playwright@latest install

echo "✅ All dependencies installed successfully!"
echo "📋 Next steps:"
echo "   1. Build the scanner: go build -o xss-scanner ./cmd/xss-scanner"
echo "   2. Run the scanner: ./xss-scanner -help"
