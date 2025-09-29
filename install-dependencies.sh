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

# Function to install package with fallbacks
install_package() {
    local package="$1"
    shift
    local fallbacks=("$@")
    
    if sudo apt-get install -y "$package" 2>/dev/null; then
        echo "✅ Installed $package"
        return 0
    fi
    
    for fallback in "${fallbacks[@]}"; do
        if [ -n "$fallback" ] && sudo apt-get install -y "$fallback" 2>/dev/null; then
            echo "✅ Installed $fallback (fallback for $package)"
            return 0
        fi
    done
    
    echo "⚠️  Warning: Could not install $package or any fallbacks"
    return 1
}

# Core packages that should be available on most systems
sudo apt-get install -y \
    wget \
    curl \
    git \
    python3-pip \
    chromium-browser

# Install packages with fallbacks for different Ubuntu/Debian versions
install_package "libgtk-4-1" "libgtk-3-0"
install_package "libgraphene-1.0-0"
install_package "libwoff1" "libwoff2-1.0.2"
install_package "libvpx9" "libvpx7" "libvpx6"
install_package "libevent-2.1-7t64" "libevent-2.1-7" "libevent-2.1-6"
install_package "libopus0"
install_package "libgstreamer1.0-0"
install_package "libgstreamer-plugins-base1.0-0"
install_package "libgstreamer-plugins-bad1.0-0"
install_package "libflite1"
install_package "libwebpdemux2" "libwebp6"
install_package "libavif16" "libavif13" "libavif12"
install_package "libharfbuzz-icu0" "libharfbuzz0b"
install_package "libwebpmux3" "libwebpmux2"
install_package "libenchant-2-2" "libenchant-2-0"
install_package "libsecret-1-0"
install_package "libhyphen0"
install_package "libmanette-0.2-0"
install_package "libx264-164" "libx264-163" "libx264-160"
install_package "libgstreamer-gl1.0-0"
install_package "libnss3-dev" "libnss3"
install_package "libatk-bridge2.0-dev" "libatk-bridge2.0-0"
install_package "libdrm2"
install_package "libxkbcommon0"
install_package "libxcomposite1"
install_package "libxdamage1"
install_package "libxrandr2"
install_package "libgbm1"
install_package "libxss1"
install_package "libasound2t64" "libasound2" "libasound2-1.0.0"

# Install wafw00f
echo "🛡️ Installing wafw00f..."
sudo apt-get install -y wafw00f

# Install ParamsMap for parameter discovery
echo "🔍 Installing ParamsMap for parameter discovery..."
if command -v go &> /dev/null; then
    go install -v github.com/pyneda/paramsmap@latest
    echo "✅ ParamsMap installed via go install"
else
    echo "⚠️  Warning: Go not found, ParamsMap installation skipped"
    echo "   Install Go first, then run: go install -v github.com/pyneda/paramsmap@latest"
fi

# Download comprehensive parameter wordlist
echo "📋 Downloading comprehensive parameter wordlist..."
WORDLIST_DIR="/opt/xss-scanner"
WORDLIST_FILE="$WORDLIST_DIR/assetnote-parameters.txt"

# Create directory if it doesn't exist
sudo mkdir -p "$WORDLIST_DIR"

# Download the wordlist
if command -v wget &> /dev/null; then
    sudo wget -O "$WORDLIST_FILE" "https://wordlists-cdn.assetnote.io/data/automated/httparchive_parameters_top_1m_2025_09_27.txt"
elif command -v curl &> /dev/null; then
    sudo curl -o "$WORDLIST_FILE" "https://wordlists-cdn.assetnote.io/data/automated/httparchive_parameters_top_1m_2025_09_27.txt"
else
    echo "⚠️  Warning: Neither wget nor curl found, wordlist download skipped"
    echo "   Install wget or curl, then download manually:"
    echo "   wget -O $WORDLIST_FILE https://wordlists-cdn.assetnote.io/data/automated/httparchive_parameters_top_1m_2025_09_27.txt"
fi

# Check if download was successful
if [ -f "$WORDLIST_FILE" ]; then
    WORDLIST_COUNT=$(wc -l < "$WORDLIST_FILE")
    echo "✅ Assetnote parameter wordlist downloaded successfully"
    echo "   Location: $WORDLIST_FILE"
    echo "   Parameters: $WORDLIST_COUNT"
    echo "   This will be used as the default wordlist for parameter discovery"
    
    # Make it readable by all users
    sudo chmod 644 "$WORDLIST_FILE"
else
    echo "❌ Failed to download wordlist"
fi


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
if go run github.com/playwright-community/playwright-go/cmd/playwright@latest install; then
    echo "✅ Playwright browsers installed successfully"
else
    echo "⚠️  Playwright browser installation failed, trying alternative method..."
    # Try installing with system dependencies
    go run github.com/playwright-community/playwright-go/cmd/playwright@latest install --with-deps
fi

echo "✅ All dependencies installed successfully!"
echo "📋 Next steps:"
echo "   1. Build the scanner: go build -o xss-scanner ./cmd/xss-scanner"
echo "   2. Run the scanner: ./xss-scanner -help"
