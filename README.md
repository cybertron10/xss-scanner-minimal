# XSS Scanner - Minimal Version

A distributed XSS (Cross-Site Scripting) scanner built with Go and Playwright for headless browser automation.

## Features

- **Headless Browser Scanning**: Uses Playwright for comprehensive XSS detection
- **WAF Detection**: Integrates with wafw00f for Web Application Firewall detection
- **Distributed Scanning**: Designed for use with cloud fleets (Ax/Axiom)
- **Multiple Scan Modes**: URL scanning, domain crawling, and batch processing
- **Concurrent Processing**: Configurable concurrency for efficient scanning

## Quick Start

### 1. Install Dependencies

```bash
# Make scripts executable
chmod +x *.sh

# Install all dependencies
./install-dependencies.sh
```

### 2. Build the Scanner

```bash
# Build the scanner binary
./build.sh
```

### 3. Run the Scanner

```bash
# Test with a single URL
./xss-scanner -url "https://example.com" -headless

# Crawl and scan a domain
./xss-scanner -d "example.com" -concurrency 3 -headless

# Scan from a file of URLs
./xss-scanner -file urls.txt -concurrency 5 -headless
```

## Usage

```bash
./xss-scanner [OPTIONS]

Options:
  -url string
        Single URL to scan
  -d string
        Domain to crawl and scan
  -file string
        File containing URLs to scan
  -concurrency int
        Number of concurrent scans (default 3)
  -headless
        Run in headless mode
  -timeout int
        Request timeout in seconds (default 30)
  -output string
        Output file for results
  -help
        Show help information
```

## Examples

### Scan Google Firing Range
```bash
./xss-scanner -d "public-firing-range.appspot.com" -concurrency 3 -headless
```

### Scan from URL list
```bash
echo "https://example.com" > urls.txt
echo "https://test.com" >> urls.txt
./xss-scanner -file urls.txt -concurrency 5 -headless
```

## Fleet Deployment

For distributed scanning with Ax/Axiom:

1. Upload this directory to your fleet instances
2. Run `./install-dependencies.sh` on each instance
3. Run `./build.sh` on each instance
4. Execute scans across the fleet

## Dependencies

- **Go 1.22+**: For building the scanner
- **Playwright**: For headless browser automation
- **wafw00f**: For WAF detection
- **System libraries**: Various Linux libraries for browser support

## File Structure

```
xss-scanner-minimal/
├── cmd/xss-scanner/     # Main application code
├── internal/            # Internal packages
├── go.mod              # Go module file
├── go.sum              # Go dependencies
├── install-dependencies.sh  # Dependency installer
├── build.sh            # Build script
└── README.md           # This file
```

## License

This project is for educational and authorized security testing purposes only.