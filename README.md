# XSS Scanner - Minimal Version

A XSS (Cross-Site Scripting) scanner built with Go and Playwright for headless browser automation.

## Features

- **Headless Browser Scanning**: Uses Playwright for comprehensive XSS detection
- **WAF Detection**: Integrates with wafw00f for Web Application Firewall detection
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
  -scan-file string
        File containing domains/subdomains or URLs to crawl and scan
  -o string
        Output file to save scan results
  -concurrency int
        Number of concurrent scans (default 5)
  -headless
        Run in headless mode
  -timeout duration
        Request timeout (default 2m)
  -crawl-only
        Only crawl domain and save URLs to file
  -help
        Show help information
```

## Examples

### Scan Google Firing Range
```bash
./xss-scanner -d "public-firing-range.appspot.com" -concurrency 3 -headless -o results.json
```

### Scan from domain/subdomain list
```bash
echo "example.com" > domains.txt
echo "subdomain.example.com" >> domains.txt
echo "test.com" >> domains.txt
./xss-scanner -scan-file domains.txt -concurrency 5 -headless -o results.json
```

### Scan from mixed URL/domain list
```bash
echo "example.com" > targets.txt
echo "https://specific-page.com" >> targets.txt
echo "subdomain.test.com" >> targets.txt
./xss-scanner -scan-file targets.txt -concurrency 5 -headless -o results.json
```

### Crawl only and save URLs
```bash
./xss-scanner -d "example.com" -crawl-only -o crawled_urls.txt
```

### Scan single URL and save results
```bash
./xss-scanner -url "https://example.com" -o single_scan.json
```

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


