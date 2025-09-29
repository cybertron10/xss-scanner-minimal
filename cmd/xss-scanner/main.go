package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"xss-scanner/internal/crawler"
	"xss-scanner/internal/scanner"
)

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	var (
		scanURL      = flag.String("url", "", "URL to scan for XSS vulnerabilities")
		scanDomain   = flag.String("d", "", "Domain to scan for XSS vulnerabilities")
		crawlOnly    = flag.Bool("crawl-only", false, "Only crawl domain and save URLs to file")
		// New: explicit scan-only mode for lists of URLs (used with -scan-file)
		scanOnly     = flag.Bool("scan", false, "Only scan URLs; skip crawling (use with -scan-file)")
        // New alias flag per user request: crawl only and write to urls.txt
        crawl        = flag.Bool("crawl", false, "Crawl only; write URLs to urls.txt and exit (no XSS scan)")
		scanFile     = flag.String("scan-file", "", "File containing URLs to scan for XSS")
		outputFile   = flag.String("o", "", "Output file to save scan results")
		concurrency  = flag.Int("concurrency", 5, "Number of concurrent scans (1-20, default: 5)")
		headersFile = flag.String("headers-file", "", "File containing HTTP headers in JSON format")
		quiet       = flag.Bool("quiet", false, "Suppress verbose output")
		headless    = flag.Bool("headless", true, "Use headless browser for testing")
		fastMode    = flag.Bool("fast-mode", false, "Enable fast mode with limited payloads")
		ultraFast   = flag.Bool("ultra-fast", false, "Enable ultra-fast mode (skip character analysis entirely)")
		timeout     = flag.Duration("timeout", 2*time.Minute, "Scan timeout")
		server      = flag.Bool("server", false, "Run as HTTP server for Burp Suite extension")
		port        = flag.String("port", "8081", "Server port (default: 8081)")
	)
	flag.Parse()

	// Validate concurrency flag
	if *concurrency < 1 || *concurrency > 20 {
		log.Fatal("Concurrency must be between 1 and 20")
	}

	// Silence all log output when quiet is enabled
	if *quiet {
		log.SetOutput(io.Discard)
	}

	// Check if running in server mode
	if *server {
		if *quiet { log.SetOutput(io.Discard) }
		runServer(*port, *quiet, *headless, *fastMode, *ultraFast, *timeout)
		return
	}

	// Check if domain scanning is requested
    if *scanDomain != "" {
		if *quiet { log.SetOutput(io.Discard) }
		
        if *crawlOnly || *crawl {
			// Only crawl domain and save URLs to file
			runDomainCrawlOnly(*scanDomain, *outputFile)
		} else {
			// Full domain scan (crawl + scan)
			runDomainScan(*scanDomain, *concurrency, *quiet, *headless, *fastMode, *ultraFast, *timeout, *outputFile)
		}
		return
	}

    if *scanFile != "" {
        if *quiet { log.SetOutput(io.Discard) }
        // Explicit behavior: with -crawl treat items as domains and crawl; with -scan treat items as URLs and scan
        if *crawlOnly || *crawl {
            runFileCrawlOnly(*scanFile, *outputFile)
        } else if *scanOnly {
            runScanFromFile(*scanFile, *concurrency, *quiet, *headless, *fastMode, *ultraFast, *timeout, *outputFile)
        } else {
            log.Fatal("With -scan-file, specify either -crawl (domains -> crawl to URLs) or -scan (URLs -> scan directly)")
        }
        return
    }

	if *scanURL == "" {
		log.Fatal("URL is required. Use -url flag or -d for domain scanning")
	}

	// Read headers from file if provided
	var headers map[string]string
	if *headersFile != "" {
		headersData, err := os.ReadFile(*headersFile)
		if err != nil {
			log.Fatalf("Failed to read headers file: %v", err)
		}
		if err := json.Unmarshal(headersData, &headers); err != nil {
			log.Fatalf("Failed to parse headers JSON: %v", err)
		}
	}

	// WAF detection for command-line mode
	var wafDetected bool
	var wafName string
	parsedURL, err := url.Parse(*scanURL)
	if err == nil {
		wafDetected, wafName = runWAFW00F(parsedURL.Host)
		if !*quiet {
			if wafDetected {
				log.Printf("WAF detected for %s: %s", parsedURL.Host, wafName)
			} else {
				log.Printf("No WAF detected for %s", parsedURL.Host)
			}
		}
	}

	// Create scanner configuration
	config := &scanner.Config{
		URL:              *scanURL,
		Headers:          headers,
		Quiet:            *quiet,
		Headless:         *headless,
		FastMode:         *fastMode,
		UltraFast:        *ultraFast,
		Timeout:          *timeout,
		WAFDetected:      wafDetected,
		WAFName:          wafName,
	}

	// Create scanner instance
	scanner := scanner.NewScanner(config)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Run the scan
	result, err := scanner.Scan(ctx)
	if err != nil {
		if !*quiet {
			log.Printf("Scan error: %v", err)
		}
		os.Exit(1)
	}

	// Output result as JSON
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal result: %v", err)
	}

	// Save to file if output file is specified
	if *outputFile != "" {
		err = os.WriteFile(*outputFile, output, 0644)
		if err != nil {
			log.Fatalf("Failed to write output file: %v", err)
		}
		if !*quiet {
			log.Printf("Results saved to: %s", *outputFile)
		}
	} else {
		// Print to stdout if no output file specified
		fmt.Println(string(output))
	}
}

// Global variables to store scan results and status
var (
	scanResults = make(map[string]interface{})
	scanStatus  = make(map[string]string)
	scanQueue   = make(chan scanRequest, 100) // Queue for concurrent scanning
	scanMutex   sync.Mutex                   // Mutex to protect shared data
    wafCache   = make(map[string]struct{Detected bool; Name string})
	
	// Concurrent scanning configuration
	maxConcurrentScans = 20 // Maximum number of concurrent scans
	activeScans        = 0  // Current number of active scans
	scanSemaphore      = make(chan struct{}, maxConcurrentScans) // Semaphore for limiting concurrent scans
	
	// Sequential scanning for proxy requests
	sequentialQueue = make(chan scanRequest, 50) // Separate queue for sequential processing
	
	// File-based result streaming
	resultsFiles = make(map[string]string) // scanID -> results file path
	resultsMutex = sync.RWMutex{}          // Mutex for results files access
	
	// Global variables for domain crawling
	crawlStatuses = make(map[string]*CrawlStatus) // scanID -> status
	crawlMutex    = sync.RWMutex{}                // Mutex for crawl status access
)

// CrawlStatus represents the status of a domain crawl
type CrawlStatus struct {
	ScanID         string    `json:"scan_id"`
	Domain         string    `json:"domain"`
	Status         string    `json:"status"` // "crawling", "scanning", "completed"
	DiscoveredURLs []string  `json:"discovered_urls"`
	ScannedURLs    []string  `json:"scanned_urls"`
	StartTime      time.Time `json:"start_time"`
	EndTime        *time.Time `json:"end_time,omitempty"`
}

// scanRequest represents a scan request in the queue
type scanRequest struct {
	URL      string
	Headers  map[string]string
	Config   *scanner.Config
	ScanType string // "proxy", "domain", "authenticated"
	ScanID   string // Unique identifier for this scan session
}

// processScanQueue processes scan requests with different strategies based on scan type
func processScanQueue(quiet bool) {
	// Start concurrent workers for domain and authenticated scans
	for i := 0; i < maxConcurrentScans; i++ {
		go scanWorker(i, scanQueue, quiet, true) // true = concurrent
	}
	
	// Start single sequential worker for proxy scans
	go scanWorker(0, sequentialQueue, quiet, false) // false = sequential
}

func scanWorker(workerID int, queue chan scanRequest, quiet bool, concurrent bool) {
	for req := range queue {
		if concurrent {
			// Acquire semaphore to limit concurrent scans
			scanSemaphore <- struct{}{}
		}
		
		// Process each scan in its own scope to ensure proper cleanup
		func() {
			if concurrent {
				defer func() { <-scanSemaphore }() // Release semaphore when done
			}
			
			// Update active scan count
			scanMutex.Lock()
			activeScans++
			currentActive := activeScans
			scanMutex.Unlock()
			
			if !quiet {
				mode := "concurrent"
				if !concurrent {
					mode = "sequential"
				}
				log.Printf("Worker %d (%s): Starting scan for %s (Active scans: %d)", workerID, mode, req.URL, currentActive)
			}
			
			// Debug: Log the URL being processed
			
			// Set the URL in the config
			req.Config.URL = req.URL
			
			// Debug: Log the config URL
			
			// Create scanner instance
			scannerInstance := scanner.NewScanner(req.Config)
			defer scannerInstance.Close()

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), req.Config.Timeout)
			defer cancel()

			// Run the scan
			result, err := scannerInstance.Scan(ctx)
			
			// Update status and results with mutex protection
			scanMutex.Lock()
			if err != nil {
				scanStatus[req.URL] = "error"
				if !quiet {
					log.Printf("Worker %d: Scan failed for %s: %v", workerID, req.URL, err)
				}
			} else {
				scanStatus[req.URL] = "completed"
				
				// Store results in memory for /results endpoint
				scanResults[req.URL] = result
				
				// Only write vulnerabilities to file for domain/authenticated scans
				if req.ScanType == "domain" || req.ScanType == "authenticated" {
					for _, vuln := range result.Vulnerabilities {
						vulnMap := map[string]interface{}{
							"exploit_url":     vuln.ExploitURL,
							"parameter":       vuln.Parameter,
							"context":         vuln.Context,
							"working_payloads": vuln.WorkingPayloads,
						}
						writeVulnerabilityToFile(req.ScanID, req.URL, vulnMap)
					}
				}
				
				if !quiet {
					log.Printf("Worker %d: Scan completed for %s", workerID, req.URL)
				}
			}
			activeScans--
			scanMutex.Unlock()
		}()
	}
}

// writeVulnerabilityToFile writes a vulnerability to the results file with proper locking
func writeVulnerabilityToFile(scanID, url string, vuln map[string]interface{}) {
	resultsMutex.Lock()
	defer resultsMutex.Unlock()
	
	resultsFile, exists := resultsFiles[scanID]
	if !exists {
		// Create new results file for this scan
		resultsFile = fmt.Sprintf("scan_results_%s.json", scanID)
		resultsFiles[scanID] = resultsFile
		
		// Initialize file with empty content
		os.WriteFile(resultsFile, []byte(""), 0644)
	}
	
	// Use atomic file operations to prevent race conditions
	tempFile := resultsFile + ".tmp"
	
	// Read existing results
	data, err := os.ReadFile(resultsFile)
	if err != nil {
		log.Printf("Error reading results file: %v", err)
		return
	}
	
	var vulnerabilities []interface{}
	if len(data) > 0 {
		// Parse existing URLs (one per line)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				vulnerabilities = append(vulnerabilities, line)
			}
		}
	}
	
	// Add URL and timestamp to vulnerability
	vuln["url"] = url
	vuln["timestamp"] = time.Now().Format("2006-01-02 15:04:05")
	
	// Check for duplicates before adding (based on exploit URL only)
	exploitURL := vuln["exploit_url"].(string)
	
	// Check if this exploit URL already exists
	duplicate := false
	for _, existingVuln := range vulnerabilities {
		existingExploitURL := existingVuln.(string)
		
		if existingExploitURL == exploitURL {
			duplicate = true
			break
		}
	}
	
	// Only add if not duplicate
	if !duplicate {
		// Add just the exploit URL as a string
		vulnerabilities = append(vulnerabilities, vuln["exploit_url"])
		log.Printf("Added new vulnerability: %s", vuln["exploit_url"])
	} else {
		log.Printf("Skipped duplicate vulnerability: %s", vuln["exploit_url"])
	}
	
	// Write to temporary file first (one URL per line)
	var lines []string
	for _, vuln := range vulnerabilities {
		lines = append(lines, vuln.(string))
	}
	newData := []byte(strings.Join(lines, "\n") + "\n")
	
	if err := os.WriteFile(tempFile, newData, 0644); err != nil {
		log.Printf("Error writing temporary file: %v", err)
		return
	}
	
	// Atomic rename to prevent race conditions
	if err := os.Rename(tempFile, resultsFile); err != nil {
		log.Printf("Error renaming temporary file: %v", err)
		os.Remove(tempFile) // Clean up temp file
		return
	}
	
	log.Printf("Successfully wrote vulnerability for %s to results file", url)
}

// cleanupAllResultsFiles removes all existing results files (called before new scan starts)
func cleanupAllResultsFiles() {
	resultsMutex.Lock()
	defer resultsMutex.Unlock()
	
	// Clean up files tracked in memory
	for scanID, resultsFile := range resultsFiles {
		if err := os.Remove(resultsFile); err == nil {
			log.Printf("Removed tracked results file: %s", resultsFile)
		}
		delete(resultsFiles, scanID)
	}
	
	// Also clean up any orphaned scan results files on disk
	files, err := filepath.Glob("scan_results_*.json")
	if err == nil {
		for _, file := range files {
			if err := os.Remove(file); err == nil {
				log.Printf("Removed orphaned results file: %s", file)
			}
		}
	}
	
	// Clean up any temporary files
	tempFiles, err := filepath.Glob("scan_results_*.json.tmp")
	if err == nil {
		for _, file := range tempFiles {
			if err := os.Remove(file); err == nil {
				log.Printf("Removed temporary results file: %s", file)
			}
		}
	}
}

// startDomainCrawling starts the domain crawling process
// cleanupCrawledFiles removes old crawled URL files
func cleanupCrawledFiles() {
	// Remove old crawled URL files
	files, err := filepath.Glob("crawled_urls_*.txt")
	if err == nil {
		for _, file := range files {
			os.Remove(file)
			log.Printf("Removed old crawled file: %s", file)
		}
	}
}

func startDomainCrawling(domain, scanID string) {
	log.Printf("Starting domain crawl for: %s (scan_id: %s)", domain, scanID)
	
	// Clean up old crawled URL files
	cleanupCrawledFiles()
	
	crawlMutex.Lock()
	crawlStatuses[scanID] = &CrawlStatus{
		ScanID:         scanID,
		Domain:         domain,
		Status:         "crawling",
		DiscoveredURLs: []string{},
		ScannedURLs:    []string{},
		StartTime:      time.Now(),
	}
	crawlMutex.Unlock()

	// Clean domain name
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		domain = strings.Split(domain, "://")[1]
	}
	if strings.HasPrefix(domain, "www.") {
		domain = domain[4:]
	}
	if strings.HasSuffix(domain, "/") && !strings.Contains(domain[1:], "/") {
		domain = domain[:len(domain)-1]
	}

	// Determine base URL
	baseURL := "https://" + domain
	if !strings.Contains(domain, "/") {
		baseURL += "/"
	}

	// Crawl the domain
	discoveredURLs := crawlDomain(baseURL, scanID)
	
	// Update status to scanning
	crawlMutex.Lock()
	if status, exists := crawlStatuses[scanID]; exists {
		status.Status = "scanning"
		status.DiscoveredURLs = discoveredURLs
	}
	crawlMutex.Unlock()

	log.Printf("Crawling completed. Found %d URLs. Starting XSS scanning...", len(discoveredURLs))

	// Start concurrent XSS scanning
	startConcurrentScanning(discoveredURLs, scanID)

	// Wait for all URLs to be scanned before marking as completed
	log.Printf("Waiting for XSS scanning to complete...")
	timeoutChan := time.After(30 * time.Minute) // 30 minute timeout
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-timeoutChan:
			log.Printf("Scan timeout reached (30 minutes). Stopping scan.")
			scanMutex.Lock()
			done := 0
			completed := 0
			for _, url := range discoveredURLs {
				if status, exists := scanStatus[url]; exists {
					if status == "completed" || status == "error" {
						done++
					}
					if status == "completed" {
						completed++
					}
				}
			}
			scanMutex.Unlock()
			log.Printf("Domain scan timed out: %d completed, %d failed, %d pending", completed, done-completed, len(discoveredURLs)-done)
			break
			
		case <-ticker.C:
			// Check if all URLs have been scanned
			scanMutex.Lock()
			allScanned := true
			done := 0
			completed := 0
			for _, url := range discoveredURLs {
				if status, exists := scanStatus[url]; exists {
					if status == "completed" || status == "error" {
						done++
					}
					if status == "completed" {
						completed++
					}
					if status != "completed" {
						allScanned = false
					}
				} else {
					allScanned = false
				}
			}
			scanMutex.Unlock()
			
			if allScanned {
				log.Printf("All URLs have been scanned successfully")
				break
			}
			
			// Update scanned URLs count
			crawlMutex.Lock()
			if status, exists := crawlStatuses[scanID]; exists {
				status.ScannedURLs = discoveredURLs[:completed]
			}
			crawlMutex.Unlock()
			
			log.Printf("Scanning in progress... (%d/%d URLs completed)", completed, len(discoveredURLs))
		}
	}

	// Mark as completed
	crawlMutex.Lock()
	if status, exists := crawlStatuses[scanID]; exists {
		status.Status = "completed"
		status.ScannedURLs = discoveredURLs // All URLs have been scanned
		now := time.Now()
		status.EndTime = &now
	}
	crawlMutex.Unlock()

	log.Printf("Domain scan completed for: %s", domain)
}

func startDomainCrawlingWithConcurrency(domain, scanID string, concurrency int) {
	log.Printf("Starting domain crawl for: %s (scan_id: %s, concurrency: %d)", domain, scanID, concurrency)
	
	// Clean up old crawled URL files
	cleanupCrawledFiles()
	
	crawlMutex.Lock()
	crawlStatuses[scanID] = &CrawlStatus{
		ScanID:         scanID,
		Domain:         domain,
		Status:         "crawling",
		DiscoveredURLs: []string{},
		ScannedURLs:    []string{},
		StartTime:      time.Now(),
	}
	crawlMutex.Unlock()

	// Clean domain name
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		domain = strings.Split(domain, "://")[1]
	}
	if strings.HasPrefix(domain, "www.") {
		domain = domain[4:]
	}
	if strings.HasSuffix(domain, "/") && !strings.Contains(domain[1:], "/") {
		domain = domain[:len(domain)-1]
	}

	// Determine base URL
	baseURL := "https://" + domain
	if !strings.Contains(domain, "/") {
		baseURL += "/"
	}

	// Crawl the domain
	discoveredURLs := crawlDomain(baseURL, scanID)
	
	// Update status to scanning
	crawlMutex.Lock()
	if status, exists := crawlStatuses[scanID]; exists {
		status.Status = "scanning"
		status.DiscoveredURLs = discoveredURLs
	}
	crawlMutex.Unlock()

	log.Printf("Crawling completed. Found %d URLs. Starting XSS scanning with concurrency %d...", len(discoveredURLs), concurrency)

	// Start concurrent XSS scanning with specified concurrency
	startConcurrentScanningWithConcurrency(discoveredURLs, scanID, concurrency)

	// Wait for all URLs to be scanned before marking as completed
	log.Printf("Waiting for XSS scanning to complete...")
	timeoutChan := time.After(30 * time.Minute) // 30 minute timeout
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-timeoutChan:
			log.Printf("Scan timeout reached (30 minutes). Stopping scan.")
			scanMutex.Lock()
			done := 0
			completed := 0
			for _, url := range discoveredURLs {
				if status, exists := scanStatus[url]; exists {
					if status == "completed" || status == "error" {
						done++
					}
					if status == "completed" {
						completed++
					}
				}
			}
			scanMutex.Unlock()
			log.Printf("Domain scan timed out: %d completed, %d failed, %d pending", completed, done-completed, len(discoveredURLs)-done)
			break
			
		case <-ticker.C:
			// Check if all URLs have been scanned
			scanMutex.Lock()
			allScanned := true
			done := 0
			completed := 0
			for _, url := range discoveredURLs {
				if status, exists := scanStatus[url]; exists {
					if status == "completed" || status == "error" {
						done++
					}
					if status == "completed" {
						completed++
					}
					if status != "completed" {
						allScanned = false
					}
				} else {
					allScanned = false
				}
			}
			scanMutex.Unlock()
			
			if allScanned {
				log.Printf("All URLs have been scanned successfully")
				break
			}
			
			// Update scanned URLs count
			crawlMutex.Lock()
			if status, exists := crawlStatuses[scanID]; exists {
				status.ScannedURLs = discoveredURLs[:completed]
			}
			crawlMutex.Unlock()
			
			log.Printf("Scanning in progress... (%d/%d URLs completed)", completed, len(discoveredURLs))
		}
	}

	// Mark as completed
	crawlMutex.Lock()
	if status, exists := crawlStatuses[scanID]; exists {
		status.Status = "completed"
		status.ScannedURLs = discoveredURLs // All URLs have been scanned
		now := time.Now()
		status.EndTime = &now
	}
	crawlMutex.Unlock()

	log.Printf("Domain scan completed for: %s", domain)
}

func startAuthenticatedScanning(scanID string, concurrency int) {
	log.Printf("Starting authenticated scan (scan_id: %s, concurrency: %d)", scanID, concurrency)
	
	// For now, this is a placeholder implementation
	// In a real implementation, this would:
	// 1. Read URLs from Burp's proxy history
	// 2. Extract authentication headers/cookies
	// 3. Scan each URL with authentication
	
	crawlMutex.Lock()
	crawlStatuses[scanID] = &CrawlStatus{
		ScanID:         scanID,
		Domain:         "authenticated_scan",
		Status:         "scanning",
		DiscoveredURLs: []string{},
		ScannedURLs:    []string{},
		StartTime:      time.Now(),
	}
	crawlMutex.Unlock()
	
	// For demonstration, we'll scan a few test URLs
	testURLs := []string{
		"https://public-firing-range.appspot.com/reflected/parameter/body/401",
		"https://public-firing-range.appspot.com/reflected/parameter/query/401",
		"https://public-firing-range.appspot.com/reflected/parameter/header/401",
	}
	
	log.Printf("Starting authenticated scan with %d test URLs", len(testURLs))
	
	// Update status with discovered URLs
	crawlMutex.Lock()
	if status, exists := crawlStatuses[scanID]; exists {
		status.DiscoveredURLs = testURLs
	}
	crawlMutex.Unlock()
	
	// Start concurrent XSS scanning with specified concurrency
	startConcurrentScanningWithConcurrency(testURLs, scanID, concurrency)
	
	// Wait for all URLs to be scanned before marking as completed
	log.Printf("Waiting for authenticated scan to complete...")
	for {
		time.Sleep(2 * time.Second)
		
		// Check if all URLs have been scanned
		scanMutex.Lock()
		allScanned := true
		for _, url := range testURLs {
			if status, exists := scanStatus[url]; !exists || status != "completed" {
				allScanned = false
				break
			}
		}
		scanMutex.Unlock()
		
		if allScanned {
			log.Printf("All URLs have been scanned successfully")
			break
		}
		
		// Update scanned URLs count
		crawlMutex.Lock()
		if status, exists := crawlStatuses[scanID]; exists {
			scannedCount := 0
			for _, url := range testURLs {
				if scanStatus[url] == "completed" {
					scannedCount++
				}
			}
			status.ScannedURLs = testURLs[:scannedCount]
		}
		crawlMutex.Unlock()
		
		log.Printf("Authenticated scan in progress... (%d/%d URLs completed)", 
			len(crawlStatuses[scanID].ScannedURLs), len(testURLs))
	}

	// Mark as completed
	crawlMutex.Lock()
	if status, exists := crawlStatuses[scanID]; exists {
		status.Status = "completed"
		status.ScannedURLs = testURLs // All URLs have been scanned
		now := time.Now()
		status.EndTime = &now
	}
	crawlMutex.Unlock()

	log.Printf("Authenticated scan completed")
}

// crawlDomain crawls the domain and returns discovered URLs
func crawlDomain(baseURL, scanID string) []string {
	log.Printf("Starting crawl for: %s", baseURL)
	
	// Create a new crawler instance
	c := crawler.NewCrawler()
	
	// Crawl the domain
	crawlResult, err := c.CrawlDomain(baseURL, map[string]string{})
	if err != nil {
		log.Printf("Crawl error for %s: %v", baseURL, err)
		return []string{}
	}

	log.Printf("Crawler found %d total URLs", len(crawlResult.URLs))

	// Save all discovered URLs to a file for debugging
	crawledURLsFile := fmt.Sprintf("crawled_urls_%s.txt", scanID)
	file, err := os.Create(crawledURLsFile)
	if err != nil {
		log.Printf("Error creating crawled URLs file: %v", err)
	} else {
		defer file.Close()
		file.WriteString(fmt.Sprintf("Crawled URLs for %s (scan_id: %s)\n", baseURL, scanID))
		file.WriteString(fmt.Sprintf("Total URLs found: %d\n\n", len(crawlResult.URLs)))
		
		for i, url := range crawlResult.URLs {
			file.WriteString(fmt.Sprintf("%d. %s\n", i+1, url))
		}
		log.Printf("Saved %d crawled URLs to: %s", len(crawlResult.URLs), crawledURLsFile)
	}

	log.Printf("Returning all %d crawled URLs for XSS testing", len(crawlResult.URLs))
	return crawlResult.URLs
}

// startConcurrentScanning starts concurrent XSS scanning for discovered URLs
func startConcurrentScanning(urls []string, scanID string) {
	log.Printf("Starting scanning of %d URLs with concurrency: %d", len(urls), maxConcurrentScans)
	
	if maxConcurrentScans == 1 {
		// Sequential scanning - one URL at a time
		log.Printf("Using sequential scanning (concurrency=1)")
		for i, url := range urls {
			log.Printf("Scanning URL %d/%d: %s", i+1, len(urls), url)
			
			// Submit each URL for sequential scanning
			scanReq := scanRequest{
				URL:      url,
				Headers:  map[string]string{},
				Config:   &scanner.Config{
					Quiet:     false, // Enable verbose logging for domain scans
					Headless:  true,  // Enable headless browser
					FastMode:  false, // Disable fast mode for thorough scanning
					UltraFast: false, // Disable ultra-fast mode
					Timeout:   2 * time.Minute, // Set reasonable timeout
				},
				ScanType: "domain",
				ScanID:   scanID,
			}
			
			// Add to sequential queue
			select {
			case sequentialQueue <- scanReq:
				log.Printf("Queued URL for sequential scanning: %s", url)
			default:
				log.Printf("Sequential queue full, skipping URL: %s", url)
			}
		}
	} else {
		// Concurrent scanning
		log.Printf("Using concurrent scanning (concurrency=%d)", maxConcurrentScans)
		for _, url := range urls {
			// Debug: Log each URL being processed
			
			// Submit each URL for scanning
			scanReq := scanRequest{
				URL:      url,
				Headers:  map[string]string{},
				Config:   &scanner.Config{
					Quiet:     false, // Enable verbose logging for domain scans
					Headless:  true,  // Enable headless browser
					FastMode:  false, // Disable fast mode for thorough scanning
					UltraFast: false, // Disable ultra-fast mode
					Timeout:   2 * time.Minute, // Set reasonable timeout
				},
				ScanType: "domain",
				ScanID:   scanID,
			}
			
			// Add to concurrent queue
			select {
			case scanQueue <- scanReq:
				log.Printf("Queued URL for concurrent scanning: %s", url)
			default:
				log.Printf("Concurrent queue full, skipping URL: %s", url)
			}
		}
	}
}

func startConcurrentScanningWithConcurrency(urls []string, scanID string, concurrency int) {
	log.Printf("Starting scanning of %d URLs with concurrency: %d", len(urls), concurrency)
	
	if concurrency == 1 {
		// Sequential scanning - one URL at a time
		log.Printf("Using sequential scanning (concurrency=1)")
		for i, url := range urls {
			log.Printf("Scanning URL %d/%d: %s", i+1, len(urls), url)
			
			// Submit each URL for sequential scanning
			scanReq := scanRequest{
				URL:      url,
				Headers:  map[string]string{},
				Config:   &scanner.Config{
					Quiet:     false, // Enable verbose logging for domain scans
					Headless:  true,  // Enable headless browser
					FastMode:  false, // Disable fast mode for thorough scanning
					UltraFast: false, // Disable ultra-fast mode
					Timeout:   2 * time.Minute, // Set reasonable timeout
				},
				ScanType: "domain",
				ScanID:   scanID,
			}
			
			// Add to sequential queue
			select {
			case sequentialQueue <- scanReq:
				log.Printf("Queued URL for sequential scanning: %s", url)
			default:
				log.Printf("Sequential queue full, skipping URL: %s", url)
			}
		}
	} else {
		// Concurrent scanning with specified concurrency
		log.Printf("Using concurrent scanning with %d workers", concurrency)
		
		// Queue all URLs synchronously to avoid race conditions
		for i, url := range urls {
			log.Printf("Queuing URL %d/%d: %s", i+1, len(urls), url)
			
			// Submit each URL for concurrent scanning
			scanReq := scanRequest{
				URL:      url,
				Headers:  map[string]string{},
				Config:   &scanner.Config{
					Quiet:     false, // Enable verbose logging for domain scans
					Headless:  true,  // Enable headless browser
					FastMode:  false, // Disable fast mode for thorough scanning
					UltraFast: false, // Disable ultra-fast mode
					Timeout:   2 * time.Minute, // Set reasonable timeout
				},
				ScanType: "domain",
				ScanID:   scanID,
			}
			
			// Add to concurrent queue synchronously (blocking)
			scanQueue <- scanReq
			log.Printf("Queued URL for concurrent scanning: %s", url)
		}
	}
}

// getCrawlStatus returns the current crawl status
func getCrawlStatus(scanID string) map[string]interface{} {
	crawlMutex.RLock()
	defer crawlMutex.RUnlock()
	
	if status, exists := crawlStatuses[scanID]; exists {
		return map[string]interface{}{
			"scan_id":         status.ScanID,
			"domain":          status.Domain,
			"status":          status.Status,
			"discovered_urls": status.DiscoveredURLs,
			"scanned_urls":    status.ScannedURLs,
			"start_time":      status.StartTime,
			"end_time":        status.EndTime,
		}
	}
	
	return map[string]interface{}{
		"error": "Scan ID not found",
	}
}

// getScanResults returns the scan results for a given scan ID
func getScanResults(scanID string) map[string]interface{} {
	resultsMutex.RLock()
	defer resultsMutex.RUnlock()
	
	if resultsFile, exists := resultsFiles[scanID]; exists {
		data, err := os.ReadFile(resultsFile)
		if err != nil {
			return map[string]interface{}{
				"error": "Error reading results file",
			}
		}
		
		var vulnerabilities []map[string]interface{}
		if err := json.Unmarshal(data, &vulnerabilities); err != nil {
			return map[string]interface{}{
				"error": "Error parsing results file",
			}
		}
		
		return map[string]interface{}{
			"scan_id":       scanID,
			"vulnerabilities": vulnerabilities,
		}
	}
	
	return map[string]interface{}{
		"scan_id":       scanID,
		"vulnerabilities": []interface{}{},
	}
}

// runDomainScan runs domain scanning from command line
// runDomainCrawlOnly only crawls a domain and saves URLs to file
func runDomainCrawlOnly(domain string, outputFile string) {
	log.Printf("Starting domain crawl only for: %s", domain)
	
	// Generate scan ID
	scanID := "crawl_only_" + strconv.FormatInt(time.Now().Unix(), 10)
	
	// Clean up old crawled URL files
	cleanupCrawledFiles()
	
	// Clean domain name
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		domain = strings.Split(domain, "://")[1]
	}
	if strings.HasPrefix(domain, "www.") {
		domain = domain[4:]
	}
	if strings.HasSuffix(domain, "/") && !strings.Contains(domain[1:], "/") {
		domain = domain[:len(domain)-1]
	}

	// Determine base URL
	baseURL := "https://" + domain
	if !strings.Contains(domain, "/") {
		baseURL += "/"
	}

    // Crawl the domain
    discoveredURLs := crawlDomain(baseURL, scanID)

    // Deduplicate and write plain URLs to urls.txt (or to -o if provided)
    outPath := "urls.txt"
    if outputFile != "" {
        outPath = outputFile
    }

    seen := make(map[string]struct{}, len(discoveredURLs))
    unique := make([]string, 0, len(discoveredURLs))
    for _, u := range discoveredURLs {
        if _, ok := seen[u]; ok {
            continue
        }
        seen[u] = struct{}{}
        unique = append(unique, u)
    }

    f, err := os.Create(outPath)
    if err != nil {
        log.Fatalf("Failed to create %s: %v", outPath, err)
    }
    for _, u := range unique {
        _, _ = f.WriteString(u + "\n")
    }
    _ = f.Close()

    log.Printf("Crawling completed. Wrote %d URLs to %s", len(unique), outPath)
}

// runFileCrawlOnly crawls targets listed in a file and writes unique URLs to output (defaults to urls.txt)
func runFileCrawlOnly(filename string, outputFile string) {
    log.Printf("Starting crawl-only from file: %s", filename)

    // Read targets (URLs or domains) from file
    targets, err := readURLsFromFile(filename)
    if err != nil {
        log.Fatalf("Error reading targets from file: %v", err)
    }
    if len(targets) == 0 {
        log.Printf("No targets found in %s", filename)
        // Still create/overwrite an empty urls.txt to be explicit
        outPath := "urls.txt"
        if outputFile != "" { outPath = outputFile }
        _ = os.WriteFile(outPath, []byte(""), 0644)
        log.Printf("Crawling completed. Wrote 0 URLs to %s", outPath)
        return
    }

    // Generate scan ID for file crawl
    scanID := "file_crawl_only_" + strconv.FormatInt(time.Now().Unix(), 10)

    // Aggregate discovered URLs across all targets
    all := make(map[string]struct{})
    for i, targetURL := range targets {
        log.Printf("Crawling %d/%d: %s", i+1, len(targets), targetURL)

        base := targetURL
        if !strings.HasSuffix(base, "/") { base += "/" }

        urls := crawlDomain(base, scanID)
        for _, u := range urls {
            all[u] = struct{}{}
        }
    }

    // Dedupe and write to output
    outPath := "urls.txt"
    if outputFile != "" { outPath = outputFile }

    f, err := os.Create(outPath)
    if err != nil {
        log.Fatalf("Failed to create %s: %v", outPath, err)
    }
    defer f.Close()

    count := 0
    for u := range all {
        _, _ = f.WriteString(u + "\n")
        count++
    }
    log.Printf("Crawling completed. Wrote %d URLs to %s", count, outPath)
}

// runScanFromFile scans URLs or domains from a file
func runScanFromFile(filename string, concurrency int, quiet, headless, fastMode, ultraFast bool, timeout time.Duration, outputFile string) {
    log.Printf("Starting direct URL scan from file: %s (concurrency: %d)", filename, concurrency)

    // Clean up old scan results files before starting new scan
    cleanupAllResultsFiles()
    log.Printf("Cleaned up old scan results files")

    // Read URLs from file (expects full URLs; domains will be prefixed as https://)
    urls, err := readURLsFromFile(filename)
    if err != nil {
        log.Fatalf("Error reading URLs from file: %v", err)
    }
    if len(urls) == 0 {
        log.Printf("No URLs found in %s", filename)
        return
    }

    log.Printf("Found %d URLs to scan", len(urls))

    // Generate scan ID
    scanID := "file_scan_" + strconv.FormatInt(time.Now().Unix(), 10)

    // Set global concurrency and start workers
    maxConcurrentScans = concurrency
    scanSemaphore = make(chan struct{}, concurrency)
    go processScanQueue(quiet)

    // Enqueue URLs directly for scanning (skip crawling)
    startConcurrentScanningWithConcurrency(urls, scanID, concurrency)

    // Wait for all URLs to be scanned (treat completed OR error as terminal)
    log.Printf("Waiting for URL scanning to complete...")
    timeoutChan := time.After(30 * time.Minute) // 30 minute timeout
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-timeoutChan:
            log.Printf("Scan timeout reached (30 minutes). Stopping scan.")
            scanMutex.Lock()
            done := 0
            completed := 0
            for _, u := range urls {
                if urlStatus, exists := scanStatus[u]; exists {
                    if urlStatus == "completed" || urlStatus == "error" {
                        done++
                    }
                    if urlStatus == "completed" {
                        completed++
                    }
                }
            }
            scanMutex.Unlock()
            log.Printf("File URL scan timed out: %d completed, %d failed, %d pending", completed, done-completed, len(urls)-done)
            if outputFile != "" {
                saveFileScanResults(scanID, outputFile)
            }
            return
            
        case <-ticker.C:
            scanMutex.Lock()
            done := 0
            completed := 0
            for _, u := range urls {
                if urlStatus, exists := scanStatus[u]; exists {
                    if urlStatus == "completed" || urlStatus == "error" {
                        done++
                    }
                    if urlStatus == "completed" {
                        completed++
                    }
                }
            }
            allDone := done == len(urls)
            scanMutex.Unlock()

            if allDone {
                log.Printf("File URL scan finished: %d completed, %d failed", completed, len(urls)-completed)
                if outputFile != "" {
                    saveFileScanResults(scanID, outputFile)
                }
                return
            }

            log.Printf("Scanning in progress... (%d/%d done)", done, len(urls))
        }
    }
}

// readURLsFromFile reads URLs or domains from a file
func readURLsFromFile(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	
	lines := strings.Split(string(content), "\n")
	var urls []string
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip empty lines, headers, and count lines
		if line == "" || strings.HasPrefix(line, "Crawled URLs for") || 
		   strings.HasPrefix(line, "Total URLs found:") {
			continue
		}
		
		// Extract URL from lines like "1. https://example.com" or direct URLs
		if strings.Contains(line, "https://") {
			parts := strings.SplitN(line, " ", 2)
			if len(parts) > 1 {
				// Format: "1. https://example.com"
				url := parts[1]
				urls = append(urls, url)
			} else {
				// Format: "https://example.com" (direct URL)
				urls = append(urls, line)
			}
		} else if strings.Contains(line, "http://") {
			// Handle http:// URLs
			parts := strings.SplitN(line, " ", 2)
			if len(parts) > 1 {
				// Format: "1. http://example.com"
				url := parts[1]
				urls = append(urls, url)
			} else {
				// Format: "http://example.com" (direct URL)
				urls = append(urls, line)
			}
		} else {
			// Treat as domain/subdomain if it doesn't contain http
			// Clean domain name
			domain := line
			if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
				domain = strings.Split(domain, "://")[1]
			}
			if strings.HasPrefix(domain, "www.") {
				domain = domain[4:]
			}
			if strings.HasSuffix(domain, "/") && !strings.Contains(domain[1:], "/") {
				domain = domain[:len(domain)-1]
			}
			
			// Add https:// prefix for domain crawling
			if domain != "" {
				urls = append(urls, "https://"+domain)
			}
		}
	}
	
	return urls, nil
}

func runDomainScan(domain string, concurrency int, quiet, headless, fastMode, ultraFast bool, timeout time.Duration, outputFile string) {
	log.Printf("Starting domain scan for: %s (concurrency: %d)", domain, concurrency)
	
	// Clean up old scan results files before starting new scan
	cleanupAllResultsFiles()
	log.Printf("Cleaned up old scan results files")
	
	// Generate scan ID
	scanID := "cli_domain_scan_" + strconv.FormatInt(time.Now().Unix(), 10)
	
	// Set global concurrency
	maxConcurrentScans = concurrency
	scanSemaphore = make(chan struct{}, concurrency)
	
	// Start worker processes
	go processScanQueue(quiet)
	
	// Start domain crawling
	startDomainCrawling(domain, scanID)
	
	// Wait for scanning to complete
	log.Printf("Waiting for scanning to complete...")
	for {
		crawlMutex.RLock()
		status, exists := crawlStatuses[scanID]
		crawlMutex.RUnlock()
		
		if !exists {
			log.Printf("Scan status not found, waiting...")
			time.Sleep(1 * time.Second)
			continue
		}
		
		if status.Status == "completed" {
			log.Printf("Domain scan completed for: %s", domain)
			
			// Save results to output file if specified
			if outputFile != "" {
				saveDomainScanResults(scanID, outputFile)
			}
			break
		}
		
		log.Printf("Scan status: %s, discovered: %d, scanned: %d", 
			status.Status, len(status.DiscoveredURLs), len(status.ScannedURLs))
		time.Sleep(2 * time.Second)
	}
}

// startFileDomainCrawling starts domain crawling for each URL/domain in the file
func startFileDomainCrawling(urls []string, scanID string) {
	log.Printf("Starting domain crawling for %d URLs/domains", len(urls))
	
	// Initialize crawl status for file scan
	crawlMutex.Lock()
	crawlStatuses[scanID] = &CrawlStatus{
		ScanID:         scanID,
		Domain:         "file_scan",
		Status:         "crawling",
		DiscoveredURLs: []string{},
		ScannedURLs:    []string{},
		StartTime:      time.Now(),
	}
	crawlMutex.Unlock()
	
	// Crawl each domain/URL
	for i, targetURL := range urls {
		log.Printf("Crawling %d/%d: %s", i+1, len(urls), targetURL)
		
		// Parse URL to get domain
		parsedURL, err := url.Parse(targetURL)
		if err != nil {
			log.Printf("Error parsing URL %s: %v", targetURL, err)
			continue
		}
		
		// Clean domain name
		domain := parsedURL.Host
		if strings.HasPrefix(domain, "www.") {
			domain = domain[4:]
		}
		
		// Determine base URL for crawling
		baseURL := targetURL
		if !strings.HasSuffix(baseURL, "/") {
			baseURL += "/"
		}
		
		// Crawl the domain
		discoveredURLs := crawlDomain(baseURL, scanID)
		
		// Update crawl status
		crawlMutex.Lock()
		if status, exists := crawlStatuses[scanID]; exists {
			status.DiscoveredURLs = append(status.DiscoveredURLs, discoveredURLs...)
		}
		crawlMutex.Unlock()
		
		log.Printf("Crawled %s: found %d URLs", domain, len(discoveredURLs))
	}
	
	// Update status to scanning
	crawlMutex.Lock()
	if status, exists := crawlStatuses[scanID]; exists {
		status.Status = "scanning"
		// Start scanning all discovered URLs
		startConcurrentScanning(status.DiscoveredURLs, scanID)
	}
	crawlMutex.Unlock()
	
	log.Printf("Domain crawling completed. Starting XSS scanning...")
}

// saveFileScanResults saves file scan results to output file
func saveFileScanResults(scanID, outputFile string) {
	resultsMutex.RLock()
	defer resultsMutex.RUnlock()
	
	if resultsFile, exists := resultsFiles[scanID]; exists {
		data, err := os.ReadFile(resultsFile)
		if err != nil {
			log.Printf("Error reading results file: %v", err)
			return
		}
		
		err = os.WriteFile(outputFile, data, 0644)
		if err != nil {
			log.Printf("Error writing output file: %v", err)
			return
		}
		
		log.Printf("Results saved to: %s", outputFile)
	}
}

// saveDomainScanResults saves domain scan results to output file
func saveDomainScanResults(scanID, outputFile string) {
	resultsMutex.RLock()
	defer resultsMutex.RUnlock()
	
	if resultsFile, exists := resultsFiles[scanID]; exists {
		data, err := os.ReadFile(resultsFile)
		if err != nil {
			log.Printf("Error reading results file: %v", err)
			return
		}
		
		err = os.WriteFile(outputFile, data, 0644)
		if err != nil {
			log.Printf("Error writing output file: %v", err)
			return
		}
		
		log.Printf("Results saved to: %s", outputFile)
	}
}

// runWAFW00F executes wafw00f for the given host and returns (detected, name)
func runWAFW00F(host string) (bool, string) {
	// Try with a longer timeout and more aggressive options
	cmd := exec.Command("wafw00f", "-a", "https://"+host, "--timeout", "15")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// If wafw00f fails, try to detect WAF based on common patterns
		// For known WAF-protected sites like PayPal, Cloudflare, etc.
		if strings.Contains(strings.ToLower(host), "paypal") || 
		   strings.Contains(strings.ToLower(host), "cloudflare") ||
		   strings.Contains(strings.ToLower(host), "akamai") {
			return true, "Unknown WAF (detected by hostname)"
		}
		return false, ""
	}
	text := string(out)
	// Simple heuristics: look for 'is behind' line
	// e.g., The site https://example.org is behind Edgecast (Verizon Digital Media) WAF.
	detected := false
	name := ""
	if idx := findIndex(text, " is behind "); idx >= 0 {
		detected = true
		// Extract name after 'is behind '
		rest := text[idx+len(" is behind "):]
		for i := 0; i < len(rest); i++ {
			if rest[i] == '\n' || rest[i] == '\r' {
				name = rest[:i]
				break
			}
		}
	}
	return detected, name
}

func findIndex(s, sub string) int {
	return len([]rune(s[:])) - len([]rune(s[:])) + strings.Index(s, sub)
}

// runServer starts the HTTP server for Burp Suite extension
func runServer(port string, quiet, headless, fastMode, ultraFast bool, timeout time.Duration) {
	// Start the scan processor with both concurrent and sequential workers
	go processScanQueue(quiet)
	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request struct {
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
			WAFDetected bool          `json:"waf_detected"`
			WAFName     string        `json:"waf_name"`
			ScanType    string        `json:"scan_type"` // "proxy", "domain", "authenticated"
			ScanID      string        `json:"scan_id"`   // Optional scan ID for grouping
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if request.URL == "" {
			http.Error(w, "URL is required", http.StatusBadRequest)
			return
		}

		// Set initial status with mutex protection
		scanMutex.Lock()
		scanStatus[request.URL] = "scanning"
		scanMutex.Unlock()

		// Create scanner configuration
		config := &scanner.Config{
			URL:              request.URL,
			Headers:          request.Headers,
			Quiet:            quiet,
			Headless:         headless,
			FastMode:         fastMode,
			UltraFast:        ultraFast,
			Timeout:          timeout,
		}
		

		// WAF detection cache by host
		u, _ := url.Parse(request.URL)
		if u != nil {
			scanMutex.Lock()
			entry, ok := wafCache[u.Host]
			scanMutex.Unlock()
			if !ok {
				// Run wafw00f once per host (best-effort)
				d, n := runWAFW00F(u.Host)
				scanMutex.Lock()
				wafCache[u.Host] = struct{Detected bool; Name string}{Detected: d, Name: n}
				scanMutex.Unlock()
				entry = struct{Detected bool; Name string}{d, n}
			}
			config.WAFDetected = entry.Detected
			config.WAFName = entry.Name
			if !quiet {
				if entry.Detected {
					log.Printf("WAF detected for %s: %s", u.Host, entry.Name)
				} else {
					log.Printf("No WAF detected for %s", u.Host)
				}
			}
		}

		// Determine scan type and generate scan ID
		scanType := request.ScanType
		if scanType == "" {
			scanType = "proxy" // Default to proxy scan for backward compatibility
		}
		
		// Generate scan ID if not provided
		scanID := request.ScanID
		if scanID == "" {
			scanID = fmt.Sprintf("%d_%s", time.Now().Unix(), strings.ReplaceAll(request.URL, "/", "_"))
		}
		
		// Create scan request
		scanReq := scanRequest{
			URL:      request.URL,
			Headers:  request.Headers,
			Config:   config,
			ScanType: scanType,
			ScanID:   scanID,
		}
		
		// Route to appropriate queue based on scan type
		var queueMessage string
		if scanType == "domain" || scanType == "authenticated" {
			// Use concurrent queue for domain and authenticated scans
			scanQueue <- scanReq
			queueMessage = "Scan queued for concurrent processing"
		} else {
			// Use sequential queue for proxy scans
			sequentialQueue <- scanReq
			queueMessage = "Scan queued for sequential processing"
		}

		// Return immediately with scan ID
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "scanning",
			"url":    request.URL,
			"scan_id": scanID,
			"message": queueMessage,
		})
	})

	// New endpoint for polling results file
	http.HandleFunc("/results-file", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		scanID := r.URL.Query().Get("scan_id")
		if scanID == "" {
			http.Error(w, "scan_id parameter required", http.StatusBadRequest)
			return
		}

		resultsMutex.RLock()
		resultsFile, exists := resultsFiles[scanID]
		resultsMutex.RUnlock()

		if !exists {
			// Return empty results if file doesn't exist yet
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]interface{}{})
			return
		}

		// Read and return the results file
		data, err := os.ReadFile(resultsFile)
		if err != nil {
			http.Error(w, "Error reading results file", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	})

	// Cleanup endpoint - removes all results files (called before new scan starts)
	http.HandleFunc("/cleanup-results", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cleanupAllResultsFiles()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "cleaned"})
	})

	// Start domain scan endpoint - accepts domain name and starts crawling
	http.HandleFunc("/start-domain-scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request struct {
			Domain      string `json:"domain"`
			Concurrency int    `json:"concurrency"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if request.Domain == "" {
			http.Error(w, "Domain required", http.StatusBadRequest)
			return
		}

		// Validate concurrency
		if request.Concurrency < 1 || request.Concurrency > 10 {
			request.Concurrency = 5 // Default to 5 if invalid
		}

		// Generate scan ID for this domain scan
		scanID := "domain_scan_" + strconv.FormatInt(time.Now().Unix(), 10)
		
		// Start domain crawling in background with specified concurrency
		go startDomainCrawlingWithConcurrency(request.Domain, scanID, request.Concurrency)
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "started",
			"scan_id": scanID,
		})
	})

	// Start authenticated scan endpoint
	http.HandleFunc("/start-authenticated-scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request struct {
			Concurrency int `json:"concurrency"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Validate concurrency
		if request.Concurrency < 1 || request.Concurrency > 10 {
			request.Concurrency = 5 // Default to 5 if invalid
		}

		// Generate scan ID for this authenticated scan
		scanID := "auth_scan_" + strconv.FormatInt(time.Now().Unix(), 10)
		
		// Start authenticated scanning in background with specified concurrency
		go startAuthenticatedScanning(scanID, request.Concurrency)
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "started",
			"scan_id": scanID,
		})
	})

	// Crawl status endpoint - returns discovered URLs and progress
	http.HandleFunc("/crawl-status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		scanID := r.URL.Query().Get("scan_id")
		if scanID == "" {
			http.Error(w, "scan_id parameter required", http.StatusBadRequest)
			return
		}

		// Return crawl status and discovered URLs
		status := getCrawlStatus(scanID)
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(status)
	})

	// Scan results endpoint - returns XSS vulnerabilities as they're found
	http.HandleFunc("/scan-results", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		scanID := r.URL.Query().Get("scan_id")
		if scanID == "" {
			http.Error(w, "scan_id parameter required", http.StatusBadRequest)
			return
		}

		// Return scan results
		results := getScanResults(scanID)
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(results)
	})

	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		
		// Return all scan statuses with mutex protection
		scanMutex.Lock()
		statuses := make(map[string]string)
		for url, status := range scanStatus {
			statuses[url] = status
		}
		scanMutex.Unlock()
		
		json.NewEncoder(w).Encode(map[string]interface{}{
			"statuses": statuses,
		})
	})

	http.HandleFunc("/results", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		// Get URL from query parameter
		url := r.URL.Query().Get("url")
		if url == "" {
			http.Error(w, "URL parameter is required", http.StatusBadRequest)
			return
		}

		// Check if results exist for this URL with mutex protection
		scanMutex.Lock()
		result, exists := scanResults[url]
		scanMutex.Unlock()
		
		
		if exists {
			// Debug: Log what we're returning
			if scanResult, ok := result.(*scanner.ScanResult); ok {
				
				// Convert ScanResult to the format expected by Burp plugin
				// Convert vulnerabilities to the format expected by processVulnerabilityFromFile
				var formattedVulns []map[string]interface{}
				for _, vuln := range scanResult.Vulnerabilities {
					payload := "No payload"
					if len(vuln.WorkingPayloads) > 0 {
						payload = vuln.WorkingPayloads[0]
					}
					
					formattedVuln := map[string]interface{}{
						"url": vuln.ExploitURL,
						"type": "Reflected XSS",
						"payload": payload,
						"context": vuln.Context,
						"timestamp": scanResult.Timestamp.Format("2006-01-02 15:04:05"),
						"parameter": vuln.Parameter,
						"method": vuln.Method,
						"confidence": vuln.Confidence,
					}
					formattedVulns = append(formattedVulns, formattedVuln)
				}
				
				response := map[string]interface{}{
					"completed": true,
					"url": scanResult.URL,
					"success": scanResult.Success,
					"vulnerabilities": formattedVulns,
					"parameters_tested": scanResult.ParametersTested,
					"scan_duration": scanResult.ScanDuration.String(),
				}
				
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
			} else {
				// Return error result
				response := map[string]interface{}{
					"completed": true,
					"url": url,
					"success": false,
					"error": "Scan failed",
					"vulnerabilities": []interface{}{},
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
			}
		} else {
			http.Error(w, "No results found for URL", http.StatusNotFound)
		}
	})

	http.HandleFunc("/crawl", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request struct {
			Domain  string            `json:"domain"`
			BaseURL string            `json:"base_url"`
			Headers map[string]string `json:"headers"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if request.BaseURL == "" {
			http.Error(w, "Base URL is required", http.StatusBadRequest)
			return
		}

		// Create crawler instance
		crawlerInstance := crawler.NewCrawler()
		
		// Perform intelligent crawling
		result, err := crawlerInstance.CrawlDomain(request.BaseURL, request.Headers)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
			})
			return
		}

		// Return crawl results
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(result)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "healthy",
			"service": "xss-scanner",
			"version": "1.0.0",
		})
	})

	if !quiet {
		log.Printf("🚀 XSS Scanner Server starting on port %s", port)
		log.Printf("📡 Scanner API: http://localhost:%s/scan", port)
		log.Printf("❤️ Health Check: http://localhost:%s/health", port)
		log.Printf("🎯 Ready for Burp Suite extension!")
	}

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
