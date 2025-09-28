package crawler

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"xss-scanner/internal/parser"
)

// Crawler represents an intelligent web crawler
type Crawler struct {
	client     *http.Client
	parser     *parser.HTMLParser
	visited    map[string]bool
	discovered map[string][]Parameter
	mu         sync.Mutex
	maxDepth   int
	baseDomain string
	basePath   string // Restrict crawling to this path
	maxWorkers int
	urlQueue   chan string
	done       chan bool
	authHeaders map[string]string // Authentication headers
}

// Parameter represents a discovered parameter
type Parameter struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // query, form, hidden, fragment
	Value    string `json:"value"`
	Endpoint string `json:"endpoint"`
}

// CrawlResult represents the result of crawling
type CrawlResult struct {
	URLs        []string              `json:"urls"`
	Parameters  map[string][]Parameter `json:"parameters"`
	Endpoints   []string              `json:"endpoints"`
	TotalPages  int                   `json:"total_pages"`
	ScanTime    time.Duration         `json:"scan_time"`
}

// NewCrawler creates a new intelligent crawler
func NewCrawler() *Crawler {
	client := &http.Client{
		Timeout: 10 * time.Second, // Reduced timeout for faster crawling
		Transport: &http.Transport{
			TLSHandshakeTimeout: 30 * time.Second,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	return &Crawler{
		client:     client,
		parser:     parser.NewHTMLParser(),
		visited:    make(map[string]bool),
		discovered: make(map[string][]Parameter),
		maxDepth:   10, // Deep crawling until no new endpoints found
		maxWorkers: 50, // More concurrent workers for faster crawling
		urlQueue:   make(chan string, 5000), // Much larger buffer for URLs
		done:       make(chan bool),
	}
}

// CrawlDomain performs intelligent crawling of a domain with concurrency
func (c *Crawler) CrawlDomain(baseURL string, headers map[string]string) (*CrawlResult, error) {
	startTime := time.Now()
	
	// Store authentication headers
	c.authHeaders = headers
	
	// Parse base URL to extract domain and path
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %v", err)
	}
	
	c.baseDomain = parsedURL.Host
	c.basePath = parsedURL.Path
	
	// If path is empty or just "/", set to root
	if c.basePath == "" || c.basePath == "/" {
		c.basePath = "/"
		log.Printf("Starting concurrent crawl of domain: %s with %d workers", c.baseDomain, c.maxWorkers)
	} else {
		log.Printf("Starting concurrent crawl of domain: %s%s with %d workers (path-restricted)", c.baseDomain, c.basePath, c.maxWorkers)
	}
	
	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < c.maxWorkers; i++ {
		wg.Add(1)
		go c.worker(&wg)
	}
	
	// Add initial URL to queue
	c.urlQueue <- baseURL
	
	// Close queue and signal completion
	go func() {
		wg.Wait()
		close(c.urlQueue)
		c.done <- true
	}()
	
	// Wait for completion with longer timeout for deep crawling
	select {
	case <-c.done:
		// Crawl completed successfully
		log.Printf("Crawl completed successfully")
	case <-time.After(10 * time.Minute):
		// Timeout after 10 minutes for deep crawling
		log.Printf("Crawl timeout after 10 minutes")
	}
	
	// Convert discovered URLs to slice
	var urlList []string
	for discoveredURL := range c.discovered {
		urlList = append(urlList, discoveredURL)
	}
	
	result := &CrawlResult{
		URLs:       urlList,
		Parameters: c.discovered,
		Endpoints:  c.extractEndpoints(urlList),
		TotalPages: len(c.visited),
		ScanTime:   time.Since(startTime),
	}
	
	log.Printf("Concurrent crawl completed: %d URLs discovered, %d pages visited in %v", 
		len(urlList), len(c.visited), time.Since(startTime))
	
	return result, nil
}

// worker processes URLs from the queue concurrently
func (c *Crawler) worker(wg *sync.WaitGroup) {
	defer wg.Done()
	
	for {
		select {
		case pageURL, ok := <-c.urlQueue:
			if !ok {
				// Channel closed, exit
				return
			}
			c.crawlPage(pageURL)
		case <-time.After(10 * time.Second):
			// Timeout if no work for 10 seconds
			return
		}
	}
}

// crawlPage crawls a single page and discovers URLs/parameters
func (c *Crawler) crawlPage(pageURL string) {
	// Check if already visited
	c.mu.Lock()
	if c.visited[pageURL] {
		c.mu.Unlock()
		return
	}
	c.visited[pageURL] = true
	totalVisited := len(c.visited)
	c.mu.Unlock()
	
	// Log progress every 50 pages
	if totalVisited%50 == 0 {
		log.Printf("Crawled %d pages, currently processing: %s", totalVisited, pageURL)
	}
	
	// Fetch page content
	content, err := c.fetchPageContent(pageURL)
	if err != nil {
		// Only skip 404s, but include 400s and 500s as they might be valid endpoints
		if !strings.Contains(err.Error(), "404") {
			log.Printf("Error fetching page %s: %v", pageURL, err)
		}
		// Still process the URL even if there's an error (except 404)
		if strings.Contains(err.Error(), "404") {
			return
		}
		// For 400/500 errors, still try to discover URLs from the error page
		content = "" // Empty content for error pages
	}
	
	// Always add the current URL to discovered URLs (except 404s)
	c.mu.Lock()
	if _, exists := c.discovered[pageURL]; !exists {
		c.discovered[pageURL] = []Parameter{}
	}
	c.mu.Unlock()
	
	// Discover URLs and parameters from this page
	discoveredURLs := c.discoverURLsFromContent(content, pageURL)
	discoveredParams := c.discoverParametersFromContent(content, pageURL)
	
	// Store discovered parameters
	c.mu.Lock()
	for url, params := range discoveredParams {
		c.discovered[url] = params
	}
	c.mu.Unlock()
	
	// Add discovered URLs to queue for processing
	for discoveredURL := range discoveredURLs {
		c.mu.Lock()
		if !c.visited[discoveredURL] && c.isSameDomain(discoveredURL) {
			c.mu.Unlock()
			select {
			case c.urlQueue <- discoveredURL:
				// URL added to queue successfully
			default:
				// Queue is full, but still try to add more URLs
				// This ensures we don't miss important URLs
				go func(url string) {
					time.Sleep(100 * time.Millisecond) // Brief delay
					select {
					case c.urlQueue <- url:
					default:
						// Still full, skip
					}
				}(discoveredURL)
			}
		} else {
			c.mu.Unlock()
		}
	}
}

// fetchPageContent fetches the content of a page
func (c *Crawler) fetchPageContent(pageURL string) (string, error) {
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return "", err
	}
	
	// Add authentication headers if available
	if c.authHeaders != nil {
		for key, value := range c.authHeaders {
			req.Header.Set(key, value)
		}
	}
	
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	// Only return error for 404s, but include all other status codes (400, 500, etc.)
	if resp.StatusCode == 404 {
		return "", fmt.Errorf("HTTP 404: Not Found")
	}
	
	// Read response body
	bodyBytes := make([]byte, 0, 1024*1024) // 1MB buffer
	buffer := make([]byte, 4096)
	
	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			bodyBytes = append(bodyBytes, buffer[:n]...)
		}
		if err != nil {
			break
		}
	}
	
	return string(bodyBytes), nil
}

// discoverURLsFromContent discovers URLs from HTML content (comprehensive)
func (c *Crawler) discoverURLsFromContent(content, baseURL string) map[string]bool {
	urls := make(map[string]bool)
	
	// Parse base URL for relative URL resolution
	base, err := url.Parse(baseURL)
	if err != nil {
		return urls
	}
	
	// Comprehensive URL patterns to find all possible links
	urlPatterns := []string{
		`href\s*=\s*["']([^"']+)["']`,                    // href attributes
		`src\s*=\s*["']([^"']+)["']`,                     // src attributes  
		`action\s*=\s*["']([^"']+)["']`,                 // form actions
		`(?:fetch|XMLHttpRequest|ajax)\s*\(\s*["']([^"']+)["']`, // JS calls
		`<a[^>]+href\s*=\s*["']([^"']+)["'][^>]*>`,      // anchor tags with href
		`<link[^>]+href\s*=\s*["']([^"']+)["'][^>]*>`,   // link tags
		`<script[^>]+src\s*=\s*["']([^"']+)["'][^>]*>`, // script tags
		`<img[^>]+src\s*=\s*["']([^"']+)["'][^>]*>`,     // img tags
		`<iframe[^>]+src\s*=\s*["']([^"']+)["'][^>]*>`, // iframe tags
		`<form[^>]+action\s*=\s*["']([^"']+)["'][^>]*>`, // form tags
		`<object[^>]+data\s*=\s*["']([^"']+)["'][^>]*>`, // object data
		`<embed[^>]+src\s*=\s*["']([^"']+)["'][^>]*>`,   // embed src
		`<source[^>]+src\s*=\s*["']([^"']+)["'][^>]*>`,  // source src
		`<param[^>]+value\s*=\s*["']([^"']+)["'][^>]*>`, // param value
	}
	
	for _, pattern := range urlPatterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				rawURL := match[1]
				
				// Skip non-HTTP schemes and fragments
				if strings.HasPrefix(rawURL, "javascript:") || 
				   strings.HasPrefix(rawURL, "data:") || 
				   strings.HasPrefix(rawURL, "mailto:") ||
				   strings.HasPrefix(rawURL, "tel:") ||
				   strings.HasPrefix(rawURL, "#") {
					continue
				}
				
				resolvedURL := c.resolveURL(rawURL, base)
				if resolvedURL != "" && c.isValidURL(resolvedURL) {
					urls[resolvedURL] = true
				}
			}
		}
	}
	
	return urls
}

// discoverParametersFromContent discovers parameters from HTML content (optimized)
func (c *Crawler) discoverParametersFromContent(content, baseURL string) map[string][]Parameter {
	params := make(map[string][]Parameter)
	
	// Parse base URL (not used in simplified version)
	_, err := url.Parse(baseURL)
	if err != nil {
		return params
	}
	
	// 1. Find form parameters (simplified)
	inputRegex := regexp.MustCompile(`<input[^>]+name\s*=\s*["']([^"']+)["'][^>]*>`)
	inputMatches := inputRegex.FindAllStringSubmatch(content, -1)
	
	var formParams []Parameter
	for _, inputMatch := range inputMatches {
		if len(inputMatch) > 1 {
			paramName := inputMatch[1]
			formParams = append(formParams, Parameter{
				Name:     paramName,
				Type:     "form",
				Value:    "",
				Endpoint: baseURL,
			})
		}
	}
	
	if len(formParams) > 0 {
		params[baseURL] = formParams
	}
	
	// 2. Find query parameters in existing URLs (simplified)
	queryRegex := regexp.MustCompile(`\?([^"'\s]+)`)
	queryMatches := queryRegex.FindAllStringSubmatch(content, -1)
	
	for _, queryMatch := range queryMatches {
		if len(queryMatch) > 1 {
			queryString := queryMatch[1]
			queryParams := strings.Split(queryString, "&")
			
			var urlParams []Parameter
			for _, param := range queryParams {
				if strings.Contains(param, "=") {
					parts := strings.SplitN(param, "=", 2)
					if len(parts) == 2 {
						urlParams = append(urlParams, Parameter{
							Name:     parts[0],
							Type:     "query",
							Value:    parts[1],
							Endpoint: baseURL,
						})
					}
				}
			}
			
			if len(urlParams) > 0 {
				params[baseURL] = append(params[baseURL], urlParams...)
			}
		}
	}
	
	return params
}

// resolveURL resolves a relative URL against a base URL
func (c *Crawler) resolveURL(relativeURL string, base *url.URL) string {
	if relativeURL == "" {
		return ""
	}
	
	// Skip non-HTTP URLs
	if strings.HasPrefix(relativeURL, "javascript:") ||
		strings.HasPrefix(relativeURL, "mailto:") ||
		strings.HasPrefix(relativeURL, "tel:") ||
		strings.HasPrefix(relativeURL, "#") {
		return ""
	}
	
	// Parse relative URL
	parsed, err := url.Parse(relativeURL)
	if err != nil {
		return ""
	}
	
	// Resolve against base URL
	resolved := base.ResolveReference(parsed)
	
	// Only return URLs from the same domain
	if resolved.Host != c.baseDomain {
		return ""
	}
	
	return resolved.String()
}

// isSameDomain checks if a URL belongs to the same domain
func (c *Crawler) isSameDomain(urlStr string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	
	return parsed.Host == c.baseDomain
}

// isValidURL checks if a URL is valid and should be crawled
func (c *Crawler) isValidURL(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	
	// Must be HTTP or HTTPS
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return false
	}
	
	// Must be same domain
	if parsedURL.Host != c.baseDomain {
		return false
	}
	
	// Path restriction: URL must be within the base path
	if c.basePath != "/" {
		// Ensure the URL path starts with the base path
		if !strings.HasPrefix(parsedURL.Path, c.basePath) {
			return false
		}
	}
	
	// Skip common non-content files
	path := strings.ToLower(parsedURL.Path)
	skipExtensions := []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot"}
	for _, ext := range skipExtensions {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}
	
	return true
}

// isParameterName checks if a JavaScript variable name looks like a parameter
func (c *Crawler) isParameterName(name string) bool {
	// Common parameter name patterns
	paramPatterns := []string{
		"id", "name", "value", "type", "mode", "action", "method",
		"url", "path", "query", "search", "filter", "sort", "page",
		"limit", "offset", "count", "size", "format", "version",
	}
	
	nameLower := strings.ToLower(name)
	for _, pattern := range paramPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	
	return false
}

// extractEndpoints extracts unique endpoints from discovered URLs
func (c *Crawler) extractEndpoints(urls []string) []string {
	endpoints := make(map[string]bool)
	
	for _, urlStr := range urls {
		parsed, err := url.Parse(urlStr)
		if err != nil {
			continue
		}
		
		endpoint := parsed.Path
		if endpoint == "" {
			endpoint = "/"
		}
		
		endpoints[endpoint] = true
	}
	
	var endpointList []string
	for endpoint := range endpoints {
		endpointList = append(endpointList, endpoint)
	}
	
	return endpointList
}
