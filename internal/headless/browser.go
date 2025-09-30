package headless

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/playwright-community/playwright-go"
)

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Note: Each browser instance now has its own mutex for thread safety

// Browser represents a headless browser instance
type Browser struct {
	pw      *playwright.Playwright
	browser playwright.Browser
	context playwright.BrowserContext
	page    playwright.Page
	mu      sync.Mutex // Individual mutex per browser instance
}

// NewBrowser creates a new headless browser instance
func NewBrowser() *Browser {
	
	// Add panic recovery for Playwright initialization
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from Playwright initialization panic: %v", r)
		}
	}()

	pw, err := playwright.Run()
	if err != nil {
		log.Printf("Failed to start Playwright: %v", err)
		return nil
	}

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
		Args: []string{
			"--disable-gpu",
			"--no-sandbox",
			"--disable-dev-shm-usage",
			"--disable-web-security",
			"--disable-features=VizDisplayCompositor",
			"--disable-blink-features=AutomationControlled",
			"--disable-extensions",
			"--disable-plugins",
			"--disable-images",
			"--disable-background-timer-throttling",
			"--disable-backgrounding-occluded-windows",
			"--disable-renderer-backgrounding",
			"--disable-field-trial-config",
			"--disable-ipc-flooding-protection",
			"--disable-background-networking",
			"--disable-default-apps",
			"--disable-sync",
			"--disable-translate",
			"--hide-scrollbars",
			"--mute-audio",
			"--no-first-run",
			"--safebrowsing-disable-auto-update",
			"--disable-url-validation",
			"--disable-features=TranslateUI",
			"--disable-ipc-flooding-protection",
			"--disable-hang-monitor",
			"--disable-prompt-on-repost",
			"--disable-domain-reliability",
			"--disable-component-extensions-with-background-pages",
		},
	})
	if err != nil {
		log.Printf("Failed to launch browser: %v", err)
		pw.Stop()
		return nil
	}

	context, err := browser.NewContext(playwright.BrowserNewContextOptions{
		IgnoreHttpsErrors: playwright.Bool(true),
		UserAgent:          playwright.String("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"),
		Viewport: &playwright.Size{
			Width:  1280,
			Height: 720,
		},
	})
	if err != nil {
		log.Printf("Failed to create browser context: %v", err)
		browser.Close()
		pw.Stop()
		return nil
	}

	page, err := context.NewPage()
	if err != nil {
		log.Printf("Failed to create page: %v", err)
		context.Close()
		browser.Close()
		pw.Stop()
		return nil
	}

	return &Browser{
		pw:      pw,
		browser: browser,
		context: context,
		page:    page,
		mu:      sync.Mutex{},
	}
}

// TestXSSPayload tests if an XSS payload triggers an alert
func (b *Browser) TestXSSPayload(ctx context.Context, baseURL, paramName, payload string, headers map[string]string) (bool, error) {
	return b.TestXSSPayloadWithMethod(ctx, baseURL, paramName, payload, headers, "GET")
}

// TestXSSPayloadWithMethod tests if an XSS payload triggers an alert with specified HTTP method
func (b *Browser) TestXSSPayloadWithMethod(ctx context.Context, baseURL, paramName, payload string, headers map[string]string, method string) (bool, error) {
	// Add panic recovery at the very beginning
	defer func() {
		if r := recover(); r != nil {
		}
	}()
	
	// Reduced noise: keep only one concise entry line
	
	// Use instance-specific mutex to prevent conflicts within this browser instance
	b.mu.Lock()
	defer b.mu.Unlock()
	
	// Add timeout protection
	timeoutCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	
	// Add panic recovery for the entire function
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from browser test panic: %v", r)
		}
	}()
	
	var testURL string
	if method == "POST" {
		testURL = baseURL
	} else {
		// Properly construct the test URL with URL encoding
		parsedBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return false, fmt.Errorf("invalid base URL: %v", err)
		}
		
		// Add the parameter to the query string
		query := parsedBaseURL.Query()
		query.Set(paramName, payload)
		parsedBaseURL.RawQuery = query.Encode()
		testURL = parsedBaseURL.String()
	}
	
	if headers != nil {
		// Keep minimal header logging
	}

	// Set up alert detection
	alertDetected := false
	
	// Set headers on the browser context if provided
	if headers != nil && len(headers) > 0 {
		// Only allow safe headers; some (Host, Sec-*, Accept-Encoding) are forbidden
		allowed := map[string]bool{
			"accept":          true,
			"accept-language": true,
			"cache-control":   true,
			"user-agent":      true,
			"referer":         true,
			"cookie":          true, // cookie will also be added via AddCookies below
		}

		filtered := map[string]string{}
		for k, v := range headers {
			lk := strings.ToLower(k)
			if allowed[lk] {
				filtered[k] = v
			}
		}

		if len(filtered) > 0 {
			if err := b.context.SetExtraHTTPHeaders(filtered); err != nil {
			} else {
			}
		} else {
		}

		// Note: Some browsers may ignore Cookie header via SetExtraHTTPHeaders.
		// If that happens in your environment, we can switch to context.AddCookies
		// with the correct Playwright types/version. For now, keep Cookie in headers.
	}
	
	// Set up dialog handler BEFORE navigation with error handling
	b.page.On("dialog", func(dialog playwright.Dialog) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Recovered from dialog handler panic: %v", r)
			}
		}()
		alertDetected = true
		dialog.Dismiss()
	})
	
	// Also set up console message handler to catch any JavaScript errors
	b.page.On("console", func(msg playwright.ConsoleMessage) {
	})

	// Check timeout before navigation
	select {
	case <-timeoutCtx.Done():
		return false, timeoutCtx.Err()
	default:
	}

	// Navigate to the test URL with better error handling
	if method == "POST" {
		// For POST requests, first navigate to the page, then submit the form
		_, err := b.page.Goto(testURL, playwright.PageGotoOptions{
			WaitUntil: playwright.WaitUntilStateDomcontentloaded,
			Timeout:    playwright.Float(60000), // Increased to 60 seconds
		})
		if err != nil {
			log.Printf("Navigation error for %s: %v", testURL, err)
			// Don't return false immediately, try to continue
		}
		
		// Fill the form field and submit
		err = b.page.Fill("input[name=\""+paramName+"\"]", payload)
		if err != nil {
			log.Printf("Error filling form field %s: %v", paramName, err)
			// Don't return false immediately, try to continue
		}
		
		// Submit the form
		err = b.page.Click("input[type=\"submit\"]")
		if err != nil {
			log.Printf("Error submitting form: %v", err)
			// Don't return false immediately, try to continue
		}
		
		// Wait a bit for the response
		time.Sleep(2 * time.Second)
	} else {
		// For GET requests, prefer direct navigation to the test URL.
		// If navigation fails (e.g., DVWA), fall back to base-page form fill/submit if an input is present.
		// Build base page URL without query
		parsedBase, errParse := url.Parse(baseURL)
		if errParse != nil {
			return false, fmt.Errorf("invalid base URL: %v", errParse)
		}
		parsedBase.RawQuery = ""
		basePageURL := parsedBase.String()

		// Try direct navigation first
		_, navErr := b.page.Goto(testURL, playwright.PageGotoOptions{
			WaitUntil: playwright.WaitUntilStateDomcontentloaded,
			Timeout:    playwright.Float(60000),
		})
		if navErr == nil {
			// Direct navigation succeeded; quick content check
			_, err := b.page.Content()
			if err != nil {
				log.Printf("Error getting page content: %v", err)
			}
		} else {
			log.Printf("Navigation error for test URL %s: %v", testURL, navErr)
			// Fall back: navigate to base page and attempt form fill/submit if input exists
			_, err := b.page.Goto(basePageURL, playwright.PageGotoOptions{
				WaitUntil: playwright.WaitUntilStateDomcontentloaded,
				Timeout:    playwright.Float(60000),
			})
			if err != nil {
				log.Printf("Navigation error for base page %s: %v", basePageURL, err)
				return false, fmt.Errorf("navigation failed: %v", err)
			}

			// Check if input exists before filling
			hasInput, _ := b.page.Evaluate(`(selector) => !!document.querySelector(selector)`, fmt.Sprintf("input[name=\\\"%s\\\"]", paramName))
			if exists, ok := hasInput.(bool); ok && exists {
				if err := b.page.Fill("input[name=\""+paramName+"\"]", payload); err != nil {
				}
				if err := b.page.Click("input[type=\"submit\"]"); err != nil {
				}
				time.Sleep(1500 * time.Millisecond)
			} else {
				// No input on page; as a final attempt, do a client-side redirect to testURL
				_, _ = b.page.Evaluate("(u) => { location.href = u }", testURL)
				time.Sleep(1500 * time.Millisecond)
			}
		}

		// Post-navigation content check
		_, err := b.page.Content()
		if err != nil {
			log.Printf("Error getting page content after navigation: %v", err)
		}
	}

	// Special handling for URL contexts (javascript: and data: URLs)
	if strings.HasPrefix(payload, "javascript:") || strings.HasPrefix(payload, "data:") {
		// For URL contexts, we need to click on the link to trigger the URL
		// Get page content first
		_, _ = b.page.Content()
		
		// For URL contexts, we need to click on the link directly
		// The payload should be in the href attribute
		clickResult, err := b.page.Evaluate(`() => {
			try {
				let eventsTriggered = 0;
				
				// Click all links that contain the payload in href
				const links = document.querySelectorAll('a[href]');
				for (let link of links) {
					try {
						if (link.href.includes('` + payload + `')) {
							link.click();
							eventsTriggered++;
							console.log('Clicked link with payload:', link.outerHTML);
						}
					} catch (e) {
						console.log('Link click error:', e.message);
					}
				}
				
				// Also handle CSS import links (link tags with href)
				const cssLinks = document.querySelectorAll('link[href]');
				for (let link of cssLinks) {
					try {
						if (link.href.includes('` + payload + `')) {
							// For CSS import contexts, we need to trigger the link differently
							// Try clicking the link element
							link.click();
							eventsTriggered++;
							console.log('Clicked CSS link with payload:', link.outerHTML);
						}
					} catch (e) {
						console.log('CSS link click error:', e.message);
					}
				}
				
				// Also handle style tags with src attributes
				const styleTags = document.querySelectorAll('style[src]');
				for (let style of styleTags) {
					try {
						if (style.src.includes('` + payload + `')) {
							// For style src contexts, try to trigger the style element
							style.click();
							eventsTriggered++;
							console.log('Clicked style tag with payload:', style.outerHTML);
						}
					} catch (e) {
						console.log('Style tag click error:', e.message);
					}
				}
				
				return {
					eventsTriggered: eventsTriggered,
					success: eventsTriggered > 0
				};
			} catch (e) {
				return {
					eventsTriggered: 0,
					success: false,
					error: e.message
				};
			}
		}`)
		
		if err != nil {
			log.Printf("Error clicking links: %v", err)
			// Don't return false immediately, continue with other checks
		} else if result, ok := clickResult.(map[string]interface{}); ok {
			if val, exists := result["eventsTriggered"]; exists {
				if _, ok := val.(float64); ok {
					// Events were triggered
				}
			}
		}
	}

	// Wait for page to load
	time.Sleep(2 * time.Second)

	// Also check for console messages that might indicate XSS
	consoleMessages := []string{}
	b.page.On("console", func(msg playwright.ConsoleMessage) {
		consoleMessages = append(consoleMessages, msg.Text())
	})

	// Get page content to analyze context
	content, _ := b.page.Content()
	
	// Check if the payload was reflected in the page
	if strings.Contains(content, payload) {
		// For iframe srcdoc, check if it's in the srcdoc attribute
		if strings.Contains(content, "srcdoc=") && strings.Contains(content, payload) {
			// For iframe srcdoc, we need to check if the payload contains executable JavaScript
			// Even if we can't detect the alert from the parent page due to sandboxing
			executablePatterns := []string{"<script", "alert(", "eval(", "Function(", "setTimeout(", "setInterval("}
			hasExecutableCode := false
			for _, pattern := range executablePatterns {
				if strings.Contains(payload, pattern) {
					hasExecutableCode = true
					break
				}
			}
			
			if hasExecutableCode {
				// For iframe srcdoc with executable code, consider it vulnerable
				// even if we can't detect the alert due to sandboxing
				return true, nil
			}
			
			// Also try to access the iframe content for additional verification
			iframeResult, err := b.page.Evaluate(`() => {
				try {
					const iframes = document.querySelectorAll('iframe');
					for (let iframe of iframes) {
						if (iframe.srcdoc && iframe.srcdoc.includes('script')) {
							// Try to access the iframe content
							try {
								const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
								if (iframeDoc) {
									const scripts = iframeDoc.querySelectorAll('script');
									if (scripts.length > 0) {
										return true;
									}
								}
							} catch (e) {
								// Cross-origin restrictions
								return false;
							}
						}
					}
					return false;
				} catch (e) {
					return false;
				}
			}`)
			
			if err != nil {
				log.Printf("Error evaluating iframe content: %v", err)
				// Don't return false immediately, continue with other checks
			} else if iframeResult == true {
				return true, nil
			}
		}
	}

	// Check timeout before event triggering
	select {
	case <-timeoutCtx.Done():
		return false, timeoutCtx.Err()
	default:
	}

	// NEW: Enhanced event triggering for event handler contexts
	if b.triggerEventsForPayload(content, payload) {
		// Wait a bit more for any triggered events to execute
		time.Sleep(1 * time.Second) // Reduced wait time
	}

	// Check timeout before final check
	select {
	case <-timeoutCtx.Done():
		return false, timeoutCtx.Err()
	default:
	}

	// Wait a bit more to see if any alerts are triggered
	time.Sleep(3 * time.Second)
	
	
	// Check if any alerts were triggered
	return alertDetected, nil
}

// triggerEventsForPayload intelligently triggers events when event handler contexts are detected
func (b *Browser) triggerEventsForPayload(content, payload string) bool {
	// Check for event handler contexts with our payload
	eventHandlers := []string{"onclick", "onload", "onmouseover", "onerror", "onfocus", "onblur", "onchange", "oninput", "onsubmit", "onreset", "onselect", "onunload", "onbeforeunload", "onpagehide", "onpageshow", "onpopstate", "onstorage", "onmessage", "ononline", "onoffline"}
	
	hasEventHandlers := false
	for _, handler := range eventHandlers {
		// Look for event handler with flexible spacing (e.g., "onerror=" or " onerror=")
		if (strings.Contains(content, handler+"=") || strings.Contains(content, " "+handler+"=")) && strings.Contains(content, payload) {
			hasEventHandlers = true
			break
		}
	}
	
	// Check for URL contexts (javascript: and data: URLs in href attributes)
	hasURLContext := false
	if strings.HasPrefix(payload, "javascript:") || strings.HasPrefix(payload, "data:") {
		// Look for href attributes containing our payload
		if strings.Contains(content, "href=") && strings.Contains(content, payload) {
			hasURLContext = true
		}
	}
	
	
	if !hasEventHandlers && !hasURLContext {
		return false
	}
	
	// Safeguard 1: Only trigger events if payload contains suspicious patterns
	suspiciousPatterns := []string{"alert(", "eval(", "Function(", "setTimeout(", "setInterval(", "document.", "window.", "location."}
	hasSuspiciousPattern := false
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(payload, pattern) {
			hasSuspiciousPattern = true
			break
		}
	}
	
	if !hasSuspiciousPattern {
		return false
	}
	
	log.Printf("Detected event handler context with payload: %s", payload)
	
	// Simplified event triggering - limited to prevent hanging
	triggerResult, err := b.page.Evaluate(`() => {
		try {
			let eventsTriggered = 0;
			
			// Only click elements that likely contain our payload (more targeted approach)
			const elements = document.querySelectorAll('button, div[onclick], a[href], img[onerror], input[onfocus]');
			for (let element of elements) {
				try {
					// Only trigger if element contains our payload
					if (element.outerHTML.includes('` + payload + `')) {
						element.click();
						eventsTriggered++;
						console.log('Clicked element with payload:', element.outerHTML);
					}
				} catch (e) {
					console.log('Element click error:', e.message);
				}
			}
			
			// Limit to first 10 elements to prevent hanging
			if (eventsTriggered > 10) {
				eventsTriggered = 10;
			}
			
			return {
				eventsTriggered: eventsTriggered,
				success: eventsTriggered > 0
			};
		} catch (e) {
			return {
				eventsTriggered: 0,
				success: false,
				error: e.message
			};
		}
	}`)
	
	if err != nil {
		log.Printf("Error triggering events: %v", err)
		return false
	}
	
	// Check if events were triggered
	if result, ok := triggerResult.(map[string]interface{}); ok {
		eventsTriggered := 0
		
		if val, exists := result["eventsTriggered"]; exists {
			if v, ok := val.(float64); ok {
				eventsTriggered = int(v)
			}
		}
		
		log.Printf("Event triggering: %d events triggered", eventsTriggered)
		
		// Return true if we triggered any events
		return eventsTriggered > 0
	}
	
	return false
}

// TestDOMCookieEval navigates to a URL after setting cookies via headers (and optionally in-page),
// then waits briefly to detect alert() from DOM-based sinks like eval(document.cookie).
func (b *Browser) TestDOMCookieEval(ctx context.Context, targetURL string, headers map[string]string, setCookieInPage string) (bool, error) {
	// Use instance-specific mutex to prevent conflicts within this browser instance
	b.mu.Lock()
	defer b.mu.Unlock()

	// Timeout scope
	timeoutCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	alertDetected := false

	// Apply extra HTTP headers (including Cookie) if provided
	if headers != nil && len(headers) > 0 {
		if err := b.context.SetExtraHTTPHeaders(headers); err != nil {
		}
	}

	// Dialog handler
	b.page.On("dialog", func(dialog playwright.Dialog) {
		alertDetected = true
		dialog.Dismiss()
	})

	// Navigate
	_, err := b.page.Goto(targetURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:    playwright.Float(60000),
	})
	if err != nil {
		return false, err
	}

	// Optional in-page cookie set then reload
	if setCookieInPage != "" {
		// Support multiple cookies separated by newlines
		cookies := strings.Split(setCookieInPage, "\n")
		for _, c := range cookies {
			c = strings.TrimSpace(c)
			if c == "" { continue }
			_, _ = b.page.Evaluate("(c)=>{document.cookie=c}", c)
		}
		_, _ = b.page.Reload()
	}

	// Wait a bit for any DOM-triggered sinks
	select {
	case <-time.After(3 * time.Second):
	case <-timeoutCtx.Done():
	}
	return alertDetected, nil
}

// Close closes the browser
func (b *Browser) Close() error {
	if b == nil {
		return nil
	}

	// Add panic recovery for browser cleanup
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from browser cleanup panic: %v", r)
		}
	}()

	if b.page != nil {
		b.page.Close()
	}
	if b.context != nil {
		b.context.Close()
	}
	if b.browser != nil {
		b.browser.Close()
	}
	if b.pw != nil {
		b.pw.Stop()
	}

	return nil
}
