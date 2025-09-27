package parser

import (
	"regexp"
	"strings"
)

// HTMLParser parses HTML content to extract parameters
type HTMLParser struct {
	// Hidden input parameters
	hiddenParamRegex *regexp.Regexp
	
	// JavaScript parameters
	jsVarRegex       *regexp.Regexp
	jsFunctionRegex  *regexp.Regexp
	jsUrlRegex       *regexp.Regexp
	jsLocationRegex  *regexp.Regexp
	
	// Form parameters
	formInputRegex   *regexp.Regexp
	formSelectRegex  *regexp.Regexp
	formTextareaRegex *regexp.Regexp
	
	// URL parameters in JavaScript
	urlParamRegex    *regexp.Regexp
	queryParamRegex  *regexp.Regexp
	
	// AJAX/API parameters
	ajaxParamRegex   *regexp.Regexp
	apiParamRegex    *regexp.Regexp
	
	// Data attributes
	dataAttrRegex    *regexp.Regexp
	
	// Meta tags
	metaParamRegex   *regexp.Regexp
	
	// Comments
	commentParamRegex *regexp.Regexp
	
	// Enhanced link extraction
	hrefRegex        *regexp.Regexp
	linkRegex        *regexp.Regexp
	anchorRegex      *regexp.Regexp
	
	// JavaScript variable extraction for parameter testing
	jsVarNameRegex   *regexp.Regexp
	jsParamRegex     *regexp.Regexp
	
	// Additional parameter sources
	jsonObjectRegex  *regexp.Regexp
	urlPathRegex     *regexp.Regexp
	cookieRegex      *regexp.Regexp
	storageRegex     *regexp.Regexp
	websocketRegex   *regexp.Regexp
	cssUrlRegex      *regexp.Regexp
	templateVarRegex *regexp.Regexp
}

// NewHTMLParser creates a new HTML parser with comprehensive parameter discovery
func NewHTMLParser() *HTMLParser {
	return &HTMLParser{
		// Hidden input parameters
		hiddenParamRegex: regexp.MustCompile(`<input[^>]*type=["']hidden["'][^>]*name=["']([^"']+)["'][^>]*>`),
		
		// JavaScript variables and functions
		jsVarRegex:      regexp.MustCompile(`(?:var|let|const)\s+(\w+)\s*=\s*[^;]+`),
		jsFunctionRegex: regexp.MustCompile(`function\s+(\w+)\s*\([^)]*\)`),
		jsUrlRegex:      regexp.MustCompile(`(?:url|href|src)\s*[:=]\s*["']([^"']*[?&][^"']*=)["']`),
		jsLocationRegex: regexp.MustCompile(`(?:window\.)?location\.(?:search|hash)\s*[:=]\s*["']([^"']*)["']`),
		
		// Form parameters
		formInputRegex:   regexp.MustCompile(`<input[^>]*name=["']([^"']+)["'][^>]*>`),
		formSelectRegex:  regexp.MustCompile(`<select[^>]*name=["']([^"']+)["'][^>]*>`),
		formTextareaRegex: regexp.MustCompile(`<textarea[^>]*name=["']([^"']+)["'][^>]*>`),
		
		// URL parameters in JavaScript
		urlParamRegex:   regexp.MustCompile(`(?:URLSearchParams|new URL|parseQueryString)\s*\([^)]*\)`),
		queryParamRegex: regexp.MustCompile(`[?&](\w+)=[^&\s]*`),
		
		// AJAX/API parameters
		ajaxParamRegex:  regexp.MustCompile(`(?:fetch|XMLHttpRequest|axios|jQuery\.ajax)\s*\([^)]*["']([^"']*[?&][^"']*=)["']`),
		apiParamRegex:   regexp.MustCompile(`/api/[^/]*\?([^"'\s]*)`),
		
		// Data attributes
		dataAttrRegex:   regexp.MustCompile(`data-(\w+)=["']([^"']+)["']`),
		
		// Meta tags
		metaParamRegex:  regexp.MustCompile(`<meta[^>]*name=["']([^"']+)["'][^>]*content=["']([^"']+)["'][^>]*>`),
		
		// Comments
		commentParamRegex: regexp.MustCompile(`<!--\s*([^>]*parameter[^>]*)\s*-->`),
		
		// Enhanced link extraction - more specific to avoid HTML tag content
		hrefRegex:      regexp.MustCompile(`href\s*=\s*["']([^"']*(?:https?://[^"']*|[^"']*\.(?:html|php|asp|jsp|js|css|xml|json|api|rest)[^"']*))["']`),
		linkRegex:      regexp.MustCompile(`<link[^>]*href\s*=\s*["']([^"']*(?:https?://[^"']*|[^"']*\.(?:html|php|asp|jsp|js|css|xml|json|api|rest)[^"']*))["'][^>]*>`),
		anchorRegex:    regexp.MustCompile(`<a[^>]*href\s*=\s*["']([^"']*(?:https?://[^"']*|[^"']*\.(?:html|php|asp|jsp|js|css|xml|json|api|rest)[^"']*))["'][^>]*>`),
		
		// JavaScript variable extraction for parameter testing
		jsVarNameRegex: regexp.MustCompile(`(?:var|let|const)\s+(\w+)\s*[=;]`),
		jsParamRegex:   regexp.MustCompile(`(\w+)\s*[:=]\s*[^,\s]+`),
		
		// Additional parameter sources
		jsonObjectRegex:  regexp.MustCompile(`(\w+)\s*:\s*\{`),
		urlPathRegex:     regexp.MustCompile(`/([^/]+)`),
		cookieRegex:      regexp.MustCompile(`document\.cookie\s*=\s*["']([^"']+)["']`),
		storageRegex:     regexp.MustCompile(`localStorage\.getItem\s*\("([^"']+)"\)`),
		websocketRegex:   regexp.MustCompile(`WebSocket\s*=\s*new\s*WebSocket\s*\("([^"']+)"\)`),
		cssUrlRegex:      regexp.MustCompile(`url\s*\(\s*["']([^"']+)["']\)`),
		templateVarRegex: regexp.MustCompile(`\{\{\s*(\w+)\s*\}\}`),
	}
}

// ExtractHiddenParameters finds hidden input parameters in HTML
func (p *HTMLParser) ExtractHiddenParameters(content string) []string {
	var params []string
	matches := p.hiddenParamRegex.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	
	return params
}

// ExtractJavaScriptParameters finds JavaScript variables and functions that might be parameters
func (p *HTMLParser) ExtractJavaScriptParameters(content string) []string {
	var params []string
	
	// Extract JavaScript variables
	jsVarMatches := p.jsVarRegex.FindAllStringSubmatch(content, -1)
	for _, match := range jsVarMatches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	
	// Extract JavaScript functions
	jsFuncMatches := p.jsFunctionRegex.FindAllStringSubmatch(content, -1)
	for _, match := range jsFuncMatches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	
	// Extract URL parameters from JavaScript
	jsUrlMatches := p.jsUrlRegex.FindAllStringSubmatch(content, -1)
	for _, match := range jsUrlMatches {
		if len(match) > 1 {
			// Extract parameter names from URL
			urlParams := p.extractParamsFromURL(match[1])
			params = append(params, urlParams...)
		}
	}
	
	// Extract location parameters
	jsLocationMatches := p.jsLocationRegex.FindAllStringSubmatch(content, -1)
	for _, match := range jsLocationMatches {
		if len(match) > 1 {
			urlParams := p.extractParamsFromURL(match[1])
			params = append(params, urlParams...)
		}
	}
	
	return params
}

// ExtractFormParameters finds all form input parameters
func (p *HTMLParser) ExtractFormParameters(content string) []string {
	var params []string
	
	// Find all input elements
	inputMatches := p.formInputRegex.FindAllStringSubmatch(content, -1)
	for _, match := range inputMatches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	
	// Find select elements
	selectMatches := p.formSelectRegex.FindAllStringSubmatch(content, -1)
	for _, match := range selectMatches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	
	// Find textarea elements
	textareaMatches := p.formTextareaRegex.FindAllStringSubmatch(content, -1)
	for _, match := range textareaMatches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	
	return params
}

// ExtractURLParameters finds parameters in URLs within the content
func (p *HTMLParser) ExtractURLParameters(content string) []string {
	var params []string
	
	// Find URLs in the content
	urlRegex := regexp.MustCompile(`https?://[^\s"']*[?&][^\s"']*`)
	urlMatches := urlRegex.FindAllString(content, -1)
	
	for _, url := range urlMatches {
		urlParams := p.extractParamsFromURL(url)
		params = append(params, urlParams...)
	}
	
	return params
}

// ExtractAJAXParameters finds parameters in AJAX calls
func (p *HTMLParser) ExtractAJAXParameters(content string) []string {
	var params []string
	
	// Find AJAX calls
	ajaxMatches := p.ajaxParamRegex.FindAllStringSubmatch(content, -1)
	for _, match := range ajaxMatches {
		if len(match) > 1 {
			urlParams := p.extractParamsFromURL(match[1])
			params = append(params, urlParams...)
		}
	}
	
	// Find API endpoints
	apiMatches := p.apiParamRegex.FindAllStringSubmatch(content, -1)
	for _, match := range apiMatches {
		if len(match) > 1 {
			urlParams := p.extractParamsFromURL(match[1])
			params = append(params, urlParams...)
		}
	}
	
	return params
}

// ExtractDataAttributes finds parameters in data attributes
func (p *HTMLParser) ExtractDataAttributes(content string) []string {
	var params []string
	
	dataMatches := p.dataAttrRegex.FindAllStringSubmatch(content, -1)
	for _, match := range dataMatches {
		if len(match) > 2 {
			params = append(params, match[1])
		}
	}
	
	return params
}

// ExtractMetaParameters finds parameters in meta tags
func (p *HTMLParser) ExtractMetaParameters(content string) []string {
	var params []string
	
	metaMatches := p.metaParamRegex.FindAllStringSubmatch(content, -1)
	for _, match := range metaMatches {
		if len(match) > 2 {
			params = append(params, match[1])
		}
	}
	
	return params
}

// ExtractCommentParameters finds parameters mentioned in HTML comments
func (p *HTMLParser) ExtractCommentParameters(content string) []string {
	var params []string
	
	commentMatches := p.commentParamRegex.FindAllStringSubmatch(content, -1)
	for _, match := range commentMatches {
		if len(match) > 1 {
			// Extract parameter names from comments
			paramRegex := regexp.MustCompile(`(\w+)\s*[:=]\s*[^,\s]+`)
			paramMatches := paramRegex.FindAllStringSubmatch(match[1], -1)
			for _, paramMatch := range paramMatches {
				if len(paramMatch) > 1 {
					params = append(params, paramMatch[1])
				}
			}
		}
	}
	
	return params
}

// ExtractEndpointsFromLinks finds endpoints and parameters from href tags and links
func (p *HTMLParser) ExtractEndpointsFromLinks(content string) []string {
	var endpoints []string
	
	// Extract all href attributes
	hrefMatches := p.hrefRegex.FindAllStringSubmatch(content, -1)
	for _, match := range hrefMatches {
		if len(match) > 1 {
			href := match[1]
			
			// Skip if this looks like HTML tag content or test data
			if strings.Contains(href, "XSS_TEST_") || 
			   strings.Contains(href, "=") && !strings.Contains(href, "?") ||
			   len(href) < 3 {
				continue
			}
			
			// Extract parameters from href URLs
			urlParams := p.extractParamsFromURL(href)
			endpoints = append(endpoints, urlParams...)
			
			// Also add the endpoint path itself
			if strings.Contains(href, "?") {
				// Extract the path before query parameters
				if idx := strings.Index(href, "?"); idx != -1 {
					path := href[:idx]
					if strings.HasPrefix(path, "/") || strings.HasPrefix(path, "http") {
						endpoints = append(endpoints, path)
					}
				}
			} else if strings.HasPrefix(href, "/") || strings.HasPrefix(href, "http") {
				endpoints = append(endpoints, href)
			}
		}
	}
	
	// Extract from anchor tags specifically
	anchorMatches := p.anchorRegex.FindAllStringSubmatch(content, -1)
	for _, match := range anchorMatches {
		if len(match) > 1 {
			href := match[1]
			urlParams := p.extractParamsFromURL(href)
			endpoints = append(endpoints, urlParams...)
		}
	}
	
	// Extract from link tags
	linkMatches := p.linkRegex.FindAllStringSubmatch(content, -1)
	for _, match := range linkMatches {
		if len(match) > 1 {
			href := match[1]
			urlParams := p.extractParamsFromURL(href)
			endpoints = append(endpoints, urlParams...)
		}
	}
	
	return endpoints
}

// ExtractJSONObjectParameters finds parameters in JavaScript object literals
func (p *HTMLParser) ExtractJSONObjectParameters(content string) []string {
	var params []string
	
	// Find object property names
	objectRegex := regexp.MustCompile(`(\w+)\s*:\s*["'][^"']*["']`)
	objectMatches := objectRegex.FindAllStringSubmatch(content, -1)
	for _, match := range objectMatches {
		if len(match) > 1 {
			paramName := match[1]
			if !p.isJavaScriptKeyword(paramName) {
				params = append(params, paramName)
			}
		}
	}
	
	// Find nested object properties
	nestedRegex := regexp.MustCompile(`(\w+)\s*:\s*\{[^}]*\}`)
	nestedMatches := nestedRegex.FindAllStringSubmatch(content, -1)
	for _, match := range nestedMatches {
		if len(match) > 1 {
			paramName := match[1]
			if !p.isJavaScriptKeyword(paramName) {
				params = append(params, paramName)
			}
		}
	}
	
	return params
}

// ExtractURLPathParameters finds parameters in URL paths
func (p *HTMLParser) ExtractURLPathParameters(content string) []string {
	var params []string
	
	// Find URL paths with potential parameters
	pathRegex := regexp.MustCompile(`/([^/?]+)/([^/?]+)`)
	pathMatches := pathRegex.FindAllStringSubmatch(content, -1)
	for _, match := range pathMatches {
		if len(match) > 2 {
			// Add path segments as potential parameters
			params = append(params, match[1], match[2])
		}
	}
	
	// Find REST-style parameters in paths
	restRegex := regexp.MustCompile(`/\{([^}]+)\}`)
	restMatches := restRegex.FindAllStringSubmatch(content, -1)
	for _, match := range restMatches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	
	return params
}

// ExtractCookieParameters finds parameters in cookie operations
func (p *HTMLParser) ExtractCookieParameters(content string) []string {
	var params []string
	
	// Find cookie assignments
	cookieAssignRegex := regexp.MustCompile(`document\.cookie\s*=\s*["']([^"']+)["']`)
	cookieMatches := cookieAssignRegex.FindAllStringSubmatch(content, -1)
	for _, match := range cookieMatches {
		if len(match) > 1 {
			cookieStr := match[1]
			// Extract cookie names
			cookieNameRegex := regexp.MustCompile(`(\w+)=`)
			cookieNameMatches := cookieNameRegex.FindAllStringSubmatch(cookieStr, -1)
			for _, cookieMatch := range cookieNameMatches {
				if len(cookieMatch) > 1 {
					params = append(params, cookieMatch[1])
				}
			}
		}
	}
	
	// Find cookie reading
	cookieReadRegex := regexp.MustCompile(`document\.cookie\.split\s*\(["']([^"']+)["']\)`)
	cookieReadMatches := cookieReadRegex.FindAllStringSubmatch(content, -1)
	for _, match := range cookieReadMatches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	
	return params
}

// ExtractStorageParameters finds parameters in localStorage/sessionStorage operations
func (p *HTMLParser) ExtractStorageParameters(content string) []string {
	var params []string
	
	// Find localStorage operations
	localStorageRegex := regexp.MustCompile(`localStorage\.(?:getItem|setItem)\s*\(["']([^"']+)["']`)
	localStorageMatches := localStorageRegex.FindAllStringSubmatch(content, -1)
	for _, match := range localStorageMatches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	
	// Find sessionStorage operations
	sessionStorageRegex := regexp.MustCompile(`sessionStorage\.(?:getItem|setItem)\s*\(["']([^"']+)["']`)
	sessionStorageMatches := sessionStorageRegex.FindAllStringSubmatch(content, -1)
	for _, match := range sessionStorageMatches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	
	return params
}

// ExtractWebSocketParameters finds parameters in WebSocket URLs
func (p *HTMLParser) ExtractWebSocketParameters(content string) []string {
	var params []string
	
	// Find WebSocket connections
	wsRegex := regexp.MustCompile(`new\s+WebSocket\s*\(["']([^"']+)["']`)
	wsMatches := wsRegex.FindAllStringSubmatch(content, -1)
	for _, match := range wsMatches {
		if len(match) > 1 {
			wsUrl := match[1]
			// Extract parameters from WebSocket URL
			urlParams := p.extractParamsFromURL(wsUrl)
			params = append(params, urlParams...)
		}
	}
	
	return params
}

// ExtractCSSURLParameters finds parameters in CSS URL references
func (p *HTMLParser) ExtractCSSURLParameters(content string) []string {
	var params []string
	
	// Find CSS url() functions
	cssUrlRegex := regexp.MustCompile(`url\s*\(\s*["']([^"']+)["']\s*\)`)
	cssUrlMatches := cssUrlRegex.FindAllStringSubmatch(content, -1)
	for _, match := range cssUrlMatches {
		if len(match) > 1 {
			cssUrl := match[1]
			// Extract parameters from CSS URL
			urlParams := p.extractParamsFromURL(cssUrl)
			params = append(params, urlParams...)
		}
	}
	
	// Find background-image URLs
	bgUrlRegex := regexp.MustCompile(`background-image:\s*url\s*\(\s*["']([^"']+)["']\s*\)`)
	bgUrlMatches := bgUrlRegex.FindAllStringSubmatch(content, -1)
	for _, match := range bgUrlMatches {
		if len(match) > 1 {
			bgUrl := match[1]
			urlParams := p.extractParamsFromURL(bgUrl)
			params = append(params, urlParams...)
		}
	}
	
	return params
}

// ExtractTemplateVariables finds server-side template variables
func (p *HTMLParser) ExtractTemplateVariables(content string) []string {
	var params []string
	
	// Find various template syntax patterns
	templatePatterns := []*regexp.Regexp{
		regexp.MustCompile(`\{\{\s*(\w+)\s*\}\}`),           // Handlebars/Mustache
		regexp.MustCompile(`\$\{(\w+)\}`),                   // ES6 template literals
		regexp.MustCompile(`<%=\s*(\w+)\s*%>`),             // ERB/EJS
		regexp.MustCompile(`\$\{(\w+)\}`),                   // PHP variables
		regexp.MustCompile(`@(\w+)`),                        // Razor/Blade
		regexp.MustCompile(`\{\s*(\w+)\s*\}`),              // Jinja2/Twig
	}
	
	for _, pattern := range templatePatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				params = append(params, match[1])
			}
		}
	}
	
	return params
}

// ExtractJavaScriptVariablesAsParameters finds JavaScript variable names and treats them as potential parameters
func (p *HTMLParser) ExtractJavaScriptVariablesAsParameters(content string) []string {
	var params []string
	
	// Extract JavaScript variable names
	jsVarMatches := p.jsVarNameRegex.FindAllStringSubmatch(content, -1)
	for _, match := range jsVarMatches {
		if len(match) > 1 {
			varName := match[1]
			// Filter out common JavaScript keywords and built-in objects
			if !p.isJavaScriptKeyword(varName) {
				params = append(params, varName)
			}
		}
	}
	
	// Extract parameters from JavaScript object literals
	jsParamMatches := p.jsParamRegex.FindAllStringSubmatch(content, -1)
	for _, match := range jsParamMatches {
		if len(match) > 1 {
			paramName := match[1]
			if !p.isJavaScriptKeyword(paramName) {
				params = append(params, paramName)
			}
		}
	}
	
	// Extract from function parameters
	funcParamRegex := regexp.MustCompile(`function\s*\w*\s*\(([^)]*)\)`)
	funcMatches := funcParamRegex.FindAllStringSubmatch(content, -1)
	for _, match := range funcMatches {
		if len(match) > 1 {
			paramsStr := match[1]
			// Split by comma and extract parameter names
			paramList := strings.Split(paramsStr, ",")
			for _, param := range paramList {
				param = strings.TrimSpace(param)
				if param != "" && !p.isJavaScriptKeyword(param) {
					params = append(params, param)
				}
			}
		}
	}
	
	return params
}

// ExtractEndpointsFromJavaScript finds endpoints mentioned in JavaScript code
func (p *HTMLParser) ExtractEndpointsFromJavaScript(content string) []string {
	var endpoints []string
	
	// Find URLs in JavaScript strings
	jsUrlRegex := regexp.MustCompile(`["']([^"']*\.(?:php|asp|aspx|jsp|html|htm|js|css|json|xml|api|rest|graphql)[^"']*)["']`)
	jsUrlMatches := jsUrlRegex.FindAllStringSubmatch(content, -1)
	for _, match := range jsUrlMatches {
		if len(match) > 1 {
			url := match[1]
			urlParams := p.extractParamsFromURL(url)
			endpoints = append(endpoints, urlParams...)
		}
	}
	
	// Find API endpoints
	apiEndpointRegex := regexp.MustCompile(`["'](/api/[^"']*)["']`)
	apiMatches := apiEndpointRegex.FindAllStringSubmatch(content, -1)
	for _, match := range apiMatches {
		if len(match) > 1 {
			endpoint := match[1]
			urlParams := p.extractParamsFromURL(endpoint)
			endpoints = append(endpoints, urlParams...)
		}
	}
	
	// Find fetch/axios calls
	fetchRegex := regexp.MustCompile(`(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["']([^"']+)["']`)
	fetchMatches := fetchRegex.FindAllStringSubmatch(content, -1)
	for _, match := range fetchMatches {
		if len(match) > 1 {
			url := match[1]
			urlParams := p.extractParamsFromURL(url)
			endpoints = append(endpoints, urlParams...)
		}
	}
	
	return endpoints
}

// isJavaScriptKeyword checks if a string is a JavaScript keyword
func (p *HTMLParser) isJavaScriptKeyword(word string) bool {
	keywords := map[string]bool{
		"abstract": true, "arguments": true, "await": true, "boolean": true,
		"break": true, "byte": true, "case": true, "catch": true,
		"char": true, "class": true, "const": true, "continue": true,
		"debugger": true, "default": true, "delete": true, "do": true,
		"double": true, "else": true, "enum": true, "eval": true,
		"export": true, "extends": true, "false": true, "final": true,
		"finally": true, "float": true, "for": true, "function": true,
		"goto": true, "if": true, "implements": true, "import": true,
		"in": true, "instanceof": true, "int": true, "interface": true,
		"let": true, "long": true, "native": true, "new": true,
		"null": true, "package": true, "private": true, "protected": true,
		"public": true, "return": true, "short": true, "static": true,
		"super": true, "switch": true, "synchronized": true, "this": true,
		"throw": true, "throws": true, "transient": true, "true": true,
		"try": true, "typeof": true, "var": true, "void": true,
		"volatile": true, "while": true, "with": true, "yield": true,
		"undefined": true, "NaN": true, "Infinity": true,
		// Common built-in objects
		"Object": true, "Array": true, "String": true, "Number": true,
		"Boolean": true, "Date": true, "RegExp": true, "Function": true,
		"Math": true, "JSON": true, "console": true, "window": true,
		"document": true, "location": true, "history": true, "navigator": true,
		"screen": true, "localStorage": true, "sessionStorage": true,
	}
	
	return keywords[word]
}

// ExtractAllParameters finds all types of parameters in the content
func (p *HTMLParser) ExtractAllParameters(content string) []string {
	var allParams []string
	paramMap := make(map[string]bool) // To avoid duplicates
	
	// Extract all types of parameters
	paramTypes := [][]string{
		p.ExtractHiddenParameters(content),
		p.ExtractJavaScriptParameters(content),
		p.ExtractFormParameters(content),
		p.ExtractURLParameters(content),
		p.ExtractAJAXParameters(content),
		p.ExtractDataAttributes(content),
		p.ExtractMetaParameters(content),
		p.ExtractCommentParameters(content),
		p.ExtractEndpointsFromLinks(content),
		p.ExtractJavaScriptVariablesAsParameters(content),
		p.ExtractEndpointsFromJavaScript(content),
		p.ExtractJSONObjectParameters(content),
		p.ExtractURLPathParameters(content),
		p.ExtractCookieParameters(content),
		p.ExtractStorageParameters(content),
		p.ExtractWebSocketParameters(content),
		p.ExtractCSSURLParameters(content),
		p.ExtractTemplateVariables(content),
	}
	
	// Combine all parameters and remove duplicates
	for _, params := range paramTypes {
		for _, param := range params {
			if !paramMap[param] {
				paramMap[param] = true
				allParams = append(allParams, param)
			}
		}
	}
	
	return allParams
}

// extractParamsFromURL extracts parameter names from a URL
func (p *HTMLParser) extractParamsFromURL(url string) []string {
	var params []string
	
	// Find query parameters
	queryMatches := p.queryParamRegex.FindAllStringSubmatch(url, -1)
	for _, match := range queryMatches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	
	return params
}

// ExtractParametersFromMultipleSources extracts parameters from multiple sources
func (p *HTMLParser) ExtractParametersFromMultipleSources(content string) []string {
	// Normalize content
	content = strings.ToLower(content)
	
	// Only extract from legitimate parameter sources - NOT HTML attributes or CSS
	var allParams []string
	paramMap := make(map[string]bool) // To avoid duplicates
	
	// Extract only from form elements and JavaScript variables
	paramTypes := [][]string{
		p.ExtractHiddenParameters(content),      // Hidden form inputs
		p.ExtractFormParameters(content),        // Regular form inputs, selects, textareas
		p.ExtractJavaScriptParameters(content),  // JavaScript variables and functions
		p.ExtractURLParameters(content),         // URL parameters in JavaScript
		p.ExtractAJAXParameters(content),        // AJAX/API parameters
		p.ExtractDataAttributes(content),        // Data attributes (legitimate parameters)
		p.ExtractMetaParameters(content),        // Meta tags (legitimate parameters)
		p.ExtractCommentParameters(content),     // Comments (legitimate parameters)
		p.ExtractJavaScriptVariablesAsParameters(content), // JavaScript variables
		p.ExtractJSONObjectParameters(content),  // JSON object parameters
		p.ExtractCookieParameters(content),      // Cookie parameters
		p.ExtractStorageParameters(content),     // Storage parameters
		p.ExtractTemplateVariables(content),     // Template variables
	}
	
	// Combine all parameters and remove duplicates
	for _, params := range paramTypes {
		for _, param := range params {
			if !paramMap[param] {
				paramMap[param] = true
				allParams = append(allParams, param)
			}
		}
	}
	
	// Additional pattern matching for common parameter patterns (but not HTML/CSS attributes)
	additionalPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(\w+)_id\b`),
		regexp.MustCompile(`(\w+)_token\b`),
		regexp.MustCompile(`(\w+)_key\b`),
		regexp.MustCompile(`(\w+)_value\b`),
		regexp.MustCompile(`(\w+)_param\b`),
		regexp.MustCompile(`(\w+)_data\b`),
		regexp.MustCompile(`(\w+)_input\b`),
		regexp.MustCompile(`(\w+)_field\b`),
		// Additional patterns for endpoints and API parameters
		regexp.MustCompile(`(\w+)_endpoint\b`),
		regexp.MustCompile(`(\w+)_url\b`),
		regexp.MustCompile(`(\w+)_path\b`),
		regexp.MustCompile(`(\w+)_route\b`),
		regexp.MustCompile(`(\w+)_action\b`),
		regexp.MustCompile(`(\w+)_method\b`),
		regexp.MustCompile(`(\w+)_controller\b`),
		// Additional patterns for common parameter types
		regexp.MustCompile(`(\w+)_name\b`),
		regexp.MustCompile(`(\w+)_email\b`),
		regexp.MustCompile(`(\w+)_password\b`),
		regexp.MustCompile(`(\w+)_username\b`),
		regexp.MustCompile(`(\w+)_session\b`),
		regexp.MustCompile(`(\w+)_auth\b`),
		regexp.MustCompile(`(\w+)_api\b`),
		regexp.MustCompile(`(\w+)_secret\b`),
		regexp.MustCompile(`(\w+)_hash\b`),
		regexp.MustCompile(`(\w+)_salt\b`),
		regexp.MustCompile(`(\w+)_nonce\b`),
		regexp.MustCompile(`(\w+)_signature\b`),
		regexp.MustCompile(`(\w+)_timestamp\b`),
		regexp.MustCompile(`(\w+)_uuid\b`),
		regexp.MustCompile(`(\w+)_guid\b`),
	}
	
	for _, pattern := range additionalPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 && !paramMap[match[1]] {
				paramMap[match[1]] = true
				allParams = append(allParams, match[1])
			}
		}
	}
	
	// Remove duplicates and common non-parameter words
	return p.filterParameters(allParams)
}

// filterParameters removes duplicates and common non-parameter words
func (p *HTMLParser) filterParameters(params []string) []string {
	paramMap := make(map[string]bool)
	var filteredParams []string
	
	// Common words to exclude
	excludeWords := map[string]bool{
		// JavaScript keywords
		"function": true, "var": true, "let": true, "const": true,
		"if": true, "else": true, "for": true, "while": true,
		"return": true, "true": true, "false": true, "null": true,
		"undefined": true, "this": true, "self": true,
		"document": true, "window": true, "location": true,
		"href": true, "src": true, "url": true, "path": true,
		"type": true, "name": true, "id": true, "class": true,
		"style": true, "title": true, "alt": true, "value": true,
		"method": true, "action": true, "form": true, "input": true,
		"button": true, "submit": true, "reset": true,
		"div": true, "span": true, "p": true, "a": true, "img": true,
		"script": true, "link": true, "meta": true,
		"head": true, "body": true, "html": true,
		// Additional HTML tag names and attributes
		"tag": true, "br": true, "hr": true, "li": true, "ul": true, "ol": true,
		"table": true, "tr": true, "td": true, "th": true, "thead": true, "tbody": true,
		"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
		"strong": true, "em": true, "b": true, "i": true, "u": true,
		"label": true, "option": true, "select": true, "textarea": true,
		"fieldset": true, "legend": true, "caption": true, "colgroup": true,
		"col": true, "tfoot": true,
		// HTML attributes
		"width": true, "height": true, "border": true, "cellpadding": true, "cellspacing": true,
		"align": true, "valign": true, "bgcolor": true, "color": true,
		"size": true, "maxlength": true, "readonly": true, "disabled": true,
		"checked": true, "selected": true, "multiple": true, "required": true,
		"placeholder": true, "pattern": true, "min": true, "max": true, "step": true,
		"autocomplete": true, "autofocus": true, "novalidate": true,
		// CSS properties
		"margin": true, "padding": true, "background": true, "radius": true,
		"display": true, "decoration": true, "vulnerability": true, "output": true,
		"payloads": true, "breakout": true, "onerror": true, "onload": true,
		"onmouseover": true, "onclick": true, "onfocus": true, "onblur": true,
		"onchange": true, "oninput": true, "onsubmit": true, "onreset": true,
		"onselect": true, "onunload": true, "onbeforeunload": true, "onpagehide": true,
		"onpageshow": true, "onpopstate": true, "onstorage": true, "onmessage": true,
		"ononline": true, "onoffline": true, "viewport": true, "lang": true,
		"charset": true, "content": true, "scale": true, "family": true,
		// Test data patterns
		"xss_test": true, "test": true,
	}
	
	for _, param := range params {
		// Skip if already seen or is a common word
		if !paramMap[param] && !excludeWords[param] && len(param) > 1 {
			// Skip if parameter contains HTML tag fragments or test data
			if strings.Contains(param, ">") || 
			   strings.Contains(param, "<") || 
			   strings.Contains(param, "XSS_TEST_") ||
			   strings.Contains(param, "body") && strings.Contains(param, ">") ||
			   strings.Contains(param, "tag") {
				continue
			}
			paramMap[param] = true
			filteredParams = append(filteredParams, param)
		}
	}
	
	return filteredParams
}
