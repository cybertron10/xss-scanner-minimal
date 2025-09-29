package scanner

import (
	"time"
)

// Config holds scanner configuration
type Config struct {
	URL              string
	Headers          map[string]string
	Quiet            bool
	Headless         bool
	FastMode         bool
	UltraFast        bool // Skip character analysis entirely for maximum speed
	Timeout          time.Duration
	// WAF detection flags (set by server once per host)
	WAFDetected      bool
	WAFName          string
	// Arjun parameter discovery
	UseArjun         bool
}

// ScanResult represents the result of an XSS scan
type ScanResult struct {
	URL                string                 `json:"url"`
	Timestamp          time.Time              `json:"timestamp"`
	Success            bool                   `json:"success"`
	Error              string                 `json:"error,omitempty"`
	ParametersTested   int                    `json:"parameters_tested"`
	VulnerabilitiesFound int                  `json:"vulnerabilities_found"`
	ParametersFound    []string               `json:"parameters_found"`
	Vulnerabilities    []Vulnerability        `json:"vulnerabilities"`
	ReflectingParams   []string               `json:"reflecting_parameters"`
	SkippedParams      []string               `json:"skipped_parameters"`
	ScanDuration       time.Duration          `json:"scan_duration"`
	// WAF metadata
	WAFDetected        bool                   `json:"waf_detected"`
	WAFName            string                 `json:"waf_name,omitempty"`
}

// Vulnerability represents an XSS vulnerability
type Vulnerability struct {
	Parameter              string   `json:"parameter"`
	Context                string   `json:"context"`
	WorkingPayloads        []string `json:"working_payloads"`
	ExploitURL             string   `json:"exploit_url"`
	Method                 string   `json:"method"` // GET, POST, etc.
	IsDirectlyExploitable  bool     `json:"is_directly_exploitable"`
	ManualInterventionRequired bool `json:"manual_intervention_required"`
	Confidence             string   `json:"confidence"`
}

// Parameter represents a discovered parameter
type Parameter struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // query, body, header, etc.
	Reflects bool   `json:"reflects"`
	Context  string `json:"context,omitempty"`
}

// ReflectionContext represents where and how a parameter reflects
type ReflectionContext struct {
	Parameter string `json:"parameter"`
	Context   string `json:"context"` // html_body, html_attribute, javascript, etc.
	Location  string `json:"location"` // where in the response it reflects
	Sanitized bool   `json:"sanitized"`
}

// PayloadResult represents the result of testing a payload
type PayloadResult struct {
	Payload       string `json:"payload"`
	AlertDetected bool   `json:"alert_detected"`
	Context       string `json:"context"`
	Working       bool   `json:"working"`
}

// HTMLContext represents the context where XSS reflection occurs
type HTMLContext string

const (
	ContextHTMLBody      HTMLContext = "html_body"
	ContextHTMLAttribute HTMLContext = "html_attribute"
	ContextHTMLTitle     HTMLContext = "html_title"
	ContextHTMLComment   HTMLContext = "html_comment"
	ContextJavaScript    HTMLContext = "javascript"
	ContextCSS           HTMLContext = "css"
	ContextURL           HTMLContext = "url"
	ContextDOM           HTMLContext = "dom"
	
	// Additional context types from original Python tool
	ContextDOMDocumentWriteln HTMLContext = "dom_document_writeln"
	ContextDOMBased           HTMLContext = "dom_based"
	ContextHTMLEscaped        HTMLContext = "html_escaped"
	ContextJSAssignment       HTMLContext = "js_assignment"
	ContextScriptTag          HTMLContext = "script_tag"
	ContextCSSExpression      HTMLContext = "css_expression"
	ContextAttribute          HTMLContext = "attribute"
	ContextUnknown            HTMLContext = "unknown"
	ContextJSON               HTMLContext = "json"
	
	// New specific attribute context types for better payload generation
	ContextHTMLAttributeDoubleQuoted HTMLContext = "html_attribute_double_quoted"
	ContextHTMLAttributeSingleQuoted HTMLContext = "html_attribute_single_quoted"
	ContextHTMLAttributeUnquoted     HTMLContext = "html_attribute_unquoted"
	ContextHTMLAttributeName         HTMLContext = "html_attribute_name"
	ContextHTMLAttributeNameUnquoted HTMLContext = "html_attribute_name_unquoted"
	ContextIframeSrc                 HTMLContext = "iframe_src" // Special context for iframe src attributes
	ContextIframeAttribute           HTMLContext = "iframe_attribute" // Special context for iframe non-src attributes
	ContextIframeSrcdoc              HTMLContext = "iframe_srcdoc" // Special context for iframe srcdoc attributes
	ContextTextarea                  HTMLContext = "textarea" // Special context for textarea content
	ContextTextareaAttribute         HTMLContext = "textarea_attribute" // Special context for textarea attribute values
	ContextNoscript                  HTMLContext = "noscript" // Special context for noscript content
	ContextStyleAttribute            HTMLContext = "style_attribute" // Special context for style attribute values
	ContextJSRegex                  HTMLContext = "js_regex" // Special context for JavaScript regex literals
	ContextJSComment                HTMLContext = "js_comment" // Special context for JavaScript comments
	ContextScriptSrcAttribute       HTMLContext = "script_src_attribute" // Special context for script src attributes
)

// XSSType represents the type of XSS vulnerability
type XSSType string

const (
	TypeReflected XSSType = "reflected"
	TypeDOM       XSSType = "dom"
	TypeStored    XSSType = "stored"
)

// ContextAnalysis represents detailed analysis of reflection context
type ContextAnalysis struct {
	ContextType        HTMLContext `json:"context_type"`
	TagName            string      `json:"tag_name,omitempty"`           // e.g., "iframe", "img", "div"
	AttributeName      string      `json:"attribute_name,omitempty"`     // e.g., "src", "href", "onload"
	QuoteType          string      `json:"quote_type,omitempty"`          // "single", "double", "unquoted", "none"
	IsAttributeValue   bool        `json:"is_attribute_value"`           // true if reflects in attribute value
	IsAttributeName    bool        `json:"is_attribute_name"`            // true if reflects as attribute name
	IsInScript         bool        `json:"is_in_script"`                  // true if in <script> tag
	IsInEvent          bool        `json:"is_in_event"`                   // true if in event handler
	IsInURL            bool        `json:"is_in_url"`                      // true if in URL context
	IsInCSS            bool        `json:"is_in_css"`                      // true if in CSS context
	IsInComment        bool        `json:"is_in_comment"`                  // true if in HTML comment
	IsInTitle          bool        `json:"is_in_title"`                   // true if in title tag
	IsExecutable       bool        `json:"is_executable"`                 // true if context allows JS execution
	RequiresBreakout   bool        `json:"requires_breakout"`             // true if needs to break out of context
	BreakoutSequence   string      `json:"breakout_sequence,omitempty"`   // e.g., "'>", "-->", "</title>"
	ExecutableContext  string      `json:"executable_context,omitempty"`  // e.g., "javascript:", "onload="
	RecommendedPayloads []string   `json:"recommended_payloads"`          // Most likely to work payloads
}

