package customresponseurlguardrail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const policyName = "custom-response-url-guardrail"

var extractedURLPattern = regexp.MustCompile("https?://[^\\s,\\\"'{}\\[\\]\\\\`*]+")
var additionalBlockedNetworks = mustParseNetworks([]string{
	"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15",
	"224.0.0.0/4", "240.0.0.0/4", "::/128", "2001:db8::/32",
})

type ResponseURLGuardrailPolicy struct {
	onlyDNS                      bool
	timeout                      time.Duration
	maximumURLs                  int
	maxResponseBodySize          int
	failClosedUnexpectedResponse bool
	showAssessment               bool
}

func (p *ResponseURLGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode: policy.HeaderModeSkip, RequestBodyMode: policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip, ResponseBodyMode: policy.BodyModeBuffer,
	}
}

func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	onlyDNS, err := booleanParameter(params, "urlOnlyDNS", false)
	if err != nil {
		return nil, err
	}
	timeoutMs, err := integerParameter(params, "urlTimeoutMs", 5000)
	if err != nil {
		return nil, err
	}
	if timeoutMs < 100 || timeoutMs > 30000 {
		return nil, errors.New("urlTimeoutMs must be between 100 and 30000")
	}
	maximumURLs, err := integerParameter(params, "maximumURLs", 10)
	if err != nil {
		return nil, err
	}
	if maximumURLs < 1 || maximumURLs > 100 {
		return nil, errors.New("maximumURLs must be between 1 and 100")
	}
	maxSize, err := integerParameter(params, "maxResponseBodySize", 4194304)
	if err != nil {
		return nil, err
	}
	failClosed, err := booleanParameter(params, "failClosedUnexpectedResponse", true)
	if err != nil {
		return nil, err
	}
	show, err := booleanParameter(params, "showAssessment", true)
	if err != nil {
		return nil, err
	}
	return &ResponseURLGuardrailPolicy{onlyDNS: onlyDNS, timeout: time.Duration(timeoutMs) * time.Millisecond, maximumURLs: maximumURLs, maxResponseBodySize: maxSize, failClosedUnexpectedResponse: failClosed, showAssessment: show}, nil
}

func (p *ResponseURLGuardrailPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	_, content, action := prepareResponse(respCtx, p.maxResponseBodySize, p.failClosedUnexpectedResponse, p.showAssessment)
	if action != nil {
		return action
	}
	if content == "" {
		return policy.DownstreamResponseModifications{}
	}
	urls := extractURLs(content)
	if len(urls) > p.maximumURLs {
		return p.block("url-validation", "Response contains more URLs than allowed.", map[string]interface{}{"maximumURLs": p.maximumURLs, "actualURLs": len(urls)})
	}
	invalid := make([]string, 0)
	for _, candidate := range urls {
		if err := p.validateURL(ctx, candidate); err != nil {
			invalid = append(invalid, candidate)
		}
	}
	if len(invalid) > 0 {
		return p.block("url-validation", "One or more URLs in the response failed validation.", map[string]interface{}{"invalidUrls": invalid})
	}
	return policy.DownstreamResponseModifications{}
}

func (p *ResponseURLGuardrailPolicy) validateURL(ctx context.Context, candidate string) error {
	parsed, err := url.Parse(candidate)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("only HTTP and HTTPS URLs are allowed")
	}
	if parsed.Hostname() == "" {
		return errors.New("URL hostname is empty")
	}
	if _, err := resolvePublicIPs(ctx, parsed.Hostname()); err != nil {
		return err
	}
	if p.onlyDNS {
		return nil
	}
	transport := &http.Transport{
		Proxy: nil, TLSHandshakeTimeout: p.timeout, ResponseHeaderTimeout: p.timeout, IdleConnTimeout: p.timeout,
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := resolvePublicIPs(dialCtx, host)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{Timeout: p.timeout}).DialContext(dialCtx, network, net.JoinHostPort(ips[0].String(), port))
		},
	}
	client := &http.Client{Timeout: p.timeout, Transport: transport, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many redirects")
		}
		if request.URL.Scheme != "http" && request.URL.Scheme != "https" {
			return errors.New("redirect uses an unsupported scheme")
		}
		_, err := resolvePublicIPs(request.Context(), request.URL.Hostname())
		return err
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, parsed.String(), nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "WSO2-Custom-Response-URL-Guardrail/1.0")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return nil
}

func prepareResponse(respCtx *policy.ResponseContext, maxSize int, failClosed, show bool) (map[string]interface{}, string, policy.ResponseAction) {
	if respCtx == nil || respCtx.ResponseBody == nil || len(respCtx.ResponseBody.Content) == 0 {
		if failClosed {
			return nil, "", block("response-structure", "Upstream response body is empty.", nil, show)
		}
		return nil, "", nil
	}
	if len(respCtx.ResponseBody.Content) > maxSize {
		return nil, "", block("response-size", "Response body exceeds the configured maximum size.", map[string]interface{}{"maximumBytes": maxSize, "actualBytes": len(respCtx.ResponseBody.Content)}, show)
	}
	var response map[string]interface{}
	if err := json.Unmarshal(respCtx.ResponseBody.Content, &response); err != nil {
		if failClosed {
			return nil, "", block("response-structure", "Upstream response is not valid JSON.", safeError(err), show)
		}
		return nil, "", nil
	}
	if _, exists := response["error"]; exists || isGuardrailIntervention(response) {
		return nil, "", nil
	}
	content, err := extractAssistantContent(response)
	if err != nil {
		if failClosed {
			return nil, "", block("response-structure", "Response does not contain a valid assistant message.", safeError(err), show)
		}
		return nil, "", nil
	}
	return response, content, nil
}
func (p *ResponseURLGuardrailPolicy) block(check, reason string, assessment interface{}) policy.ImmediateResponse {
	return block(check, reason, assessment, p.showAssessment)
}
func block(check, reason string, assessment interface{}, show bool) policy.ImmediateResponse {
	message := map[string]interface{}{"action": "GUARDRAIL_INTERVENED", "actionReason": reason, "direction": "RESPONSE", "interveningGuardrail": policyName, "check": check}
	if show && assessment != nil {
		message["assessments"] = assessment
	}
	body, err := json.Marshal(map[string]interface{}{"type": "RESPONSE_URL_GUARDRAIL", "message": message})
	if err != nil {
		body = []byte(`{"type":"RESPONSE_URL_GUARDRAIL","message":{"action":"GUARDRAIL_INTERVENED"}}`)
	}
	return policy.ImmediateResponse{StatusCode: 422, Headers: map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store"}, Body: body}
}
func extractURLs(content string) []string {
	matches := extractedURLPattern.FindAllString(content, -1)
	seen := map[string]struct{}{}
	result := make([]string, 0, len(matches))
	for _, match := range matches {
		cleaned := strings.TrimRight(match, ".,;:!?)]}")
		if _, ok := seen[cleaned]; ok {
			continue
		}
		seen[cleaned] = struct{}{}
		result = append(result, cleaned)
	}
	return result
}
func resolvePublicIPs(ctx context.Context, host string) ([]net.IP, error) {
	if strings.EqualFold(host, "localhost") {
		return nil, errors.New("localhost is not allowed")
	}
	if literal := net.ParseIP(host); literal != nil {
		if isBlockedIP(literal) {
			return nil, errors.New("private or reserved IP address is not allowed")
		}
		return []net.IP{literal}, nil
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("hostname did not resolve to an IP address")
	}
	result := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		if isBlockedIP(address.IP) {
			return nil, errors.New("hostname resolves to a private or reserved IP address")
		}
		result = append(result, address.IP)
	}
	return result, nil
}
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, network := range additionalBlockedNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
func mustParseNetworks(values []string) []*net.IPNet {
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		result = append(result, network)
	}
	return result
}
func isGuardrailIntervention(response map[string]interface{}) bool {
	message, ok := response["message"].(map[string]interface{})
	if !ok {
		return false
	}
	action, _ := message["action"].(string)
	return action == "GUARDRAIL_INTERVENED"
}
func extractAssistantContent(response map[string]interface{}) (string, error) {
	raw, exists := response["choices"]
	if !exists {
		return "", errors.New("key not found: choices")
	}
	choices, ok := raw.([]interface{})
	if !ok || len(choices) == 0 {
		return "", errors.New("choices is not a non-empty array")
	}
	first, ok := choices[0].(map[string]interface{})
	if !ok {
		return "", errors.New("choices[0] is not an object")
	}
	message, ok := first["message"].(map[string]interface{})
	if !ok {
		return "", errors.New("choices[0].message is not an object")
	}
	content, ok := message["content"].(string)
	if !ok {
		return "", errors.New("choices[0].message.content is not a string")
	}
	return content, nil
}
func booleanParameter(params map[string]interface{}, name string, fallback bool) (bool, error) {
	value, exists := params[name]
	if !exists || value == nil {
		return fallback, nil
	}
	typed, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("parameter %q must be a boolean, received %T", name, value)
	}
	return typed, nil
}
func integerParameter(params map[string]interface{}, name string, fallback int) (int, error) {
	value, exists := params[name]
	if !exists || value == nil {
		return fallback, nil
	}
	switch typed := value.(type) {
	case int:
		return typed, nil
	case int32:
		return int(typed), nil
	case int64:
		return int(typed), nil
	case float64:
		return int(typed), nil
	case json.Number:
		parsed, err := typed.Int64()
		return int(parsed), err
	default:
		return 0, fmt.Errorf("parameter %q must be an integer, received %T", name, value)
	}
}
func safeError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 1000 {
		return value[:1000] + "..."
	}
	return value
}
