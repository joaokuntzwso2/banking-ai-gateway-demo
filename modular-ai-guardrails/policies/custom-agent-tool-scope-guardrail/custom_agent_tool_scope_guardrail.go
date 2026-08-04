package customagenttoolscopeguardrail

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	pendingRequestBlockMetadataKey = "wso2.ai.pending-request-block"
	policyName                     = "custom-agent-tool-scope-guardrail"
)

var suspiciousToolDescriptionFragments = []string{
	"ignore all previous instructions",
	"ignore previous instructions",
	"ignora todas las instrucciones anteriores",
	"reveal the system prompt",
	"revela el prompt de sistema",
	"export all data",
	"exporta todos los datos",
	"send all customer data",
	"envía todos los datos",
}

type AgentToolScopeGuardrailPolicy struct {
	allowed                            map[string]struct{}
	allowedList                        []string
	sensitive                          map[string]string
	requireApproval                    bool
	blockSuspiciousDescriptions        bool
	maxRequestBodySize                 int
	quarantineModel, quarantineMessage string
	showAssessment                     bool
	allowSignedDemoContext             bool
	demoContextHMACSecret              string
	demoContextHeader                  string
	demoSignatureHeader                string
	expectedAudience                   string
	maxDemoContextAgeSeconds           int64
}

type delegatedContext struct {
	Source          string
	Subject         string   `json:"subject"`
	TenantID        string   `json:"tenantId"`
	Scopes          []string `json:"scopes"`
	ApprovalID      string   `json:"approvalId"`
	ApprovedActions []string `json:"approvedActions"`
	RequestedAction string   `json:"requestedAction"`
	Audience        string   `json:"aud"`
	ExpiresAt       int64    `json:"exp"`
	IssuedAt        int64    `json:"iat"`
	Nonce           string   `json:"nonce"`
}

func (p *AgentToolScopeGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	csv, err := stringParameter(params, "allowedTools", "")
	if err != nil {
		return nil, err
	}
	allowed := map[string]struct{}{}
	list := []string{}
	for _, item := range strings.Split(csv, ",") {
		name := strings.TrimSpace(item)
		if name == "" {
			continue
		}
		allowed[name] = struct{}{}
		list = append(list, name)
	}
	if len(allowed) == 0 {
		return nil, errors.New("allowedTools must not be empty")
	}

	rawSensitive, err := stringParameter(params, "sensitiveToolScopesJson", "{}")
	if err != nil {
		return nil, err
	}
	sensitive := map[string]string{}
	if err := json.Unmarshal([]byte(rawSensitive), &sensitive); err != nil {
		return nil, fmt.Errorf("invalid sensitiveToolScopesJson: %w", err)
	}

	requireApproval, err := booleanParameter(params, "requireApprovalForSensitive", true)
	if err != nil {
		return nil, err
	}
	blockSuspiciousDescriptions, err := booleanParameter(params, "blockSuspiciousToolDescriptions", true)
	if err != nil {
		return nil, err
	}
	maxBodySize, err := integerParameter(params, "maxRequestBodySize", 1048576)
	if err != nil {
		return nil, err
	}
	if maxBodySize <= 0 {
		return nil, errors.New("maxRequestBodySize must be greater than zero")
	}
	quarantineModel, err := stringParameter(params, "quarantineModel", "gpt-4o-mini")
	if err != nil {
		return nil, err
	}
	quarantineMessage, err := stringParameter(params, "quarantineMessage", "Reply exactly with OK.")
	if err != nil {
		return nil, err
	}
	showAssessment, err := booleanParameter(params, "showAssessment", true)
	if err != nil {
		return nil, err
	}
	allowSignedDemoContext, err := booleanParameter(params, "allowSignedDemoContext", true)
	if err != nil {
		return nil, err
	}
	demoContextHMACSecret, err := stringParameter(params, "demoContextHmacSecret", "")
	if err != nil {
		return nil, err
	}
	if allowSignedDemoContext && len(demoContextHMACSecret) < 24 {
		return nil, errors.New("demoContextHmacSecret must contain at least 24 characters when allowSignedDemoContext is enabled")
	}
	demoContextHeader, err := stringParameter(params, "demoContextHeader", "X-Aurelius-Delegation-Context")
	if err != nil {
		return nil, err
	}
	demoSignatureHeader, err := stringParameter(params, "demoSignatureHeader", "X-Aurelius-Delegation-Signature")
	if err != nil {
		return nil, err
	}
	expectedAudience, err := stringParameter(params, "expectedAudience", "customer-ai-secure")
	if err != nil {
		return nil, err
	}
	maxDemoContextAgeSeconds, err := integerParameter(params, "maxDemoContextAgeSeconds", 120)
	if err != nil {
		return nil, err
	}
	if maxDemoContextAgeSeconds < 1 || maxDemoContextAgeSeconds > 3600 {
		return nil, errors.New("maxDemoContextAgeSeconds must be between 1 and 3600")
	}

	return &AgentToolScopeGuardrailPolicy{
		allowed:                     allowed,
		allowedList:                 list,
		sensitive:                   sensitive,
		requireApproval:             requireApproval,
		blockSuspiciousDescriptions: blockSuspiciousDescriptions,
		maxRequestBodySize:          maxBodySize,
		quarantineModel:             quarantineModel,
		quarantineMessage:           quarantineMessage,
		showAssessment:              showAssessment,
		allowSignedDemoContext:      allowSignedDemoContext,
		demoContextHMACSecret:       demoContextHMACSecret,
		demoContextHeader:           demoContextHeader,
		demoSignatureHeader:         demoSignatureHeader,
		expectedAudience:            expectedAudience,
		maxDemoContextAgeSeconds:    int64(maxDemoContextAgeSeconds),
	}, nil
}

func (p *AgentToolScopeGuardrailPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if reqCtx == nil || pending(reqCtx.Metadata) {
		return nil
	}
	if reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 {
		return nil
	}
	if len(reqCtx.Body.Content) > p.maxRequestBodySize {
		return p.block(reqCtx, "tool-authorization", "Request body exceeds the configured maximum size.", nil)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(reqCtx.Body.Content, &payload); err != nil {
		return p.block(reqCtx, "tool-authorization", "Request body is not valid JSON.", safeError(err))
	}

	// Authorization context inside the model request is user-controlled and must
	// never be treated as proof of identity, scope, or approval.
	if _, exists := payload["securityContext"]; exists {
		return p.block(reqCtx, "untrusted-authorization-context", "Authorization context supplied inside the model request body is not trusted.", p.assessment(map[string]interface{}{
			"requiredSource": "gateway AuthContext or a server-signed demo delegation context",
		}))
	}

	security, err := p.resolveDelegatedContext(reqCtx)
	if err != nil {
		return p.block(reqCtx, "tool-authorization", "The delegated authorization context is invalid.", p.assessment(safeError(err)))
	}

	tools := extractTools(payload["tools"])
	for _, tool := range tools {
		if _, ok := p.allowed[tool.Name]; !ok {
			return p.block(reqCtx, "tool-allowlist", "An unapproved or lookalike tool was declared.", p.assessment(map[string]interface{}{
				"requestedTool":       tool.Name,
				"approvedTools":       p.allowedList,
				"nearestApprovedTool": nearest(tool.Name, p.allowedList),
			}))
		}
		if p.blockSuspiciousDescriptions && containsSuspiciousInstruction(tool.Description) {
			return p.block(reqCtx, "tool-description-poisoning", "An approved tool declaration contained a suspicious instruction in its description.", p.assessment(map[string]interface{}{
				"tool": tool.Name,
			}))
		}
	}

	selected := selectedTool(payload["tool_choice"])
	if selected == "" {
		selected = security.RequestedAction
	}
	if selected != "" {
		if _, ok := p.allowed[selected]; !ok {
			return p.block(reqCtx, "tool-allowlist", "The selected tool is not approved.", p.assessment(map[string]interface{}{
				"requestedTool":       selected,
				"approvedTools":       p.allowedList,
				"nearestApprovedTool": nearest(selected, p.allowedList),
			}))
		}
	}

	actions := map[string]struct{}{}
	for _, tool := range tools {
		if _, sensitive := p.sensitive[tool.Name]; sensitive {
			actions[tool.Name] = struct{}{}
		}
	}
	if selected != "" {
		if _, sensitive := p.sensitive[selected]; sensitive {
			actions[selected] = struct{}{}
		}
	}

	for action := range actions {
		requiredScope := p.sensitive[action]
		if !contains(security.Scopes, requiredScope) {
			return p.block(reqCtx, "tool-authorization", "A sensitive tool is outside the delegated user scope.", p.assessment(map[string]interface{}{
				"tool":          action,
				"requiredScope": requiredScope,
				"grantedScopes": security.Scopes,
				"contextSource": security.Source,
			}))
		}
		if p.requireApproval && (strings.TrimSpace(security.ApprovalID) == "" || !contains(security.ApprovedActions, action)) {
			return p.block(reqCtx, "tool-authorization", "A sensitive tool requires a matching human approval.", p.assessment(map[string]interface{}{
				"tool":              action,
				"approvalRequired":  true,
				"approvalIdPresent": security.ApprovalID != "",
				"approvedActions":   security.ApprovedActions,
				"contextSource":     security.Source,
			}))
		}
	}

	// Never forward local delegation evidence to the model provider.
	if reqCtx.Headers != nil && (reqCtx.Headers.Has(p.demoContextHeader) || reqCtx.Headers.Has(p.demoSignatureHeader)) {
		return policy.UpstreamRequestModifications{
			HeadersToRemove: []string{p.demoContextHeader, p.demoSignatureHeader},
			AnalyticsMetadata: map[string]interface{}{
				"ai.security.delegated_context_validated": security.Source != "",
				"ai.security.delegated_context_source":    security.Source,
			},
		}
	}

	return nil
}

type declaredTool struct {
	Name        string
	Description string
}

func (p *AgentToolScopeGuardrailPolicy) resolveDelegatedContext(reqCtx *policy.RequestContext) (delegatedContext, error) {
	if reqCtx.AuthContext != nil && reqCtx.AuthContext.Authenticated {
		context := delegatedContext{
			Source:   "gateway-auth-context",
			Subject:  reqCtx.AuthContext.Subject,
			Scopes:   scopeNames(reqCtx.AuthContext.Scopes),
			Audience: first(reqCtx.AuthContext.Audience),
		}
		properties := reqCtx.AuthContext.Properties
		if properties != nil {
			context.TenantID = properties["tenant_id"]
			context.ApprovalID = properties["approval_id"]
			context.ApprovedActions = splitCSV(properties["approved_actions"])
			context.RequestedAction = properties["requested_action"]
		}
		if len(context.Scopes) > 0 || context.ApprovalID != "" || context.RequestedAction != "" {
			return context, nil
		}
	}

	if !p.allowSignedDemoContext || reqCtx.Headers == nil {
		return delegatedContext{}, nil
	}
	encodedValues := reqCtx.Headers.Get(p.demoContextHeader)
	signatureValues := reqCtx.Headers.Get(p.demoSignatureHeader)
	if len(encodedValues) == 0 && len(signatureValues) == 0 {
		return delegatedContext{}, nil
	}
	if len(encodedValues) != 1 || len(signatureValues) != 1 {
		return delegatedContext{}, errors.New("exactly one delegation context and signature header are required")
	}
	encoded := strings.TrimSpace(encodedValues[0])
	suppliedSignature := strings.TrimSpace(signatureValues[0])
	expectedSignature := hmac.New(sha256.New, []byte(p.demoContextHMACSecret))
	_, _ = expectedSignature.Write([]byte(encoded))
	expected := expectedSignature.Sum(nil)
	supplied, err := hex.DecodeString(suppliedSignature)
	if err != nil || len(supplied) != len(expected) || !hmac.Equal(supplied, expected) {
		return delegatedContext{}, errors.New("delegation context signature validation failed")
	}
	decoded, err := decodeBase64URL(encoded)
	if err != nil {
		return delegatedContext{}, fmt.Errorf("delegation context encoding is invalid: %w", err)
	}
	var context delegatedContext
	if err := json.Unmarshal(decoded, &context); err != nil {
		return delegatedContext{}, fmt.Errorf("delegation context JSON is invalid: %w", err)
	}
	context.Source = "server-signed-demo-context"
	now := time.Now().Unix()
	if context.Audience != p.expectedAudience {
		return delegatedContext{}, errors.New("delegation context audience does not match this proxy")
	}
	if context.ExpiresAt < now || context.ExpiresAt > now+p.maxDemoContextAgeSeconds {
		return delegatedContext{}, errors.New("delegation context has expired or exceeds the allowed validity window")
	}
	if context.IssuedAt <= 0 || context.IssuedAt > now+5 || now-context.IssuedAt > p.maxDemoContextAgeSeconds {
		return delegatedContext{}, errors.New("delegation context issue time is outside the allowed window")
	}
	if strings.TrimSpace(context.Nonce) == "" {
		return delegatedContext{}, errors.New("delegation context nonce is required")
	}
	return context, nil
}

func (p *AgentToolScopeGuardrailPolicy) assessment(value interface{}) interface{} {
	if p.showAssessment {
		return value
	}
	return nil
}

func (p *AgentToolScopeGuardrailPolicy) block(reqCtx *policy.RequestContext, check, reason string, assessment interface{}) policy.RequestAction {
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]interface{}{}
	}
	reqCtx.Metadata[pendingRequestBlockMetadataKey] = map[string]interface{}{
		"policy":     policyName,
		"check":      check,
		"reason":     reason,
		"assessment": assessment,
	}
	safe := map[string]interface{}{
		"model":       p.quarantineModel,
		"temperature": 0,
		"stream":      false,
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": p.quarantineMessage},
		},
	}
	body, _ := json.Marshal(safe)
	return policy.UpstreamRequestModifications{
		Body:            body,
		HeadersToRemove: []string{p.demoContextHeader, p.demoSignatureHeader},
		AnalyticsMetadata: map[string]interface{}{
			"ai.security.request_blocked": true,
			"ai.security.blocking_policy": policyName,
		},
	}
}

func extractTools(value interface{}) []declaredTool {
	items, _ := value.([]interface{})
	out := make([]declaredTool, 0, len(items))
	for _, raw := range items {
		object, _ := raw.(map[string]interface{})
		function, _ := object["function"].(map[string]interface{})
		name, _ := function["name"].(string)
		description, _ := function["description"].(string)
		if name != "" {
			out = append(out, declaredTool{Name: name, Description: description})
		}
	}
	return out
}

func selectedTool(value interface{}) string {
	object, _ := value.(map[string]interface{})
	function, _ := object["function"].(map[string]interface{})
	name, _ := function["name"].(string)
	return name
}

func containsSuspiciousInstruction(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, fragment := range suspiciousToolDescriptionFragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func scopeNames(scopes map[string]bool) []string {
	out := []string{}
	for scope, granted := range scopes {
		if granted {
			out = append(out, scope)
		}
	}
	return out
}

func splitCSV(value string) []string {
	out := []string{}
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func decodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func nearest(value string, choices []string) string {
	if value == "" || len(choices) == 0 {
		return ""
	}
	best := choices[0]
	distance := levenshtein(strings.ToLower(value), strings.ToLower(best))
	for _, choice := range choices[1:] {
		if current := levenshtein(strings.ToLower(value), strings.ToLower(choice)); current < distance {
			best = choice
			distance = current
		}
	}
	return best
}

func levenshtein(a, b string) int {
	left, right := []rune(a), []rune(b)
	previous := make([]int, len(right)+1)
	for index := range previous {
		previous[index] = index
	}
	for i, leftRune := range left {
		current := make([]int, len(right)+1)
		current[0] = i + 1
		for j, rightRune := range right {
			cost := 0
			if leftRune != rightRune {
				cost = 1
			}
			current[j+1] = min3(current[j]+1, previous[j+1]+1, previous[j]+cost)
		}
		previous = current
	}
	return previous[len(right)]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func pending(metadata map[string]interface{}) bool {
	if metadata == nil {
		return false
	}
	_, ok := metadata[pendingRequestBlockMetadataKey]
	return ok
}

func stringParameter(params map[string]interface{}, name, fallback string) (string, error) {
	value, exists := params[name]
	if !exists || value == nil {
		return fallback, nil
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("parameter %q must be a string, received %T", name, value)
	}
	return text, nil
}

func booleanParameter(params map[string]interface{}, name string, fallback bool) (bool, error) {
	value, exists := params[name]
	if !exists || value == nil {
		return fallback, nil
	}
	flag, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("parameter %q must be a boolean, received %T", name, value)
	}
	return flag, nil
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
