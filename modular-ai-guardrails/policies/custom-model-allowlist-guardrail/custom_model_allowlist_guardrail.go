package custommodelallowlistguardrail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	pendingRequestBlockMetadataKey = "wso2.ai.pending-request-block"
	policyName                     = "custom-model-allowlist-guardrail"
)

type ModelAllowlistGuardrailPolicy struct {
	allowed            map[string]struct{}
	allowedList        []string
	requireModel       bool
	quarantineModel    string
	quarantineMessage  string
	maxRequestBodySize int
	showAssessment     bool
}

func (p *ModelAllowlistGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{RequestHeaderMode: policy.HeaderModeSkip, RequestBodyMode: policy.BodyModeBuffer, ResponseHeaderMode: policy.HeaderModeSkip, ResponseBodyMode: policy.BodyModeSkip}
}

func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	csv, err := stringParameter(params, "allowedModels", "gpt-4o-mini")
	if err != nil {
		return nil, err
	}
	allowed := map[string]struct{}{}
	allowedList := []string{}
	for _, item := range strings.Split(csv, ",") {
		model := strings.TrimSpace(item)
		if model == "" {
			continue
		}
		allowed[model] = struct{}{}
		allowedList = append(allowedList, model)
	}
	if len(allowed) == 0 {
		return nil, errors.New("allowedModels must contain at least one model")
	}
	requireModel, err := booleanParameter(params, "requireModel", true)
	if err != nil {
		return nil, err
	}
	quarantineModel, err := stringParameter(params, "quarantineModel", allowedList[0])
	if err != nil {
		return nil, err
	}
	if _, ok := allowed[quarantineModel]; !ok {
		return nil, errors.New("quarantineModel must be included in allowedModels")
	}
	quarantineMessage, err := stringParameter(params, "quarantineMessage", "Reply exactly with OK.")
	if err != nil {
		return nil, err
	}
	maxSize, err := integerParameter(params, "maxRequestBodySize", 1048576)
	if err != nil {
		return nil, err
	}
	if maxSize <= 0 {
		return nil, errors.New("maxRequestBodySize must be greater than zero")
	}
	showAssessment, err := booleanParameter(params, "showAssessment", true)
	if err != nil {
		return nil, err
	}
	return &ModelAllowlistGuardrailPolicy{allowed: allowed, allowedList: allowedList, requireModel: requireModel, quarantineModel: quarantineModel, quarantineMessage: quarantineMessage, maxRequestBodySize: maxSize, showAssessment: showAssessment}, nil
}

func (p *ModelAllowlistGuardrailPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if reqCtx == nil || pending(reqCtx.Metadata) {
		return nil
	}
	if reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 {
		return p.quarantine(reqCtx, nil, "model-allowlist", "Request body is empty.", nil)
	}
	if len(reqCtx.Body.Content) > p.maxRequestBodySize {
		return p.quarantine(reqCtx, nil, "model-allowlist", "Request body exceeds the configured maximum size.", map[string]interface{}{"maximumBytes": p.maxRequestBodySize, "actualBytes": len(reqCtx.Body.Content)})
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(reqCtx.Body.Content, &payload); err != nil {
		return p.quarantine(reqCtx, nil, "model-allowlist", "Request body is not valid JSON.", safeError(err))
	}
	model, _ := payload["model"].(string)
	model = strings.TrimSpace(model)
	if model == "" && !p.requireModel {
		return nil
	}
	if _, ok := p.allowed[model]; ok {
		return nil
	}
	assessment := interface{}(nil)
	if p.showAssessment {
		assessment = map[string]interface{}{"requestedModel": model, "approvedModels": p.allowedList, "nearestApprovedModel": nearest(model, p.allowedList)}
	}
	reason := "Requested model is not approved for this endpoint."
	if model == "" {
		reason = "A model identifier is required for this endpoint."
	}
	return p.quarantine(reqCtx, payload, "model-allowlist", reason, assessment)
}

func (p *ModelAllowlistGuardrailPolicy) quarantine(reqCtx *policy.RequestContext, original map[string]interface{}, check, reason string, assessment interface{}) policy.RequestAction {
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]interface{}{}
	}
	reqCtx.Metadata[pendingRequestBlockMetadataKey] = map[string]interface{}{"policy": policyName, "check": check, "reason": reason, "assessment": assessment}
	safe := map[string]interface{}{"model": p.quarantineModel, "temperature": 0, "stream": false, "messages": []interface{}{map[string]interface{}{"role": "user", "content": p.quarantineMessage}}}
	body, _ := json.Marshal(safe)
	return policy.UpstreamRequestModifications{Body: body, AnalyticsMetadata: map[string]interface{}{"ai.security.request_blocked": true, "ai.security.blocking_policy": policyName}}
}

func nearest(value string, choices []string) string {
	if value == "" || len(choices) == 0 {
		return ""
	}
	best, distance := choices[0], levenshtein(strings.ToLower(value), strings.ToLower(choices[0]))
	for _, choice := range choices[1:] {
		if d := levenshtein(strings.ToLower(value), strings.ToLower(choice)); d < distance {
			best, distance = choice, d
		}
	}
	return best
}
func levenshtein(a, b string) int {
	ar, br := []rune(a), []rune(b)
	previous := make([]int, len(br)+1)
	for j := range previous {
		previous[j] = j
	}
	for i, ca := range ar {
		current := make([]int, len(br)+1)
		current[0] = i + 1
		for j, cb := range br {
			cost := 0
			if ca != cb {
				cost = 1
			}
			current[j+1] = min3(current[j]+1, previous[j+1]+1, previous[j]+cost)
		}
		previous = current
	}
	return previous[len(br)]
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
	v, ok := params[name]
	if !ok || v == nil {
		return fallback, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("parameter %q must be a string, received %T", name, v)
	}
	return s, nil
}
func booleanParameter(params map[string]interface{}, name string, fallback bool) (bool, error) {
	v, ok := params[name]
	if !ok || v == nil {
		return fallback, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("parameter %q must be a boolean, received %T", name, v)
	}
	return b, nil
}
func integerParameter(params map[string]interface{}, name string, fallback int) (int, error) {
	v, ok := params[name]
	if !ok || v == nil {
		return fallback, nil
	}
	switch t := v.(type) {
	case int:
		return t, nil
	case int32:
		return int(t), nil
	case int64:
		return int(t), nil
	case float64:
		return int(t), nil
	case json.Number:
		n, e := t.Int64()
		return int(n), e
	default:
		return 0, fmt.Errorf("parameter %q must be an integer, received %T", name, v)
	}
}
func safeError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 1000 {
		return s[:1000] + "..."
	}
	return s
}
