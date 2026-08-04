package customrelianceguardrail

import (
	"context"
	"encoding/json"
	"fmt"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"regexp"
)

const (
	pendingKey = "wso2.ai.pending-request-block"
	policyName = "custom-reliance-guardrail"
)

type P struct {
	re      *regexp.Regexp
	max     int
	message string
	show    bool
}

func (p *P) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{RequestHeaderMode: policy.HeaderModeSkip, RequestBodyMode: policy.BodyModeBuffer, ResponseHeaderMode: policy.HeaderModeSkip, ResponseBodyMode: policy.BodyModeSkip}
}
func GetPolicy(_ policy.PolicyMetadata, x map[string]interface{}) (policy.Policy, error) {
	v, e := s(x, "blockedRelianceRegex", `(?i)(respuesta definitiva|definitive answer).*(aunque no exista evidencia|without evidence)|(no menciones incertidumbre|do not mention uncertainty)|(no solicites revisi[oó]n|do not request review)`)
	if e != nil {
		return nil, e
	}
	r, e := regexp.Compile(v)
	if e != nil {
		return nil, e
	}
	m, e := i(x, "maxRequestBodySize", 1048576)
	if e != nil {
		return nil, e
	}
	q, e := s(x, "quarantineMessage", "Reply exactly with OK.")
	if e != nil {
		return nil, e
	}
	sh, e := bo(x, "showAssessment", true)
	if e != nil {
		return nil, e
	}
	return &P{re: r, max: m, message: q, show: sh}, nil
}
func (p *P) OnRequestBody(_ context.Context, r *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if r == nil || pending(r.Metadata) || r.Body == nil || len(r.Body.Content) == 0 || len(r.Body.Content) > p.max {
		return nil
	}
	var x map[string]interface{}
	if json.Unmarshal(r.Body.Content, &x) != nil {
		return nil
	}
	c, ok := content(x)
	if !ok || !p.re.MatchString(c) {
		return nil
	}
	var a interface{}
	if p.show {
		a = map[string]interface{}{"classification": "EXCESSIVE_RELIANCE_OR_MISINFORMATION", "requiredBehavior": "acknowledge-uncertainty-and-human-review"}
	}
	if r.Metadata == nil {
		r.Metadata = map[string]interface{}{}
	}
	r.Metadata[pendingKey] = map[string]interface{}{"policy": policyName, "check": "excessive-reliance", "reason": "Request attempts to suppress uncertainty, evidence requirements, or human review.", "assessment": a}
	safe := map[string]interface{}{"model": "gpt-4o-mini", "temperature": 0, "stream": false, "messages": []interface{}{map[string]interface{}{"role": "user", "content": p.message}}}
	if model, ok := x["model"]; ok {
		safe["model"] = model
	}
	body, _ := json.Marshal(safe)
	return policy.UpstreamRequestModifications{Body: body}
}
func content(x map[string]interface{}) (string, bool) {
	m, ok := x["messages"].([]interface{})
	if !ok || len(m) == 0 {
		return "", false
	}
	o, ok := m[len(m)-1].(map[string]interface{})
	if !ok {
		return "", false
	}
	v, ok := o["content"].(string)
	return v, ok
}
func pending(m map[string]interface{}) bool {
	if m == nil {
		return false
	}
	_, ok := m[pendingKey]
	return ok
}
func s(p map[string]interface{}, n, f string) (string, error) {
	v, ok := p[n]
	if !ok || v == nil {
		return f, nil
	}
	z, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be string", n)
	}
	return z, nil
}
func bo(p map[string]interface{}, n string, f bool) (bool, error) {
	v, ok := p[n]
	if !ok || v == nil {
		return f, nil
	}
	z, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be bool", n)
	}
	return z, nil
}
func i(p map[string]interface{}, n string, f int) (int, error) {
	v, ok := p[n]
	if !ok || v == nil {
		return f, nil
	}
	switch z := v.(type) {
	case int:
		return z, nil
	case float64:
		return int(z), nil
	case json.Number:
		q, e := z.Int64()
		return int(q), e
	default:
		return 0, fmt.Errorf("%s must be integer", n)
	}
}
