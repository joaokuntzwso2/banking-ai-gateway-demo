package customhighimpactdecisionguardrail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"regexp"
)

const (
	pendingKey = "wso2.ai.pending-request-block"
	reviewKey  = "wso2.ai.high-impact-human-review"
	policyName = "custom-high-impact-decision-guardrail"
)

type P struct {
	prohibited, approved *regexp.Regexp
	max                  int
	message              string
	show                 bool
}

func (p *P) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{RequestHeaderMode: policy.HeaderModeSkip, RequestBodyMode: policy.BodyModeBuffer, ResponseHeaderMode: policy.HeaderModeSkip, ResponseBodyMode: policy.BodyModeBuffer}
}
func GetPolicy(_ policy.PolicyMetadata, x map[string]interface{}) (policy.Policy, error) {
	a, e := s(x, "prohibitedDecisionRegex", `(?i)(selecciona|elige|rechaza|contrata|rank|select).*(autom[aá]ticamente|automatically|mejor candidato|best candidate).*(edad|estado civil|situaci[oó]n familiar|condiciones m[eé]dicas|age|marital status|family status|medical conditions)`)
	if e != nil {
		return nil, e
	}
	b, e := s(x, "approvedReviewRegex", `(?i)(experiencia profesional|professional experience).*(recomendaci[oó]n preliminar|preliminary recommendation).*(revisi[oó]n humana|human review)`)
	if e != nil {
		return nil, e
	}
	ar, e := regexp.Compile(a)
	if e != nil {
		return nil, e
	}
	br, e := regexp.Compile(b)
	if e != nil {
		return nil, e
	}
	m, e := i(x, "maxBodySize", 4194304)
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
	return &P{prohibited: ar, approved: br, max: m, message: q, show: sh}, nil
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
	if !ok {
		return nil
	}
	if p.prohibited.MatchString(c) {
		var a interface{}
		if p.show {
			a = map[string]interface{}{"classification": "PROHIBITED_HIGH_IMPACT_AUTOMATED_DECISION", "protectedAttributesDetected": true, "requiredControl": "approved-attributes-and-human-review"}
		}
		return quarantine(r, x, "high-impact-decision", "Automated high-impact decision request uses prohibited sensitive attributes.", a, p.message)
	}
	if p.approved.MatchString(c) {
		if r.Metadata == nil {
			r.Metadata = map[string]interface{}{}
		}
		r.Metadata[reviewKey] = true
	}
	return nil
}
func (p *P) OnResponseBody(_ context.Context, r *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if r == nil || r.Metadata == nil {
		return policy.DownstreamResponseModifications{}
	}
	required, ok := r.Metadata[reviewKey].(bool)
	if !ok || !required {
		return policy.DownstreamResponseModifications{}
	}
	if r.ResponseBody == nil || len(r.ResponseBody.Content) == 0 {
		return p.block("high-impact-human-review", "High-impact response body is empty.", nil)
	}
	var envelope map[string]interface{}
	if json.Unmarshal(r.ResponseBody.Content, &envelope) != nil {
		return p.block("high-impact-human-review", "High-impact response is not valid JSON.", nil)
	}
	if _, ok := envelope["error"]; ok || intervention(envelope) {
		return policy.DownstreamResponseModifications{}
	}
	content, err := assistant(envelope)
	if err != nil {
		return p.block("high-impact-human-review", err.Error(), nil)
	}
	var decision map[string]interface{}
	if json.Unmarshal([]byte(content), &decision) != nil {
		return p.block("high-impact-human-review", "High-impact response content must be structured JSON.", nil)
	}
	value, ok := decision["requiresHumanReview"].(bool)
	if !ok || !value {
		return p.block("high-impact-human-review", "High-impact decision response must require human review.", map[string]interface{}{"requiresHumanReview": value})
	}
	return policy.DownstreamResponseModifications{}
}
func (p *P) block(check, reason string, a interface{}) policy.ImmediateResponse {
	m := map[string]interface{}{"action": "GUARDRAIL_INTERVENED", "actionReason": reason, "direction": "RESPONSE", "interveningGuardrail": policyName, "check": check}
	if p.show && a != nil {
		m["assessments"] = a
	}
	body, _ := json.Marshal(map[string]interface{}{"type": "HIGH_IMPACT_DECISION_GUARDRAIL", "message": m})
	return policy.ImmediateResponse{StatusCode: 422, Headers: map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store"}, Body: body}
}
func quarantine(r *policy.RequestContext, x map[string]interface{}, check, reason string, a interface{}, message string) policy.RequestAction {
	if r.Metadata == nil {
		r.Metadata = map[string]interface{}{}
	}
	r.Metadata[pendingKey] = map[string]interface{}{"policy": policyName, "check": check, "reason": reason, "assessment": a}
	safe := map[string]interface{}{"model": "gpt-4o-mini", "temperature": 0, "stream": false, "messages": []interface{}{map[string]interface{}{"role": "user", "content": message}}}
	if model, ok := x["model"]; ok {
		safe["model"] = model
	}
	body, _ := json.Marshal(safe)
	return policy.UpstreamRequestModifications{Body: body}
}
func assistant(x map[string]interface{}) (string, error) {
	v, ok := x["choices"].([]interface{})
	if !ok || len(v) == 0 {
		return "", errors.New("choices is missing")
	}
	c, ok := v[0].(map[string]interface{})
	if !ok {
		return "", errors.New("choice is invalid")
	}
	m, ok := c["message"].(map[string]interface{})
	if !ok {
		return "", errors.New("assistant message is missing")
	}
	s, ok := m["content"].(string)
	if !ok {
		return "", errors.New("assistant content is missing")
	}
	return s, nil
}
func intervention(x map[string]interface{}) bool {
	m, ok := x["message"].(map[string]interface{})
	if !ok {
		return false
	}
	a, _ := m["action"].(string)
	return a == "GUARDRAIL_INTERVENED"
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
