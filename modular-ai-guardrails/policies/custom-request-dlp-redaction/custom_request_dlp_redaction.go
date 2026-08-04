package customrequestdlpredaction

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const pendingRequestBlockMetadataKey = "wso2.ai.pending-request-block"

var emailPattern = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
var phonePattern = regexp.MustCompile(`\+[1-9][0-9 ()\.\-]{7,18}[0-9]`)
var cardCandidatePattern = regexp.MustCompile(`\b(?:[0-9][ -]?){13,19}\b`)
var ibanCandidatePattern = regexp.MustCompile(`(?i)\b[A-Z]{2}[0-9]{2}[A-Z0-9 ]{11,30}\b`)
var secretPattern = regexp.MustCompile(`(?i)(sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)`)

type RequestDLPRedactionPolicy struct {
	replacement                       string
	email, phone, card, iban, secrets bool
	maxRequestBodySize                int
}

func (p *RequestDLPRedactionPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{RequestHeaderMode: policy.HeaderModeSkip, RequestBodyMode: policy.BodyModeBuffer, ResponseHeaderMode: policy.HeaderModeSkip, ResponseBodyMode: policy.BodyModeSkip}
}
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	replacement, err := stringParameter(params, "replacement", "*****")
	if err != nil {
		return nil, err
	}
	if replacement == "" {
		return nil, fmt.Errorf("replacement must not be empty")
	}
	email, err := booleanParameter(params, "redactEmail", true)
	if err != nil {
		return nil, err
	}
	phone, err := booleanParameter(params, "redactPhone", true)
	if err != nil {
		return nil, err
	}
	card, err := booleanParameter(params, "redactPaymentCard", true)
	if err != nil {
		return nil, err
	}
	iban, err := booleanParameter(params, "redactIBAN", true)
	if err != nil {
		return nil, err
	}
	secrets, err := booleanParameter(params, "redactSecrets", true)
	if err != nil {
		return nil, err
	}
	maxSize, err := integerParameter(params, "maxRequestBodySize", 1048576)
	if err != nil {
		return nil, err
	}
	return &RequestDLPRedactionPolicy{replacement: replacement, email: email, phone: phone, card: card, iban: iban, secrets: secrets, maxRequestBodySize: maxSize}, nil
}
func (p *RequestDLPRedactionPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if reqCtx == nil || pending(reqCtx.Metadata) || reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 || len(reqCtx.Body.Content) > p.maxRequestBodySize {
		return nil
	}
	var payload map[string]interface{}
	if json.Unmarshal(reqCtx.Body.Content, &payload) != nil {
		return nil
	}
	messages, ok := payload["messages"].([]interface{})
	if !ok {
		return nil
	}
	totals := map[string]int{"email": 0, "phone": 0, "paymentCard": 0, "iban": 0, "secret": 0}
	changed := false
	for _, raw := range messages {
		message, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		content, ok := message["content"].(string)
		if !ok {
			continue
		}
		redacted, counts := p.redact(content)
		if redacted != content {
			message["content"] = redacted
			changed = true
		}
		for key, value := range counts {
			totals[key] += value
		}
	}
	if !changed {
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return policy.UpstreamRequestModifications{Body: body, AnalyticsMetadata: map[string]interface{}{"ai.security.dlp.redacted": true, "ai.security.dlp.email_count": totals["email"], "ai.security.dlp.phone_count": totals["phone"], "ai.security.dlp.card_count": totals["paymentCard"], "ai.security.dlp.iban_count": totals["iban"], "ai.security.dlp.secret_count": totals["secret"]}}
}
func (p *RequestDLPRedactionPolicy) redact(value string) (string, map[string]int) {
	counts := map[string]int{"email": 0, "phone": 0, "paymentCard": 0, "iban": 0, "secret": 0}
	result := value
	if p.email {
		result = emailPattern.ReplaceAllStringFunc(result, func(string) string { counts["email"]++; return p.replacement })
	}
	if p.phone {
		result = phonePattern.ReplaceAllStringFunc(result, func(string) string { counts["phone"]++; return p.replacement })
	}
	if p.card {
		result = cardCandidatePattern.ReplaceAllStringFunc(result, func(candidate string) string {
			digits := digitsOnly(candidate)
			if len(digits) >= 13 && len(digits) <= 19 && luhnValid(digits) {
				counts["paymentCard"]++
				return p.replacement
			}
			return candidate
		})
	}
	if p.iban {
		result = ibanCandidatePattern.ReplaceAllStringFunc(result, func(candidate string) string {
			compact := strings.ToUpper(strings.ReplaceAll(candidate, " ", ""))
			if ibanValid(compact) {
				counts["iban"]++
				return p.replacement
			}
			return candidate
		})
	}
	if p.secrets {
		result = secretPattern.ReplaceAllStringFunc(result, func(string) string { counts["secret"]++; return p.replacement })
	}
	return result, counts
}
func digitsOnly(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		return -1
	}, value)
}
func luhnValid(value string) bool {
	sum := 0
	parity := len(value) % 2
	for i, r := range value {
		d := int(r - '0')
		if i%2 == parity {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}
func ibanValid(value string) bool {
	if len(value) < 15 || len(value) > 34 {
		return false
	}
	rearranged := value[4:] + value[:4]
	remainder := 0
	for _, r := range rearranged {
		if r >= '0' && r <= '9' {
			remainder = (remainder*10 + int(r-'0')) % 97
		} else if r >= 'A' && r <= 'Z' {
			n := int(r-'A') + 10
			remainder = (remainder*100 + n) % 97
		} else {
			return false
		}
	}
	return remainder == 1
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
		return "", fmt.Errorf("parameter %q must be a string", name)
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
		return false, fmt.Errorf("parameter %q must be a boolean", name)
	}
	return b, nil
}
func integerParameter(params map[string]interface{}, name string, fallback int) (int, error) {
	v, ok := params[name]
	if !ok || v == nil {
		return fallback, nil
	}
	switch n := v.(type) {
	case int:
		return n, nil
	case int32:
		return int(n), nil
	case int64:
		return int(n), nil
	case float64:
		return int(n), nil
	case json.Number:
		i, e := n.Int64()
		return int(i), e
	default:
		return 0, fmt.Errorf("parameter %q must be an integer", name)
	}
}
