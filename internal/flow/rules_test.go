package flow_test

import (
	"testing"

	"github.com/rostradamus/klaws/internal/flow"
	"github.com/stretchr/testify/assert"
)

func TestMatchSourceOnGetterAndField(t *testing.T) {
	cases := map[string]string{
		"getSsn":        "ssn",
		"ssn":           "ssn",
		"userSsn":       "ssn",
		"주민등록번호":        "ssn",
		"cardNumber":    "card",
		"getEmail":      "email",
		"phone":         "phone",
		"passport":      "passport",
		"driverLicense": "driverLicense",
	}
	for name, wantID := range cases {
		rule, ok := flow.MatchSource(name)
		assert.True(t, ok, "expected %q to match a source", name)
		assert.Equal(t, wantID, rule.ID, "input: %q", name)
	}
}

// A driver's-license match must not surface the passport label. Both are
// 고유식별정보 (SensUnique), but the finding label is user-facing, so a
// driverLicense field must read "운전면허번호", not "여권번호".
func TestMatchSourceDriverLicenseHasItsOwnLabel(t *testing.T) {
	dl, ok := flow.MatchSource("driverLicense")
	assert.True(t, ok)
	assert.Equal(t, "운전면허번호", dl.Label)
	assert.Equal(t, flow.SensUnique, dl.Sens)

	pp, ok := flow.MatchSource("passport")
	assert.True(t, ok)
	assert.Equal(t, "여권번호", pp.Label)
}

func TestMatchSourceIsWordBoundaryAware(t *testing.T) {
	// "accountingPeriod" contains "account" as a substring but not as a word.
	// A naive strings.Contains matcher would produce a false positive here.
	_, ok := flow.MatchSource("accountingPeriod")
	assert.False(t, ok, "substring match must not seed taint")
}

func TestMatchSourceRejectsUnrelatedNames(t *testing.T) {
	for _, name := range []string{"user", "UserDto", "total", "index", "i"} {
		_, ok := flow.MatchSource(name)
		assert.False(t, ok, "input: %q", name)
	}
}

func TestSourceSensitivity(t *testing.T) {
	ssn, _ := flow.MatchSource("ssn")
	assert.Equal(t, flow.SensUnique, ssn.Sens)

	card, _ := flow.MatchSource("cardNumber")
	assert.Equal(t, flow.SensFinancial, card.Sens)

	email, _ := flow.MatchSource("email")
	assert.Equal(t, flow.SensGeneral, email.Sens)
}

func TestMatchSink(t *testing.T) {
	cases := map[string]flow.SinkKind{
		"log.info":                   flow.SinkLog,
		"logger.debug":               flow.SinkLog,
		"System.out.print":           flow.SinkLog,
		"e.printStackTrace":          flow.SinkLog,
		"restTemplate.postForObject": flow.SinkTransmit,
		"webClient.post":             flow.SinkTransmit,
		"repository.save":            flow.SinkPersist,
		"jdbcTemplate.update":        flow.SinkPersist,
	}
	for call, wantKind := range cases {
		rule, ok := flow.MatchSink(call)
		assert.True(t, ok, "expected %q to match a sink", call)
		assert.Equal(t, wantKind, rule.Kind, "input: %q", call)
	}
}

func TestMatchSinkRejectsOrdinaryCalls(t *testing.T) {
	for _, call := range []string{"list.add", "map.get", "service.compute"} {
		_, ok := flow.MatchSink(call)
		assert.False(t, ok, "input: %q", call)
	}
}

func TestIsSanitizer(t *testing.T) {
	for _, call := range []string{"encrypt", "AesUtil.encrypt", "mask", "hashPassword", "redact", "anonymize"} {
		assert.True(t, flow.IsSanitizer(call), "input: %q", call)
	}
}

func TestIsSanitizerIsWordBoundaryAware(t *testing.T) {
	// "hashMap.put" contains "hash" as a substring. Treating it as a sanitizer
	// would silently swallow real findings.
	assert.False(t, flow.IsSanitizer("hashMap.put"), "substring match must not clear taint")
}

func TestEveryLawIDInSinkRulesIsValid(t *testing.T) {
	// Guard against citing a provision the law registry cannot resolve. An early
	// spec draft cited PIPA-24-3 and PIPA-28-2, neither of which exists.
	valid := map[string]bool{
		"PIPA-17": true, "PIPA-24": true, "PIPA-24-2": true, "PIPA-29": true,
	}
	for _, sink := range flow.DefaultSinks {
		assert.NotEmpty(t, sink.Laws, "sink %v must cite at least one provision", sink.Kind)
		for _, id := range sink.Laws {
			assert.True(t, valid[id], "sink %v cites unknown law ID %q", sink.Kind, id)
		}
	}
}

func TestEverySourceRuleHasLabelAndPatterns(t *testing.T) {
	for _, src := range flow.DefaultSources {
		assert.NotEmpty(t, src.ID)
		assert.NotEmpty(t, src.Label, "source %q needs a human-facing label", src.ID)
		assert.NotEmpty(t, src.Patterns, "source %q needs patterns", src.ID)
	}
}

// --- Fix 1: hashCode must not clear taint (Object.hashCode() is not anonymization) ---

func TestIsSanitizerHashCodeIsNotSanitizer(t *testing.T) {
	for _, call := range []string{"obj.hashCode", "ssn.hashCode", "user.getHashCode"} {
		assert.False(t, flow.IsSanitizer(call), "input: %q — hashCode must not silently clear taint", call)
	}
}

func TestIsSanitizerHashPasswordStillSanitizes(t *testing.T) {
	assert.True(t, flow.IsSanitizer("hashPassword"), "hashPassword must still be a sanitizer")
}

func TestIsSanitizerUnchangedCases(t *testing.T) {
	assert.True(t, flow.IsSanitizer("AesUtil.encrypt"))
	assert.False(t, flow.IsSanitizer("hashMap.put"))
}

// --- Fix 2: the "name" source rule must cover the real-name field family ---

func TestMatchSourceNameFamilyMatches(t *testing.T) {
	for _, name := range []string{"firstName", "lastName", "fullName", "customerName", "middleName"} {
		rule, ok := flow.MatchSource(name)
		assert.True(t, ok, "expected %q to match a source", name)
		assert.Equal(t, "name", rule.ID, "input: %q", name)
	}
}

func TestMatchSourceNameFamilyDoesNotOverbroaden(t *testing.T) {
	// Regression guard: adding bare "name" would flood with false positives on
	// identifiers like fileName/className that merely end in "Name".
	for _, name := range []string{"fileName", "className"} {
		_, ok := flow.MatchSource(name)
		assert.False(t, ok, "input: %q must not match the name rule", name)
	}
}

// --- Fix 3: bare "account" is too broad a source pattern ---

func TestMatchSourceAccountBareWordDoesNotMatch(t *testing.T) {
	for _, name := range []string{"accountId", "accountService", "accountRepository"} {
		_, ok := flow.MatchSource(name)
		assert.False(t, ok, "input: %q must not match — bare account is too broad", name)
	}
}

func TestMatchSourceAccountNumberFamilyStillMatches(t *testing.T) {
	for _, name := range []string{"accountNumber", "accountNo", "bankAccount"} {
		rule, ok := flow.MatchSource(name)
		assert.True(t, ok, "expected %q to match a source", name)
		assert.Equal(t, "card", rule.ID, "input: %q", name)
		assert.Equal(t, flow.SensFinancial, rule.Sens, "input: %q", name)
	}
}

func TestMatchSourceKoreanAccountNumberUnchanged(t *testing.T) {
	rule, ok := flow.MatchSource("계좌번호")
	assert.True(t, ok)
	assert.Equal(t, "card", rule.ID)
}
