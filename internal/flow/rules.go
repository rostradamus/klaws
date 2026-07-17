package flow

import "strings"

// Sensitivity grades how sensitive a category of personal data is under PIPA.
type Sensitivity int

const (
	// SensGeneral is ordinary personal data (email, phone, address, name).
	SensGeneral Sensitivity = iota
	// SensFinancial is payment and account data.
	SensFinancial
	// SensUnique is 고유식별정보 — unique identifying information under PIPA 제24조.
	SensUnique
)

// SourceRule describes a category of personal data and the identifier patterns
// that indicate it. Patterns match whole words, not substrings.
type SourceRule struct {
	ID       string
	Label    string // human-facing, appears in findings
	Sens     Sensitivity
	Patterns []string
}

// SinkKind classifies where tainted data ends up.
type SinkKind int

const (
	SinkLog SinkKind = iota
	SinkTransmit
	SinkPersist
)

// SinkRule describes a dangerous destination and the provisions it relates to.
type SinkRule struct {
	Kind     SinkKind
	Label    string // human-facing, appears in findings
	Laws     []string
	Patterns []string
}

// DefaultSources is the curated personal-data catalogue. Kept as plain data so a
// future .klaws.yaml override can extend it without touching the engine.
var DefaultSources = []SourceRule{
	{ID: "ssn", Label: "주민등록번호", Sens: SensUnique,
		Patterns: []string{"ssn", "rrn", "jumin", "주민등록번호", "주민번호", "residentRegistration"}},
	{ID: "passport", Label: "여권번호", Sens: SensUnique,
		Patterns: []string{"passport", "여권번호", "driverLicense", "운전면허"}},
	{ID: "card", Label: "카드·계좌번호", Sens: SensFinancial,
		Patterns: []string{"cardNumber", "cardNo", "카드번호", "accountNumber", "accountNo", "계좌번호", "bankAccount"}},
	{ID: "phone", Label: "전화번호", Sens: SensGeneral,
		Patterns: []string{"phone", "mobile", "전화번호", "휴대폰"}},
	{ID: "email", Label: "이메일", Sens: SensGeneral,
		Patterns: []string{"email", "이메일"}},
	{ID: "address", Label: "주소", Sens: SensGeneral,
		Patterns: []string{"address", "주소"}},
	{ID: "name", Label: "성명", Sens: SensGeneral,
		Patterns: []string{"userName", "realName", "이름", "성명",
			"firstName", "lastName", "fullName", "customerName", "middleName", "memberName"}},
}

// DefaultSinks maps destinations to the provisions they relate to. Every ID here
// must exist in internal/law/laws/pipa.yaml — see TestEveryLawIDInSinkRulesIsValid.
var DefaultSinks = []SinkRule{
	{Kind: SinkLog, Label: "log output", Laws: []string{"PIPA-29"},
		Patterns: []string{"log.info", "log.debug", "log.warn", "log.error", "logger.",
			"System.out.print", "System.err.print", "printStackTrace"}},
	{Kind: SinkTransmit, Label: "external transmission", Laws: []string{"PIPA-17"},
		Patterns: []string{"restTemplate.", "webClient.", "okHttpClient.", "httpClient.",
			"HttpEntity", "FeignClient", "URLConnection"}},
	{Kind: SinkPersist, Label: "storage without visible encryption", Laws: []string{"PIPA-24-2", "PIPA-29"},
		Patterns: []string{"repository.save", "entityManager.persist", "jdbcTemplate.update",
			"Files.write", "FileWriter", "preparedStatement.set"}},
}

// DefaultSanitizers clear taint. This is the primary false-positive defense.
var DefaultSanitizers = []string{
	"encrypt", "mask", "hash", "redact", "anonymize", "pseudonym",
	"aes", "sha", "bcrypt", "digest",
}

// MatchSource reports whether an identifier names personal data. Matching is
// word-based: "accountingPeriod" does not match the "account" pattern, because
// substring matching is the classic source of false positives.
func MatchSource(name string) (SourceRule, bool) {
	words := splitWords(name)
	if len(words) == 0 {
		return SourceRule{}, false
	}

	for _, rule := range DefaultSources {
		for _, pattern := range rule.Patterns {
			want := normalizePattern(pattern)
			if matchesWordRun(words, want) {
				return rule, true
			}
		}
	}
	return SourceRule{}, false
}

// matchesWordRun reports whether any contiguous run of words joins to want.
// This lets a multi-word pattern ("cardNumber") match ["card","number"] while a
// single-word pattern ("ssn") matches the "ssn" word in ["user","ssn"].
func matchesWordRun(words []string, want string) bool {
	for i := range words {
		joined := ""
		for j := i; j < len(words); j++ {
			joined += words[j]
			if joined == want {
				return true
			}
			if len(joined) > len(want) {
				break
			}
		}
	}
	return false
}

func normalizePattern(p string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(p))
}

// MatchSink reports whether a dotted call expression is a dangerous destination.
// Sink patterns are call fragments ("log.info", "restTemplate."), so substring
// matching is correct here — unlike source matching.
func MatchSink(callText string) (SinkRule, bool) {
	lc := strings.ToLower(callText)
	for _, rule := range DefaultSinks {
		for _, pattern := range rule.Patterns {
			if strings.Contains(lc, strings.ToLower(pattern)) {
				return rule, true
			}
		}
	}
	return SinkRule{}, false
}

// IsSanitizer reports whether a call neutralizes personal data. Matching is
// word-based against the invoked method name — the last dotted segment — so
// "hashMap.put" is not mistaken for a hash. A receiver's name sanitizes
// nothing; only the method it invokes can.
func IsSanitizer(callText string) bool {
	segments := strings.Split(callText, ".")
	method := segments[len(segments)-1]
	words := splitWords(method)
	// Object.hashCode() is an identity/content hash for use in hashmaps, not a
	// cryptographic or anonymizing operation — it must not clear taint even
	// though its word-run contains the bare "hash" sanitizer word.
	if matchesWordRun(words, "hashcode") {
		return false
	}
	for _, word := range words {
		for _, s := range DefaultSanitizers {
			if word == s {
				return true
			}
		}
	}
	return false
}
