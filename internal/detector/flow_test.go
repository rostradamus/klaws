package detector_test

import (
	"testing"

	"github.com/rostradamus/klaws/internal/detector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const flowSample = `class UserService {
  void register(UserDto user) {
    String s = user.getSsn();
    String msg = "id=" + s;
    log.info(msg);
  }
}`

func TestFlowDetectorMetadata(t *testing.T) {
	d := detector.NewFlowDetector()

	assert.Equal(t, "PIPA-FLOW-001", d.ID())
	assert.Equal(t, "Personal Data Flow Risk", d.Name())
	assert.NotEmpty(t, d.Description())
	assert.ElementsMatch(t, []string{"PIPA-17", "PIPA-24", "PIPA-24-2", "PIPA-29"}, d.RelatedLawIDs())
}

func TestFlowDetectorProducesFindingAnchoredAtSink(t *testing.T) {
	findings := detector.NewFlowDetector().Scan(flowSample, "UserService.java")

	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "PIPA-FLOW-001", f.DetectorID)
	assert.Equal(t, "HIGH", f.RiskLevel)
	assert.Equal(t, "UserService.java", f.FilePath)
	assert.Equal(t, 5, f.LineNumber, "finding anchors at the sink — the line to change")
	assert.Contains(t, f.Snippet, "log.info")
	assert.ElementsMatch(t, []string{"PIPA-29", "PIPA-24"}, f.RelatedLaws)
}

func TestFlowDetectorAttachesTrace(t *testing.T) {
	findings := detector.NewFlowDetector().Scan(flowSample, "UserService.java")

	require.Len(t, findings, 1)
	trace := findings[0].Trace
	require.Len(t, trace, 3)
	assert.Equal(t, "source", trace[0].Kind)
	assert.Equal(t, "propagate", trace[1].Kind)
	assert.Equal(t, "sink", trace[2].Kind)
	assert.Equal(t, 3, trace[0].Line)
	assert.Equal(t, 5, trace[2].Line)
	assert.Contains(t, trace[1].Note, "concat")
}

func TestFlowDetectorMessageIsHedged(t *testing.T) {
	findings := detector.NewFlowDetector().Scan(flowSample, "UserService.java")
	msg := findings[0].Message

	assert.Contains(t, msg, "Possible")
	assert.Contains(t, msg, "may require review")
	assert.Contains(t, msg, "주민등록번호")
	for _, banned := range []string{"violation", "illegal", "non-compliant", "you must"} {
		assert.NotContains(t, msg, banned, "user-facing text must stay hedged")
	}
}

func TestFlowDetectorRiskMatrix(t *testing.T) {
	cases := []struct {
		name   string
		getter string
		sink   string
		want   string
	}{
		{"unique to log", "getSsn", "log.info(s);", "HIGH"},
		{"unique to transmit", "getSsn", "restTemplate.postForObject(s);", "HIGH"},
		{"unique to persist", "getSsn", "repository.save(s);", "HIGH"},
		{"financial to log", "getCardNumber", "log.info(s);", "HIGH"},
		{"financial to transmit", "getCardNumber", "restTemplate.postForObject(s);", "HIGH"},
		{"financial to persist", "getCardNumber", "repository.save(s);", "MEDIUM"},
		{"general to log", "getEmail", "log.info(s);", "MEDIUM"},
		{"general to transmit", "getEmail", "restTemplate.postForObject(s);", "HIGH"},
		{"general to persist", "getEmail", "repository.save(s);", "LOW"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "class T {\n  void m(UserDto user) {\n    String s = user." + tc.getter + "();\n    " + tc.sink + "\n  }\n}"
			findings := detector.NewFlowDetector().Scan(src, "T.java")
			require.Len(t, findings, 1)
			assert.Equal(t, tc.want, findings[0].RiskLevel)
		})
	}
}

func TestFlowDetectorSuppressesPersistenceInTestFiles(t *testing.T) {
	src := "class T {\n  void m(UserDto user) {\n    String s = user.getSsn();\n    repository.save(s);\n  }\n}"

	for _, path := range []string{
		"src/test/java/UserServiceTest.java",
		"UserServiceTests.java",
		"UserServiceIT.java",
	} {
		assert.Empty(t, detector.NewFlowDetector().Scan(src, path), "path: %s", path)
	}

	assert.Len(t, detector.NewFlowDetector().Scan(src, "src/main/java/UserService.java"), 1,
		"production code is still reported")
}

func TestFlowDetectorCitesOnlyKnownLawIDs(t *testing.T) {
	valid := map[string]bool{"PIPA-17": true, "PIPA-24": true, "PIPA-24-2": true, "PIPA-29": true}

	srcs := []string{
		"class T { void m(UserDto u) { log.info(u.getSsn()); } }",
		"class T { void m(UserDto u) { restTemplate.postForObject(u.getEmail()); } }",
		"class T { void m(UserDto u) { repository.save(u.getCardNumber()); } }",
	}
	for _, src := range srcs {
		for _, f := range detector.NewFlowDetector().Scan(src, "T.java") {
			assert.NotEmpty(t, f.RelatedLaws)
			for _, id := range f.RelatedLaws {
				assert.True(t, valid[id], "finding cites unknown law ID %q", id)
			}
		}
	}
}

func TestFlowDetectorReturnsNoFindingsForCleanCode(t *testing.T) {
	src := "class T {\n  void m() {\n    int total = 1 + 2;\n    log.info(\"total=\" + total);\n  }\n}"
	assert.Empty(t, detector.NewFlowDetector().Scan(src, "T.java"))
}

// PIPA-24-2 (제24조의2) governs resident registration numbers specifically, not
// unique identifiers in general and not other data categories. A persistence
// finding should cite it only when the source is actually a resident
// registration number, never for a passport number (also SensUnique), a card
// number, or an email reaching the same sink.
func TestFlowDetectorCitesPIPA24_2OnlyForResidentRegistrationNumber(t *testing.T) {
	cases := []struct {
		name    string
		getter  string
		wantHas bool
	}{
		{"resident registration number cites PIPA-24-2", "getSsn", true},
		{"passport number does not cite PIPA-24-2", "getPassportNumber", false},
		{"card number does not cite PIPA-24-2", "getCardNumber", false},
		{"email does not cite PIPA-24-2", "getEmail", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "class T {\n  void m(UserDto user) {\n    String s = user." + tc.getter + "();\n    repository.save(s);\n  }\n}"
			findings := detector.NewFlowDetector().Scan(src, "T.java")
			require.Len(t, findings, 1)
			assert.Equal(t, tc.wantHas, contains(findings[0].RelatedLaws, "PIPA-24-2"))
		})
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
