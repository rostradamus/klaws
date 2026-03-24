package detector_test

import (
	"os"
	"testing"

	"github.com/rostradamus/klaws/internal/detector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConsentDetector_Detects_MissingConsent(t *testing.T) {
	src, err := os.ReadFile("../../testdata/MemberController.java")
	require.NoError(t, err)

	d := detector.NewConsentDetector()
	findings := d.Scan(string(src), "MemberController.java")

	assert.Equal(t, 2, len(findings), "should find 2 missing consent risks")

	for _, f := range findings {
		assert.Equal(t, "PIPA-CST-001", f.DetectorID)
		assert.Equal(t, "HIGH", f.RiskLevel)
		assert.Contains(t, f.Message, "may require review")
		assert.Contains(t, f.RelatedLaws, "PIPA-15")
	}
}

func TestConsentDetector_SkipsConsented(t *testing.T) {
	src := `
    @PostMapping("/register")
    public void register(String email) {
        if (!consent) { return; }
        save(email);
    }`
	d := detector.NewConsentDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestConsentDetector_SkipsGetMapping(t *testing.T) {
	src := `
    @GetMapping("/users")
    public List<User> getUsers(String email) {
        return userService.findByEmail(email);
    }`
	d := detector.NewConsentDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestConsentDetector_Metadata(t *testing.T) {
	d := detector.NewConsentDetector()
	assert.Equal(t, "PIPA-CST-001", d.ID())
	assert.Equal(t, []string{"PIPA-15"}, d.RelatedLawIDs())
}
