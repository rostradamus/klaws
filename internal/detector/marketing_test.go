package detector_test

import (
	"os"
	"testing"

	"github.com/rostradamus/klaws/internal/detector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarketingConsentDetector_Detects_MissingConsent(t *testing.T) {
	src, err := os.ReadFile("../../testdata/MarketingService.java")
	require.NoError(t, err)

	d := detector.NewMarketingConsentDetector()
	findings := d.Scan(string(src), "MarketingService.java")

	assert.Equal(t, 1, len(findings), "should find 1 marketing message without consent")

	for _, f := range findings {
		assert.Equal(t, "NIA-MKT-001", f.DetectorID)
		assert.Equal(t, "MEDIUM", f.RiskLevel)
		assert.Contains(t, f.Message, "may require review")
		assert.Contains(t, f.RelatedLaws, "NIA-50")
	}
}

func TestMarketingConsentDetector_SkipsConsented(t *testing.T) {
	src := `
    public void sendPromotion(String email) {
        if (!user.hasMarketingConsent()) { return; }
        mailer.sendEmail(email, "marketing newsletter");
    }`
	d := detector.NewMarketingConsentDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestMarketingConsentDetector_SkipsNonMarketingSend(t *testing.T) {
	src := `
    public void sendReceipt(String email) {
        mailer.sendEmail(email, "Your order receipt");
    }`
	d := detector.NewMarketingConsentDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestMarketingConsentDetector_UnsubscribeDoesNotSuppress(t *testing.T) {
	// An "unsubscribe" footer must not be mistaken for opt-in consent.
	src := `
    public void blast(String email) {
        String body = "Our latest marketing promotion. To unsubscribe click here.";
        mailer.sendEmail(email, body);
    }`
	d := detector.NewMarketingConsentDetector()
	findings := d.Scan(src, "Blast.java")
	assert.Equal(t, 1, len(findings))
	assert.Equal(t, "NIA-MKT-001", findings[0].DetectorID)
}

func TestMarketingConsentDetector_Detects_KoreanIntent(t *testing.T) {
	src := `
    public void blast(String phone) {
        String body = "광고 마케팅 메시지";
        smsClient.send(phone, body);
    }`
	d := detector.NewMarketingConsentDetector()
	findings := d.Scan(src, "Korean.java")
	assert.Equal(t, 1, len(findings))
	assert.Equal(t, "NIA-MKT-001", findings[0].DetectorID)
}

func TestMarketingConsentDetector_IgnoresIntentInComments(t *testing.T) {
	// Advertising intent that appears only in a comment must not trigger a
	// finding — detection is based on executable code, consistent with the
	// other detectors.
	src := `
    // send the marketing promotion newsletter to users here
    public void notifyUser(String email) {
        mailer.sendEmail(email, "Your account summary");
    }`
	d := detector.NewMarketingConsentDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestMarketingConsentDetector_Metadata(t *testing.T) {
	d := detector.NewMarketingConsentDetector()
	assert.Equal(t, "NIA-MKT-001", d.ID())
	assert.Equal(t, []string{"NIA-50"}, d.RelatedLawIDs())
}
