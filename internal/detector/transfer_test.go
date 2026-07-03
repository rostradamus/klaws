package detector_test

import (
	"os"
	"testing"

	"github.com/rostradamus/klaws/internal/detector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThirdPartyTransferDetector_Detects_ExternalTransfer(t *testing.T) {
	src, err := os.ReadFile("../../testdata/TransferService.java")
	require.NoError(t, err)

	d := detector.NewThirdPartyTransferDetector()
	findings := d.Scan(string(src), "TransferService.java")

	assert.Equal(t, 1, len(findings), "should flag one external transfer of personal data")

	f := findings[0]
	assert.Equal(t, "PIPA-XBR-001", f.DetectorID)
	assert.Equal(t, "HIGH", f.RiskLevel)
	assert.Contains(t, f.Message, "may require review")
	assert.Contains(t, f.RelatedLaws, "PIPA-17")
}

func TestThirdPartyTransferDetector_SkipsWhenConsentPresent(t *testing.T) {
	src := `
    public void share(String email) {
        if (!user.hasProvisionConsent()) { return; }
        restTemplate.postForObject("https://partner.example.com/api", email, Void.class);
    }`
	d := detector.NewThirdPartyTransferDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestThirdPartyTransferDetector_SkipsInternalCall(t *testing.T) {
	// No external/third-party signal — an internal save is not a transfer.
	src := `
    public void save(String email) {
        userRepository.save(new User(email));
    }`
	d := detector.NewThirdPartyTransferDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestThirdPartyTransferDetector_SkipsWhenNoPersonalData(t *testing.T) {
	// External call, but no personal data in the payload.
	src := `
    public void ping() {
        restTemplate.postForObject("https://partner.example.com/health", "ping", Void.class);
    }`
	d := detector.NewThirdPartyTransferDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestThirdPartyTransferDetector_Detects_KoreanSignals(t *testing.T) {
	src := `
    public void 제공(String 이메일) {
        client.send(외부API, 이메일);
    }`
	d := detector.NewThirdPartyTransferDetector()
	findings := d.Scan(src, "Korean.java")
	assert.Equal(t, 1, len(findings))
	assert.Equal(t, "PIPA-XBR-001", findings[0].DetectorID)
}

func TestThirdPartyTransferDetector_Metadata(t *testing.T) {
	d := detector.NewThirdPartyTransferDetector()
	assert.Equal(t, "PIPA-XBR-001", d.ID())
	assert.Equal(t, []string{"PIPA-17"}, d.RelatedLawIDs())
}
