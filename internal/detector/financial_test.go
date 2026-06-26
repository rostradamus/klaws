package detector_test

import (
	"os"
	"testing"

	"github.com/rostradamus/klaws/internal/detector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFinancialDataDetector_Detects_UnprotectedFields(t *testing.T) {
	src, err := os.ReadFile("../../testdata/PaymentEntity.java")
	require.NoError(t, err)

	d := detector.NewFinancialDataDetector()
	findings := d.Scan(string(src), "PaymentEntity.java")

	assert.Equal(t, 2, len(findings), "should find 2 unprotected credit information fields")

	for _, f := range findings {
		assert.Equal(t, "CIA-ENC-001", f.DetectorID)
		assert.Equal(t, "HIGH", f.RiskLevel)
		assert.Contains(t, f.Message, "Possible unprotected credit information")
		assert.Contains(t, f.Message, "may require review")
		assert.Contains(t, f.RelatedLaws, "CIA-19")
	}
}

func TestFinancialDataDetector_SkipsProtectedField(t *testing.T) {
	src := `
    @Encrypted
    private String cardNumber;`
	d := detector.NewFinancialDataDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestFinancialDataDetector_NoFalsePositives(t *testing.T) {
	src := `private String username;`
	d := detector.NewFinancialDataDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestFinancialDataDetector_IgnoresSimilarFieldNames(t *testing.T) {
	// "accountNotes"/"cardHolder" share a prefix but are not credit identifiers.
	src := `
    private String accountNotes;
    private String cardHolder;`
	d := detector.NewFinancialDataDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestFinancialDataDetector_Detects_KoreanField(t *testing.T) {
	src := `private String 카드번호;`
	d := detector.NewFinancialDataDetector()
	findings := d.Scan(src, "Korean.java")
	assert.Equal(t, 1, len(findings))
	assert.Equal(t, "CIA-ENC-001", findings[0].DetectorID)
}

func TestFinancialDataDetector_Metadata(t *testing.T) {
	d := detector.NewFinancialDataDetector()
	assert.Equal(t, "CIA-ENC-001", d.ID())
	assert.Equal(t, []string{"CIA-19"}, d.RelatedLawIDs())
}
