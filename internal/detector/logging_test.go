package detector_test

import (
	"os"
	"testing"

	"github.com/rostradamus/klaws/internal/detector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoggingDetector_Detects_PersonalData(t *testing.T) {
	src, err := os.ReadFile("../../testdata/UserService.java")
	require.NoError(t, err)

	d := detector.NewLoggingDetector()
	findings := d.Scan(string(src), "UserService.java")

	assert.Equal(t, 3, len(findings), "should find 3 personal data logging risks")

	for _, f := range findings {
		assert.Equal(t, "PIPA-LOG-001", f.DetectorID)
		assert.Equal(t, "MEDIUM", f.RiskLevel)
		assert.Contains(t, f.Message, "Possible personal data")
		assert.Contains(t, f.Message, "may require review")
		assert.Contains(t, f.RelatedLaws, "PIPA-29")
	}
}

func TestLoggingDetector_NoFalsePositives(t *testing.T) {
	src := `log.info("User registration completed successfully");`
	d := detector.NewLoggingDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestLoggingDetector_Metadata(t *testing.T) {
	d := detector.NewLoggingDetector()
	assert.Equal(t, "PIPA-LOG-001", d.ID())
	assert.Equal(t, "Personal Data Logging Risk", d.Name())
	assert.Equal(t, []string{"PIPA-29"}, d.RelatedLawIDs())
}
