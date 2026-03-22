package detector_test

import (
	"os"
	"testing"

	"github.com/rostradamus/dev-lawyer/internal/detector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptionDetector_Detects_UnencryptedFields(t *testing.T) {
	src, err := os.ReadFile("../../testdata/MemberEntity.java")
	require.NoError(t, err)

	d := detector.NewEncryptionDetector()
	findings := d.Scan(string(src), "MemberEntity.java")

	assert.Equal(t, 2, len(findings), "should find 2 unencrypted personal data fields")

	for _, f := range findings {
		assert.Equal(t, "PIPA-ENC-001", f.DetectorID)
		assert.Equal(t, "HIGH", f.RiskLevel)
		assert.Contains(t, f.Message, "Possible unencrypted personal identifier")
		assert.Contains(t, f.Message, "may require review")
	}
}

func TestEncryptionDetector_NoFalsePositives(t *testing.T) {
	src := `private String username;`
	d := detector.NewEncryptionDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestEncryptionDetector_Metadata(t *testing.T) {
	d := detector.NewEncryptionDetector()
	assert.Equal(t, "PIPA-ENC-001", d.ID())
	assert.Contains(t, d.RelatedLawIDs(), "PIPA-24-2")
	assert.Contains(t, d.RelatedLawIDs(), "PIPA-29")
}
