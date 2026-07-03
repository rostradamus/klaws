package detector_test

import (
	"os"
	"testing"

	"github.com/rostradamus/klaws/internal/detector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPersonalDataRetentionDetector_Detects_MissingDestruction(t *testing.T) {
	src, err := os.ReadFile("../../testdata/ProfileEntity.java")
	require.NoError(t, err)

	d := detector.NewPersonalDataRetentionDetector()
	findings := d.Scan(string(src), "ProfileEntity.java")

	assert.Equal(t, 1, len(findings), "should flag personal data without destruction handling once per file")

	f := findings[0]
	assert.Equal(t, "PIPA-RET-001", f.DetectorID)
	assert.Equal(t, "MEDIUM", f.RiskLevel)
	assert.Contains(t, f.Message, "may require review")
	assert.Contains(t, f.RelatedLaws, "PIPA-21")
}

func TestPersonalDataRetentionDetector_SkipsWhenDestructionPresent(t *testing.T) {
	src := `
    private String email;
    private Instant deletedAt;`
	d := detector.NewPersonalDataRetentionDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestPersonalDataRetentionDetector_IgnoresNonFieldMentions(t *testing.T) {
	// A personal-data term used in a method/log, not a stored field, is not
	// a retention concern and must not trigger.
	src := `
    public void notifyUser(String email) {
        log.info("sending to " + email);
    }`
	d := detector.NewPersonalDataRetentionDetector()
	findings := d.Scan(src, "Service.java")
	assert.Empty(t, findings)
}

func TestPersonalDataRetentionDetector_NoFalsePositives(t *testing.T) {
	src := `private String username;`
	d := detector.NewPersonalDataRetentionDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestPersonalDataRetentionDetector_CommentDoesNotSuppress(t *testing.T) {
	src := `
    // TODO: add a destruction / retention policy for these records
    private String email;`
	d := detector.NewPersonalDataRetentionDetector()
	findings := d.Scan(src, "Profile.java")
	assert.Equal(t, 1, len(findings))
	assert.Equal(t, "PIPA-RET-001", findings[0].DetectorID)
}

func TestPersonalDataRetentionDetector_Metadata(t *testing.T) {
	d := detector.NewPersonalDataRetentionDetector()
	assert.Equal(t, "PIPA-RET-001", d.ID())
	assert.Equal(t, []string{"PIPA-21"}, d.RelatedLawIDs())
}
