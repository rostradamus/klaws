package detector_test

import (
	"os"
	"testing"

	"github.com/rostradamus/klaws/internal/detector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetentionDetector_Detects_MissingRetention(t *testing.T) {
	src, err := os.ReadFile("../../testdata/OrderEntity.java")
	require.NoError(t, err)

	d := detector.NewRetentionDetector()
	findings := d.Scan(string(src), "OrderEntity.java")

	assert.Equal(t, 1, len(findings), "should flag transaction records once per file")

	f := findings[0]
	assert.Equal(t, "ECA-RET-001", f.DetectorID)
	assert.Equal(t, "MEDIUM", f.RiskLevel)
	assert.Contains(t, f.Message, "may require review")
	assert.Contains(t, f.RelatedLaws, "ECA-6")
}

func TestRetentionDetector_SkipsWhenRetentionPresent(t *testing.T) {
	src := `
    private String orderId;
    private Instant retentionExpiresAt;`
	d := detector.NewRetentionDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestRetentionDetector_NoFalsePositives(t *testing.T) {
	src := `private String username;`
	d := detector.NewRetentionDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestRetentionDetector_SettledFieldDoesNotSuppress(t *testing.T) {
	// "settledAt" contains "ttl" but is not retention handling — the finding
	// should still fire.
	src := `
    private String orderId;
    private Instant settledAt;`
	d := detector.NewRetentionDetector()
	findings := d.Scan(src, "Order.java")
	assert.Equal(t, 1, len(findings))
	assert.Equal(t, "ECA-RET-001", findings[0].DetectorID)
}

func TestRetentionDetector_IgnoresSimilarFieldNames(t *testing.T) {
	// "orderNotes" shares a prefix with "orderNo" but is not a transaction id.
	src := `private String orderNotes;`
	d := detector.NewRetentionDetector()
	findings := d.Scan(src, "Clean.java")
	assert.Empty(t, findings)
}

func TestRetentionDetector_Metadata(t *testing.T) {
	d := detector.NewRetentionDetector()
	assert.Equal(t, "ECA-RET-001", d.ID())
	assert.Equal(t, []string{"ECA-6"}, d.RelatedLawIDs())
}
