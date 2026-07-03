package report

import (
	"encoding/json"
	"strings"
)

// SARIF 2.1.0 output, suitable for GitHub code scanning (upload-sarif). Only the
// subset of the schema klaws needs is modeled here.

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	toolInfoURI  = "https://github.com/rostradamus/klaws"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	HelpURI          string         `json:"helpUri"`
	Properties       sarifRuleProps `json:"properties"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
}

type sarifResult struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level"`
	Message    sarifText        `json:"message"`
	Locations  []sarifLocation  `json:"locations"`
	Properties sarifResultProps `json:"properties"`
}

type sarifResultProps struct {
	RiskLevel   string   `json:"riskLevel"`
	RelatedLaws []string `json:"relatedLaws"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int       `json:"startLine"`
	Snippet   sarifText `json:"snippet"`
}

// sarifLevel maps a klaws risk level to a SARIF result level.
func sarifLevel(risk string) string {
	switch strings.ToUpper(risk) {
	case "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity maps a klaws risk level to a GitHub code-scanning
// security-severity score (0.0–10.0, as a string).
func securitySeverity(risk string) string {
	switch strings.ToUpper(risk) {
	case "HIGH":
		return "8.0"
	case "MEDIUM":
		return "5.0"
	default:
		return "3.0"
	}
}

// FormatSARIF renders a report as SARIF 2.1.0. The detectors slice supplies rule
// metadata (name, description); results are built from the findings.
func FormatSARIF(r Report, detectors []DetectorInfo) ([]byte, error) {
	rules := make([]sarifRule, 0, len(detectors))
	for _, d := range detectors {
		rules = append(rules, sarifRule{
			ID:               d.ID,
			Name:             d.Name,
			ShortDescription: sarifText{Text: d.Description},
			HelpURI:          toolInfoURI,
			Properties: sarifRuleProps{
				Tags:             append([]string{"compliance", "korean-law"}, d.RelatedLaws...),
				SecuritySeverity: securitySeverity(highestRiskFor(d.ID, r)),
			},
		})
	}

	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		results = append(results, sarifResult{
			RuleID:  f.DetectorID,
			Level:   sarifLevel(f.RiskLevel),
			Message: sarifText{Text: f.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.FilePath},
					Region: sarifRegion{
						StartLine: f.LineNumber,
						Snippet:   sarifText{Text: f.Snippet},
					},
				},
			}},
			Properties: sarifResultProps{
				RiskLevel:   f.RiskLevel,
				RelatedLaws: f.RelatedLaws,
			},
		})
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "klaws",
				InformationURI: toolInfoURI,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

// highestRiskFor returns the most severe risk level seen among findings for a
// detector, defaulting to the detector's typical level when it produced none.
func highestRiskFor(detectorID string, r Report) string {
	best := ""
	for _, f := range r.Findings {
		if f.DetectorID != detectorID {
			continue
		}
		if riskRank(f.RiskLevel) > riskRank(best) {
			best = f.RiskLevel
		}
	}
	return best
}
