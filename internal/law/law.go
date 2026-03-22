package law

type Law struct {
	ID        string `json:"id" yaml:"id"`
	NameKo    string `json:"name_ko" yaml:"name_ko"`
	NameEn    string `json:"name_en" yaml:"name_en"`
	Summary   string `json:"summary" yaml:"summary"`
	URL       string `json:"url" yaml:"url"`
	RiskLevel string `json:"risk_level" yaml:"risk_level"`
	FullText  string `json:"full_text,omitempty" yaml:"-"`
}

type lawsFile struct {
	Laws []Law `yaml:"laws"`
}

// LawRegistry matches the spec interface
type LawRegistry interface {
	Lookup(id string) (Law, error)
	LookupLive(id string) (Law, error)
	All() []Law
}
