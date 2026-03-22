package law

import (
	"context"
	"embed"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed laws.yaml
var embeddedLaws embed.FS

// Registry implements LawRegistry
type Registry struct {
	laws []Law
	byID map[string]Law
}

// NewRegistry loads from a YAML file path. Pass "" to use embedded laws.yaml.
func NewRegistry(yamlPath string) (*Registry, error) {
	var data []byte
	var err error

	if yamlPath == "" {
		data, err = embeddedLaws.ReadFile("laws.yaml")
	} else {
		data, err = os.ReadFile(yamlPath)
	}
	if err != nil {
		return nil, fmt.Errorf("reading laws file: %w", err)
	}

	var file lawsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parsing laws YAML: %w", err)
	}

	byID := make(map[string]Law, len(file.Laws))
	for _, l := range file.Laws {
		byID[l.ID] = l
	}

	return &Registry{laws: file.Laws, byID: byID}, nil
}

func (r *Registry) Lookup(id string) (Law, error) {
	l, ok := r.byID[id]
	if !ok {
		return Law{}, fmt.Errorf("law not found: %s", id)
	}
	return l, nil
}

func (r *Registry) All() []Law {
	return r.laws
}

func (r *Registry) LookupLive(id string) (Law, error) {
	l, err := r.Lookup(id)
	if err != nil {
		return Law{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := NewDefaultClient()
	text, fetchErr := client.FetchArticle(ctx, l.NameKo)
	if fetchErr != nil {
		// Fallback to bundled data without full text
		return l, nil
	}

	l.FullText = text
	return l, nil
}
