package law

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed laws/*.yaml
var embeddedLaws embed.FS

// Registry implements LawRegistry
type Registry struct {
	laws []Law
	byID map[string]Law
}

// NewRegistry loads from a YAML file path. Pass "" to use embedded laws/ directory.
func NewRegistry(yamlPath string) (*Registry, error) {
	if yamlPath != "" {
		return loadFromFile(yamlPath)
	}
	return loadFromEmbedded()
}

func loadFromFile(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading laws file: %w", err)
	}

	var file lawsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parsing laws YAML: %w", err)
	}

	return buildRegistry(file.Laws)
}

func loadFromEmbedded() (*Registry, error) {
	matches, err := fs.Glob(embeddedLaws, "laws/*.yaml")
	if err != nil {
		return nil, fmt.Errorf("globbing embedded laws: %w", err)
	}
	sort.Strings(matches)

	var allLaws []Law
	for _, match := range matches {
		data, err := embeddedLaws.ReadFile(match)
		if err != nil {
			return nil, fmt.Errorf("reading embedded %s: %w", match, err)
		}

		var file lawsFile
		if err := yaml.Unmarshal(data, &file); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", match, err)
		}
		allLaws = append(allLaws, file.Laws...)
	}

	return buildRegistry(allLaws)
}

func buildRegistry(laws []Law) (*Registry, error) {
	byID := make(map[string]Law, len(laws))
	for _, l := range laws {
		if _, exists := byID[l.ID]; exists {
			return nil, fmt.Errorf("duplicate law ID: %s", l.ID)
		}
		byID[l.ID] = l
	}
	return &Registry{laws: laws, byID: byID}, nil
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
