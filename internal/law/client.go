package law

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const defaultBaseURL = "https://www.law.go.kr/DRF/lawSearch.do"
const defaultTimeout = 10 * time.Second

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
}

func NewClientWithTimeout(baseURL string, timeoutMs int) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond},
	}
}

func NewDefaultClient() *Client {
	return NewClient(defaultBaseURL)
}

type lawSearchResponse struct {
	XMLName xml.Name   `xml:"LawSearch"`
	Laws    []lawEntry `xml:"law"`
}

type lawEntry struct {
	Name    string `xml:"법령명_한글"`
	Content string `xml:"조문내용"`
}

func (c *Client) FetchArticle(ctx context.Context, query string) (string, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("parsing base URL: %w", err)
	}

	q := u.Query()
	q.Set("target", "law")
	q.Set("query", query)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching law data: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	var result lawSearchResponse
	if err := xml.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parsing XML response: %w", err)
	}

	if len(result.Laws) == 0 {
		return "", fmt.Errorf("no results found for query: %s", query)
	}

	return result.Laws[0].Content, nil
}
