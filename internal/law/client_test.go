package law_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rostradamus/dev-lawyer/internal/law"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Fetch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<LawSearch>
  <law>
    <법령명_한글>개인정보 보호법</법령명_한글>
    <조문내용>제15조(개인정보의 수집·이용) 개인정보처리자는 다음 각 호의 어느 하나에 해당하는 경우에는 개인정보를 수집할 수 있다.</조문내용>
  </law>
</LawSearch>`))
	}))
	defer ts.Close()

	client := law.NewClient(ts.URL)
	text, err := client.FetchArticle(context.Background(), "개인정보보호법")
	require.NoError(t, err)
	assert.Contains(t, text, "개인정보")
}

func TestClient_Timeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	client := law.NewClientWithTimeout(ts.URL, 50) // 50ms timeout
	_, err := client.FetchArticle(context.Background(), "test")
	assert.Error(t, err)
}
