package ipreputation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAbuseIPDBScoreUsesMockAPI(t *testing.T) {
	calls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.Header.Get("Key") != "token" {
			t.Fatalf("bad request method/header")
		}
		if got := r.URL.Query().Get("ipAddress"); got != "198.51.100.9" {
			t.Fatalf("ipAddress = %q, want 198.51.100.9", got)
		}
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":42,"countryCode":"US","usageType":"Data Center","totalReports":3}}`))
	}))
	defer api.Close()

	a := NewAbuseIPDB("token")
	a.endpoint = api.URL
	a.client = api.Client()

	got, err := a.Score(context.Background(), "198.51.100.9")
	if err != nil {
		t.Fatalf("Score returned error: %v", err)
	}
	if got.Risk < 0.41 || got.Risk > 0.43 {
		t.Fatalf("Risk = %v, want around 0.42", got.Risk)
	}
	if _, err := a.Score(context.Background(), "198.51.100.9"); err != nil {
		t.Fatalf("cached Score returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 cached lookup", calls)
	}
}
