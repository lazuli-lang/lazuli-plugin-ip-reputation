package ipreputation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"lazuli.dev/runtime/lazuli"
	"lazuli.dev/runtime/lazuli/reputation"
)

const (
	AdapterRef   = "@plugin/ip-reputation"
	abuseIPDBURL = "https://api.abuseipdb.com/api/v2/check"
	cacheTTL     = 30 * time.Minute
)

var (
	ErrUnconfigured      = errors.New("ip-reputation: ABUSEIPDB_API_KEY not set")
	ErrVendorUnsupported = errors.New("ip-reputation: vendor unsupported in v0.1")
)

type Adapter struct {
	token, endpoint string
	client          *http.Client
	err             error
	mu              sync.Mutex
	cache           map[string]struct {
		score   reputation.Score
		expires time.Time
	}
}

var _ reputation.Scorer = (*Adapter)(nil)

func init() { lazuli.RegisterAdapter(AdapterRef, newAdapter()) }

func newAdapter() reputation.Scorer {
	if vendor := strings.ToLower(os.Getenv("IP_REPUTATION_VENDOR")); vendor != "" && vendor != "abuseipdb" {
		return stubScorer(vendor)
	}
	return NewAbuseIPDB(os.Getenv("ABUSEIPDB_API_KEY"))
}

func NewAbuseIPDB(token string) *Adapter {
	a := &Adapter{
		token:    token,
		endpoint: abuseIPDBURL,
		client:   &http.Client{Timeout: 1200 * time.Millisecond},
		cache: map[string]struct {
			score   reputation.Score
			expires time.Time
		}{},
	}
	if token == "" {
		a.err = ErrUnconfigured
	}
	return a
}

func (a *Adapter) Score(ctx context.Context, ip string) (reputation.Score, error) {
	now := time.Now()
	a.mu.Lock()
	hit, ok := a.cache[ip]
	a.mu.Unlock()
	if ok && now.Before(hit.expires) {
		return hit.score, nil
	}
	if a.err != nil {
		return reputation.Score{}, a.err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"?ipAddress="+url.QueryEscape(ip), nil)
	if err != nil {
		return reputation.Score{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Key", a.token)
	resp, err := a.client.Do(req)
	if err != nil {
		return reputation.Score{}, reputation.ErrScorerUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusTooManyRequests {
		return reputation.Score{}, reputation.ErrRateLimited
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return reputation.Score{}, reputation.ErrScorerUnavailable
	}
	var out abuseResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return reputation.Score{}, err
	}
	risk := out.Data.AbuseConfidenceScore / 100
	if risk < 0 {
		risk = 0
	} else if risk > 1 {
		risk = 1
	}
	score := reputation.Score{Risk: risk, Country: out.Data.CountryCode, Reasons: []string{"abuseipdb"}, ScoredAt: now}
	a.mu.Lock()
	a.cache[ip] = struct {
		score   reputation.Score
		expires time.Time
	}{score: score, expires: now.Add(cacheTTL)}
	a.mu.Unlock()
	return score, nil
}

func (a *Adapter) Close() error { return nil }

type abuseResponse struct {
	Data struct {
		AbuseConfidenceScore float32 `json:"abuseConfidenceScore"`
		CountryCode          string  `json:"countryCode"`
	} `json:"data"`
}

type stubScorer string

func (s stubScorer) Score(context.Context, string) (reputation.Score, error) {
	return reputation.Score{}, ErrVendorUnsupported
}
func (s stubScorer) Close() error { return nil }
