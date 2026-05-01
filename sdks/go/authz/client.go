// Package authz is the Go SDK for the AuthZ service.
//
// It mirrors the Python SDK's surface: an AuthzClient for runtime decisions
// and an AdminClient for management operations. Both share an HTTP layer
// with retry on transient failures and a small effective-permissions cache.
package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Subject is the entity an authorization request is being made for.
type Subject struct {
	Type            string `json:"type"`
	UserID          string `json:"user_id,omitempty"`
	AgentID         string `json:"agent_id,omitempty"`
	ServiceAccount  string `json:"service_account_id,omitempty"`
}

// BulkCheck is a (resource, action) pair to be evaluated in a bulk call.
type BulkCheck struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// BulkCheckResult is one row from a bulk-authorize response.
type BulkCheckResult struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason"`
}

// ResolvedContext is the response from /v1/resolve-context.
type ResolvedContext struct {
	TenantID      string   `json:"tenant_id"`
	ApplicationID string   `json:"application_id"`
	UserID        string   `json:"user_id"`
	Roles         []string `json:"roles"`
	Permissions   []string `json:"permissions"`
}

// AuthorizeResponse is the response from /v1/authorize.
type AuthorizeResponse struct {
	Allowed             bool     `json:"allowed"`
	Decision            string   `json:"decision"`
	Reason              string   `json:"reason"`
	RequiredPermission  string   `json:"required_permission"`
	MatchedPermissions  []string `json:"matched_permissions"`
}

// ServiceError carries the HTTP status + decoded body for non-2xx responses.
type ServiceError struct {
	StatusCode int
	Body       any
}

func (e *ServiceError) Error() string {
	return fmt.Sprintf("authz service returned %d: %v", e.StatusCode, e.Body)
}

// ErrPermissionDenied is returned from Require when the subject lacks the permission.
var ErrPermissionDenied = errors.New("permission denied")

// Client talks to the AuthZ service for runtime decisions.
//
// Safe for concurrent use; the cache is guarded by an internal mutex.
type Client struct {
	baseURL     string
	apiKey      string
	httpClient  *http.Client
	maxRetries  int
	backoff     time.Duration
	cacheTTL    time.Duration
	cacheMax    int

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	permissions map[string]struct{}
	expiresAt   time.Time
}

// NewClient constructs a Client for the given base URL.
//
// Pass cacheTTL=0 to disable the effective-permissions cache.
func NewClient(baseURL, apiKey string, opts ...Option) *Client {
	c := &Client{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		maxRetries: 2,
		backoff:    100 * time.Millisecond,
		cacheTTL:   0,
		cacheMax:   1024,
		cache:      make(map[string]cacheEntry),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the HTTP client (e.g. for mTLS).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.httpClient = h }
}

// WithCache enables the effective-permissions LRU cache.
func WithCache(ttl time.Duration, max int) Option {
	return func(c *Client) { c.cacheTTL = ttl; c.cacheMax = max }
}

// WithRetry configures retries on transient failures.
func WithRetry(max int, backoff time.Duration) Option {
	return func(c *Client) { c.maxRetries = max; c.backoff = backoff }
}

// post is the shared POST helper with retry on transport errors and 5xx.
func (c *Client) post(ctx context.Context, path string, body, out any) error {
	url := c.baseURL
	if url == "" {
		return errors.New("authz: base URL not set")
	}
	if url[len(url)-1] != '/' {
		url += "/"
	}
	url += path

	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if c.apiKey != "" {
			req.Header.Set("X-API-Key", c.apiKey)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt < c.maxRetries {
				time.Sleep(c.backoff << attempt)
				continue
			}
			return fmt.Errorf("authz: transport error after retries: %w", err)
		}

		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)

		if resp.StatusCode >= 500 && attempt < c.maxRetries {
			time.Sleep(c.backoff << attempt)
			continue
		}
		if resp.StatusCode >= 400 {
			var detail any
			if e := json.Unmarshal(respBody, &detail); e != nil {
				detail = string(respBody)
			}
			return &ServiceError{StatusCode: resp.StatusCode, Body: detail}
		}
		if out != nil && len(respBody) > 0 {
			return json.Unmarshal(respBody, out)
		}
		return nil
	}
	return lastErr
}

// AuthorizeRequest mirrors the Python SDK shape.
type AuthorizeRequest struct {
	TenantID      string                 `json:"tenant_id"`
	ApplicationID string                 `json:"application_id"`
	Subject       Subject                `json:"subject"`
	Resource      string                 `json:"resource"`
	Action        string                 `json:"action"`
	Context       map[string]interface{} `json:"context,omitempty"`
}

// Authorize runs a single decision.
func (c *Client) Authorize(ctx context.Context, req AuthorizeRequest) (bool, error) {
	var out AuthorizeResponse
	if err := c.post(ctx, "v1/authorize", req, &out); err != nil {
		return false, err
	}
	return out.Allowed, nil
}

// Require returns ErrPermissionDenied when the decision is deny.
func (c *Client) Require(ctx context.Context, req AuthorizeRequest) error {
	allowed, err := c.Authorize(ctx, req)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("%w: %s.%s", ErrPermissionDenied, req.Resource, req.Action)
	}
	return nil
}

// BulkAuthorizeRequest is the input to BulkAuthorize.
type BulkAuthorizeRequest struct {
	TenantID      string                 `json:"tenant_id"`
	ApplicationID string                 `json:"application_id"`
	Subject       Subject                `json:"subject"`
	Checks        []BulkCheck            `json:"checks"`
	Context       map[string]interface{} `json:"context,omitempty"`
}

type bulkAuthorizeResponse struct {
	Results []BulkCheckResult `json:"results"`
}

// BulkAuthorize evaluates many checks in one round-trip.
func (c *Client) BulkAuthorize(ctx context.Context, req BulkAuthorizeRequest) ([]BulkCheckResult, error) {
	var out bulkAuthorizeResponse
	if err := c.post(ctx, "v1/bulk-authorize", req, &out); err != nil {
		return nil, err
	}
	return out.Results, nil
}

// EffectivePermissionsRequest is the input to GetEffectivePermissions.
type EffectivePermissionsRequest struct {
	TenantID      string  `json:"tenant_id"`
	ApplicationID string  `json:"application_id"`
	Subject       Subject `json:"subject"`
}

type effectivePermissionsResponse struct {
	Permissions []string `json:"permissions"`
}

// GetEffectivePermissions returns the precomputed permission set.
//
// Cached for the configured TTL (set via WithCache).
func (c *Client) GetEffectivePermissions(ctx context.Context, req EffectivePermissionsRequest) (map[string]struct{}, error) {
	cacheKey := req.TenantID + "|" + req.ApplicationID + "|" + req.Subject.Type + "|" + req.Subject.UserID + "|" + req.Subject.AgentID

	if c.cacheTTL > 0 {
		c.mu.Lock()
		if entry, ok := c.cache[cacheKey]; ok {
			if entry.expiresAt.After(time.Now()) {
				out := make(map[string]struct{}, len(entry.permissions))
				for k := range entry.permissions {
					out[k] = struct{}{}
				}
				c.mu.Unlock()
				return out, nil
			}
			delete(c.cache, cacheKey)
		}
		c.mu.Unlock()
	}

	var resp effectivePermissionsResponse
	if err := c.post(ctx, "v1/effective-permissions", req, &resp); err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(resp.Permissions))
	for _, p := range resp.Permissions {
		out[p] = struct{}{}
	}

	if c.cacheTTL > 0 {
		c.mu.Lock()
		// Cap cache size by evicting oldest entry (linear scan, fine for ~1k entries).
		if len(c.cache) >= c.cacheMax {
			var oldestKey string
			var oldestTime time.Time
			first := true
			for k, v := range c.cache {
				if first || v.expiresAt.Before(oldestTime) {
					oldestKey = k
					oldestTime = v.expiresAt
					first = false
				}
			}
			delete(c.cache, oldestKey)
		}
		c.cache[cacheKey] = cacheEntry{
			permissions: out,
			expiresAt:   time.Now().Add(c.cacheTTL),
		}
		c.mu.Unlock()
	}
	return out, nil
}

// ResolveContextRequest mirrors /v1/resolve-context.
type ResolveContextRequest struct {
	ApplicationID    string                 `json:"application_id"`
	Provider         string                 `json:"provider"`
	Issuer           string                 `json:"issuer"`
	Subject          string                 `json:"subject"`
	Email            string                 `json:"email,omitempty"`
	ExternalTenantID string                 `json:"external_tenant_id,omitempty"`
	ExplicitTenantID string                 `json:"explicit_tenant_id,omitempty"`
	Claims           map[string]interface{} `json:"claims,omitempty"`
}

// ResolveContext maps an IdentityPrincipal to a UserContext.
func (c *Client) ResolveContext(ctx context.Context, req ResolveContextRequest) (*ResolvedContext, error) {
	var out ResolvedContext
	if err := c.post(ctx, "v1/resolve-context", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CacheInvalidate drops cached entries matching the partition keys.
func (c *Client) CacheInvalidate(tenantID, applicationID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.cache {
		if (tenantID == "" || hasPrefix(k, tenantID+"|")) &&
			(applicationID == "" || containsAfter(k, "|", applicationID+"|")) {
			delete(c.cache, k)
		}
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func containsAfter(s, sep, target string) bool {
	idx := indexOf(s, sep)
	if idx < 0 {
		return false
	}
	return hasPrefix(s[idx+1:], target)
}

func indexOf(s, sep string) int {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return i
		}
	}
	return -1
}
