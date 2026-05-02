package authz

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthorize_AllowAndDeny(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k1" {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.URL.Path != "/v1/authorize" {
			http.NotFound(w, r)
			return
		}
		var req AuthorizeRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		allowed := req.Action == "read"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthorizeResponse{
			Allowed:            allowed,
			Decision:           map[bool]string{true: "allow", false: "deny"}[allowed],
			Reason:             map[bool]string{true: "permission_granted", false: "missing_permission"}[allowed],
			RequiredPermission: req.Resource + "." + req.Action,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "k1")
	ctx := context.Background()

	allow, err := client.Authorize(ctx, AuthorizeRequest{
		TenantID:      "t",
		ApplicationID: "a",
		Subject:       Subject{Type: "user", UserID: "u"},
		Resource:      "docs",
		Action:        "read",
	})
	if err != nil || !allow {
		t.Fatalf("expected allow, got allow=%v err=%v", allow, err)
	}

	allow, err = client.Authorize(ctx, AuthorizeRequest{
		TenantID:      "t",
		ApplicationID: "a",
		Subject:       Subject{Type: "user", UserID: "u"},
		Resource:      "docs",
		Action:        "write",
	})
	if err != nil || allow {
		t.Fatalf("expected deny, got allow=%v err=%v", allow, err)
	}
}

func TestRequire_ReturnsErrPermissionDenied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AuthorizeResponse{Allowed: false, Decision: "deny"})
	}))
	defer server.Close()
	client := NewClient(server.URL, "")
	err := client.Require(context.Background(), AuthorizeRequest{
		TenantID:      "t",
		ApplicationID: "a",
		Subject:       Subject{Type: "user", UserID: "u"},
		Resource:      "x",
		Action:        "y",
	})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestEffectivePermissions_CachesResult(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_ = json.NewEncoder(w).Encode(map[string][]string{
			"permissions": {"docs.read", "tools.gmail.send"},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "", WithCache(60*time.Second, 10))
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		perms, err := client.GetEffectivePermissions(ctx, EffectivePermissionsRequest{
			TenantID: "t", ApplicationID: "a",
			Subject: Subject{Type: "user", UserID: "u"},
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if _, ok := perms["docs.read"]; !ok {
			t.Fatalf("expected docs.read in result, got %v", perms)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected single upstream call thanks to cache, got %d", got)
	}
}

func TestPost_RetriesOnServerError(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 2 {
			http.Error(w, "boom", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(AuthorizeResponse{Allowed: true, Decision: "allow"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "", WithRetry(2, 1*time.Millisecond))
	allow, err := client.Authorize(context.Background(), AuthorizeRequest{
		TenantID: "t", ApplicationID: "a",
		Subject: Subject{Type: "user", UserID: "u"},
		Resource: "x", Action: "y",
	})
	if err != nil || !allow {
		t.Fatalf("expected allow after retry; got allow=%v err=%v", allow, err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 server calls, got %d", got)
	}
}

func TestServiceError_ContainsStatusAndBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"missing_or_invalid_api_key"}`, 401)
	}))
	defer server.Close()
	client := NewClient(server.URL, "")
	_, err := client.Authorize(context.Background(), AuthorizeRequest{})
	var se *ServiceError
	if !errors.As(err, &se) {
		t.Fatalf("expected ServiceError, got %v", err)
	}
	if se.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", se.StatusCode)
	}
	if !strings.Contains(se.Error(), "401") {
		t.Fatalf("expected 401 in error message: %s", se.Error())
	}
}

func TestToolGuard_RequireRejectsMissingPermission(t *testing.T) {
	guard := NewToolGuard(map[string]struct{}{"docs.read": {}})
	if err := guard.Require("docs", "write"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
	if err := guard.Require("docs", "read"); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
}

func TestMCPGuard_NamespacesUnderMCP(t *testing.T) {
	guard := NewMCPGuard(map[string]struct{}{"mcp.github.read_repo": {}})
	if !guard.IsAllowed("github", "read_repo") {
		t.Fatalf("expected mcp.github.read_repo allowed")
	}
	if guard.IsAllowed("github", "create_issue") {
		t.Fatalf("expected mcp.github.create_issue denied")
	}
}
