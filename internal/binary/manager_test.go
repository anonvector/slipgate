package binary

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDownloadNotFound: only a missing asset reports errNotFound, the one
// error EnsureInstalled falls back to the stable release on.
func TestDownloadNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing":
			http.NotFound(w, r)
		case "/broken":
			http.Error(w, "oops", http.StatusInternalServerError)
		default:
			io.WriteString(w, "binary")
		}
	}))
	defer srv.Close()

	if err := downloadToWriter(srv.URL+"/missing", io.Discard); !errors.Is(err, errNotFound) {
		t.Errorf("missing asset: got %v, want errNotFound", err)
	}
	if err := downloadToWriter(srv.URL+"/broken", io.Discard); err == nil || errors.Is(err, errNotFound) {
		t.Errorf("server error: got %v, want a non-404 error", err)
	}
	if err := downloadToWriter(srv.URL+"/ok", io.Discard); err != nil {
		t.Errorf("existing asset: %v", err)
	}
}
