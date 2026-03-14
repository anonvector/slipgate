package binary

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/version"
)

const (
	releaseBaseURL = "https://github.com/anonvector/slipgate/releases"
	binaryBaseURL  = "https://github.com/anonvector/slipgate/releases/latest/download"
)

// Binary download URLs per binary name. Arch is appended at runtime.
var binaryURLs = map[string]string{
	"dnstt-server":      "https://github.com/anonvector/noizdns-deploy/releases/latest/download/dnstt-server-%s-%s",
	"slipstream-server": "https://github.com/anonvector/slipstream-rust-deploy/releases/latest/download/slipstream-server-%s-%s",
	"microsocks":        "https://github.com/anonvector/slipgate/releases/latest/download/microsocks-%s-%s",
	"caddy-naive":       "https://github.com/anonvector/naiveproxy/releases/latest/download/caddy-naive-%s-%s",
}

// EnsureInstalled checks if a binary exists, downloads if not.
func EnsureInstalled(name string) error {
	binPath := filepath.Join(config.DefaultBinDir, name)
	if _, err := os.Stat(binPath); err == nil {
		return nil // already exists
	}

	urlTemplate, ok := binaryURLs[name]
	if !ok {
		return fmt.Errorf("unknown binary: %s", name)
	}

	url := fmt.Sprintf(urlTemplate, runtime.GOOS, runtime.GOARCH)
	return downloadTo(url, binPath, 0755)
}

// CheckUpdate checks GitHub releases for a newer version.
func CheckUpdate() (newVersion string, downloadURL string, err error) {
	apiURL := "https://api.github.com/repos/anonvector/slipgate/releases/latest"
	resp, err := http.Get(apiURL)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", "", err
	}

	if release.TagName == version.Version || release.TagName == "v"+version.Version {
		return "", "", nil
	}

	// Find matching asset
	target := fmt.Sprintf("slipgate-%s-%s", runtime.GOOS, runtime.GOARCH)
	for _, asset := range release.Assets {
		if strings.Contains(asset.Name, target) {
			return release.TagName, asset.BrowserDownloadURL, nil
		}
	}

	return release.TagName, "", fmt.Errorf("no matching binary for %s/%s", runtime.GOOS, runtime.GOARCH)
}

// Download fetches a URL to a temp file.
func Download(url string) (string, error) {
	tmp, err := os.CreateTemp("", "slipgate-update-*")
	if err != nil {
		return "", err
	}
	defer tmp.Close()

	if err := downloadToWriter(url, tmp); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}

	if err := os.Chmod(tmp.Name(), 0755); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}

	return tmp.Name(), nil
}

func downloadTo(url, dest string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}

	tmp := dest + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		os.Remove(tmp)
	}()

	if err := downloadToWriter(url, f); err != nil {
		return err
	}
	f.Close()

	// Try rename, fallback to copy
	if err := os.Rename(tmp, dest); err != nil {
		cpCmd := exec.Command("cp", tmp, dest)
		if err := cpCmd.Run(); err != nil {
			return fmt.Errorf("install binary: %w", err)
		}
		os.Chmod(dest, mode)
	}

	return nil
}

func downloadToWriter(url string, w io.Writer) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}
