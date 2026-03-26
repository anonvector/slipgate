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
	"time"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/version"
)

var httpClient = &http.Client{Timeout: 120 * time.Second}

const releaseBaseURL = "https://github.com/anonvector/slipgate/releases"

// OfflineDir, when set, makes EnsureInstalled copy binaries from this
// directory instead of downloading. Used for SCP/offline installs.
var OfflineDir string

const stableDownloadBase = releaseBaseURL + "/latest/download"

// DownloadBase returns the base URL for slipgate binary downloads.
// Dev builds use their tagged release; stable builds use latest.
func DownloadBase() string {
	if version.ReleaseTag != "" {
		return releaseBaseURL + "/download/" + version.ReleaseTag
	}
	return stableDownloadBase
}

// binaryURLTemplates returns download URL templates for transport binaries.
// Transport binaries always come from the latest stable release regardless
// of dev/stable channel — they are not included in dev pre-releases.
func binaryURLTemplates() map[string]string {
	return map[string]string{
		"dnstt-server":      stableDownloadBase + "/dnstt-server-%s-%s",
		"slipstream-server": stableDownloadBase + "/slipstream-server-%s-%s",
		"caddy-naive":       stableDownloadBase + "/caddy-naive-%s-%s",
	}
}

// EnsureInstalled checks if a binary exists. If not, copies from OfflineDir
// (if set) or downloads from GitHub releases.
func EnsureInstalled(name string) error {
	binPath := filepath.Join(config.DefaultBinDir, name)
	if _, err := os.Stat(binPath); err == nil {
		return nil // already exists
	}

	// Offline mode: copy from local directory
	if OfflineDir != "" {
		return installFromOffline(name, binPath)
	}

	// Online mode: download from releases
	urlTemplate, ok := binaryURLTemplates()[name]
	if !ok {
		return fmt.Errorf("unknown binary: %s", name)
	}

	url := fmt.Sprintf(urlTemplate, runtime.GOOS, runtime.GOARCH)
	if err := downloadTo(url, binPath, 0755); err != nil {
		return fmt.Errorf("download %s from %s: %w", name, url, err)
	}
	return nil
}

// installFromOffline copies a binary from the offline directory.
// Looks for: name-os-arch, name-arch, or just name.
func installFromOffline(name, destPath string) error {
	candidates := []string{
		fmt.Sprintf("%s-%s-%s", name, runtime.GOOS, runtime.GOARCH),
		fmt.Sprintf("%s-%s", name, runtime.GOARCH),
		name,
	}

	for _, candidate := range candidates {
		src := filepath.Join(OfflineDir, candidate)
		if _, err := os.Stat(src); err == nil {
			data, err := os.ReadFile(src)
			if err != nil {
				return fmt.Errorf("read %s: %w", src, err)
			}
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return err
			}
			if err := os.WriteFile(destPath, data, 0755); err != nil {
				return fmt.Errorf("write %s: %w", destPath, err)
			}
			return nil
		}
	}

	return fmt.Errorf("binary %s not found in %s (tried: %s)", name, OfflineDir, strings.Join(candidates, ", "))
}

// CheckUpdate checks GitHub releases for a newer version.
// Dev builds check their own tag; stable builds check latest.
func CheckUpdate() (newVersion string, downloadURL string, err error) {
	apiURL := "https://api.github.com/repos/anonvector/slipgate/releases/latest"
	if version.ReleaseTag != "" {
		apiURL = "https://api.github.com/repos/anonvector/slipgate/releases/tags/" + version.ReleaseTag
	}
	resp, err := httpClient.Get(apiURL)
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
	resp, err := httpClient.Get(url)
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
