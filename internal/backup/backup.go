// Package backup packs a slipgate server's setup (config, users and every
// tunnel's key and certificate files) into one block of text that can be
// saved to a file or copy-pasted, and unpacks it on another server.
package backup

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/anonvector/slipgate/internal/config"
)

// The first and last lines of a backup.
const (
	BeginMarker = "-----BEGIN SLIPGATE BACKUP-----"
	EndMarker   = "-----END SLIPGATE BACKUP-----"
)

const (
	// formatVersion is bumped when a backup can no longer be read by older
	// slipgate versions.
	formatVersion = 1
	lineWidth     = 76

	// maxFileSize skips anything in a tunnel directory that can't be a key
	// or certificate (keys are bytes, certificates a few KB).
	maxFileSize = 1 << 20
	// maxDecoded bounds decompression of an untrusted backup.
	maxDecoded = 32 << 20
)

var fileNameRegex = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`)

// Bundle is the content of a backup.
type Bundle struct {
	Format  int            `json:"format"`
	Created time.Time      `json:"created"`
	Version string         `json:"version"` // slipgate version that made it
	Config  *config.Config `json:"config"`
	// Files holds each tunnel's files by tag and file name. The config's key
	// and certificate paths are stored as names in this map.
	Files map[string]map[string]File `json:"files"`

	// Skipped lists files left out of a new backup (too large to be keys).
	Skipped []string `json:"-"`
	// DroppedUsers describes users of a decoded backup that can't be
	// created safely and were left out.
	DroppedUsers []string `json:"-"`
}

// File is one file from a tunnel's directory.
type File struct {
	Mode os.FileMode `json:"mode"`
	Data []byte      `json:"data"`
}

// Create collects cfg and its tunnels' files from tunnelRoot/<tag>/. A key or
// certificate configured outside its tunnel's directory is included too and
// restored into that directory, so a bundle only holds files that belong in
// tunnelRoot.
func Create(cfg *config.Config, tunnelRoot, version string) (*Bundle, error) {
	// Work on a copy: the bundle's paths are rewritten to file names.
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var c config.Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}

	b := &Bundle{
		Format:  formatVersion,
		Created: time.Now().UTC().Truncate(time.Second),
		Version: version,
		Config:  &c,
		Files:   make(map[string]map[string]File),
	}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		dir := filepath.Join(tunnelRoot, t.Tag)
		files, err := b.readTunnelDir(dir)
		if err != nil {
			return nil, fmt.Errorf("tunnel %s: %w", t.Tag, err)
		}
		for _, p := range keyPaths(t) {
			if *p == "" {
				continue
			}
			name := filepath.Base(*p)
			if _, ok := files[name]; !ok || filepath.Dir(filepath.Clean(*p)) != dir {
				f, err := readFile(*p)
				if err != nil {
					return nil, fmt.Errorf("tunnel %s: %w", t.Tag, err)
				}
				name = freeName(files, name)
				files[name] = f
			}
			*p = name
		}
		if len(files) > 0 {
			b.Files[t.Tag] = files
		}
	}
	return b, nil
}

// readTunnelDir reads the regular files directly in dir. A missing directory
// is not an error: external and direct tunnels have none.
func (b *Bundle) readTunnelDir(dir string) (map[string]File, error) {
	files := make(map[string]File)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return files, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !fileNameRegex.MatchString(e.Name()) {
			continue // subdirectories such as NaiveProxy's .caddy state
		}
		path := filepath.Join(dir, e.Name())
		if info, err := e.Info(); err == nil && info.Size() > maxFileSize {
			b.Skipped = append(b.Skipped, path)
			continue
		}
		f, err := readFile(path)
		if err != nil {
			return nil, err
		}
		files[e.Name()] = f
	}
	return files, nil
}

func readFile(path string) (File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return File{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	return File{Mode: info.Mode().Perm(), Data: data}, nil
}

// freeName returns name, or name with a numeric prefix if files has it.
func freeName(files map[string]File, name string) string {
	if !fileNameRegex.MatchString(name) {
		name = "file"
	}
	if _, taken := files[name]; !taken {
		return name
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%d-%s", i, name)
		if _, taken := files[candidate]; !taken {
			return candidate
		}
	}
}

// keyPaths returns pointers to t's key and certificate path fields.
func keyPaths(t *config.TunnelConfig) []*string {
	var paths []*string
	if t.DNSTT != nil {
		paths = append(paths, &t.DNSTT.PrivateKey)
	}
	if t.VayDNS != nil {
		paths = append(paths, &t.VayDNS.PrivateKey)
	}
	if t.Soar != nil {
		paths = append(paths, &t.Soar.PrivateKey)
	}
	if t.Slipstream != nil {
		paths = append(paths, &t.Slipstream.Cert, &t.Slipstream.Key)
	}
	if t.StunTLS != nil {
		paths = append(paths, &t.StunTLS.Cert, &t.StunTLS.Key)
	}
	return paths
}

// Encode returns the bundle as text: gzip-compressed JSON in base64, wrapped
// at 76 columns between BEGIN and END lines, so it survives terminals, chat
// apps and email.
func (b *Bundle) Encode() (string, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	var zipped bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&zipped, gzip.BestCompression)
	if _, err := zw.Write(data); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}

	body := base64.StdEncoding.EncodeToString(zipped.Bytes())
	var sb strings.Builder
	sb.WriteString(BeginMarker + "\n")
	for len(body) > lineWidth {
		sb.WriteString(body[:lineWidth] + "\n")
		body = body[lineWidth:]
	}
	sb.WriteString(body + "\n")
	sb.WriteString(EndMarker + "\n")
	return sb.String(), nil
}

// Decode parses text made by Encode and checks everything in it, since a
// backup may come from anyone. Text around the BEGIN and END lines is
// ignored, as are spaces and line breaks between them, which copy-paste
// tends to change.
func Decode(text string) (*Bundle, error) {
	start := strings.Index(text, BeginMarker)
	end := strings.Index(text, EndMarker)
	if start < 0 || end < start {
		return nil, errors.New("no slipgate backup found: the text must include the BEGIN and END lines")
	}
	body := strings.Join(strings.Fields(text[start+len(BeginMarker):end]), "")

	damaged := errors.New("backup text is damaged or incomplete; copy it again from the BEGIN line to the END line")
	zipped, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, damaged
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, damaged
	}
	// Reading to EOF also verifies gzip's checksum.
	data, err := io.ReadAll(io.LimitReader(zr, maxDecoded+1))
	if err != nil {
		return nil, damaged
	}
	if len(data) > maxDecoded {
		return nil, errors.New("backup is too large")
	}

	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("invalid backup: %w", err)
	}
	if b.Format > formatVersion {
		return nil, fmt.Errorf("backup was made by a newer slipgate (%s); update slipgate on this server first", b.Version)
	}
	if b.Format < 1 || b.Config == nil {
		return nil, errors.New("invalid backup: missing format or config")
	}
	b.DroppedUsers = b.Config.RemoveInvalidUsers()
	if err := b.validate(); err != nil {
		return nil, fmt.Errorf("invalid backup: %w", err)
	}
	return &b, nil
}

// validate checks the config and that every file belongs to a tunnel, has a
// plain file name, and that every configured key or certificate is present.
func (b *Bundle) validate() error {
	if err := b.Config.ValidateImported(); err != nil {
		return err
	}
	for tag, files := range b.Files {
		if b.Config.GetTunnel(tag) == nil {
			return fmt.Errorf("files for unknown tunnel %q", tag)
		}
		for name, f := range files {
			if !fileNameRegex.MatchString(name) {
				return fmt.Errorf("tunnel %s: invalid file name %q", tag, name)
			}
			if len(f.Data) > maxFileSize {
				return fmt.Errorf("tunnel %s: file %s is too large", tag, name)
			}
		}
	}
	for i := range b.Config.Tunnels {
		t := &b.Config.Tunnels[i]
		for _, p := range keyPaths(t) {
			if *p == "" {
				continue
			}
			if _, ok := b.Files[t.Tag][*p]; !ok {
				return fmt.Errorf("tunnel %s: key or certificate %q is missing", t.Tag, *p)
			}
		}
	}
	return nil
}

// Restore writes the bundle's files to tunnelRoot/<tag>/ and returns the
// bundle's config with its key and certificate paths pointing at them.
func (b *Bundle) Restore(tunnelRoot string) (*config.Config, error) {
	tags := make([]string, 0, len(b.Files))
	for tag := range b.Files {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		dir := filepath.Join(tunnelRoot, tag)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, err
		}
		for name, f := range b.Files[tag] {
			// Never more than rw-r--r--: keys stay private, nothing executable.
			perm := f.Mode.Perm() & 0644
			if perm == 0 {
				perm = 0600
			}
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, f.Data, perm); err != nil {
				return nil, err
			}
			// WriteFile keeps the mode of a file that already existed.
			if err := os.Chmod(path, perm); err != nil {
				return nil, err
			}
		}
	}

	raw, err := json.Marshal(b.Config)
	if err != nil {
		return nil, err
	}
	var c config.Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		for _, p := range keyPaths(t) {
			if *p != "" {
				*p = filepath.Join(tunnelRoot, t.Tag, *p)
			}
		}
	}
	return &c, nil
}
