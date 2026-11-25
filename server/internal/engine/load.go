package engine

import (
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ide-bloom/modigliani/server/internal/profile"
	"github.com/ide-bloom/modigliani/server/internal/tmpl"
)

// Loaded is a profile plus where it came from and how its signature checked out.
type Loaded struct {
	*profile.Profile
	Path      string
	Signature profile.VerifyResult
	// Library profiles are shared (scrubbed) ones; their signatures are verified.
	Library bool
}

var phRe = regexp.MustCompile(`\{\{\s*ph\.([A-Za-z0-9_]+)\s*\}\}`)

// LoadProfiles reads every profile under the given files or directories. Profiles with an
// invalid signature and profiles marked not revivable are skipped with a log entry.
func LoadProfiles(log *slog.Logger, paths, trusted []string) ([]*Loaded, error) {
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && profile.IsProfileFile(path) {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(files)
	var out []*Loaded
	seen := map[string]string{}
	for _, f := range files {
		p, data, err := profile.LoadFile(f)
		if err != nil {
			log.Warn("skipping unreadable profile", "path", f, "err", err)
			continue
		}
		l := &Loaded{Profile: p, Path: f, Library: p.Provenance.Scrubbed}
		l.Signature = profile.Verify(f, data, trusted)
		switch l.Signature.Status {
		case profile.SigInvalid:
			log.Error("refusing profile with an invalid signature", "path", f, "key_id", l.Signature.KeyID)
			continue
		case profile.SigUnsigned:
			if l.Library {
				log.Warn("library profile is unsigned; check where it came from", "profile", p.ID, "path", f)
			}
		case profile.SigUntrusted:
			log.Warn("profile is signed by a key that is not in trusted_keys", "profile", p.ID, "key_id", l.Signature.KeyID)
		default:
			log.Info("profile signature verified", "profile", p.ID, "key_id", l.Signature.KeyID)
		}
		if p.Revivability.Status == profile.StatusNotRevivable {
			log.Warn("profile describes a device that is not revivable without firmware access; not serving it",
				"profile", p.ID, "reasons", strings.Join(p.Revivability.Reasons, "; "))
			continue
		}
		if prev, dup := seen[p.ID]; dup {
			log.Warn("duplicate profile id; keeping the first", "profile", p.ID, "kept", prev, "skipped", f)
			continue
		}
		seen[p.ID] = f
		fillPlaceholders(log, l)
		out = append(out, l)
	}
	return out, nil
}

// fillPlaceholders substitutes filled placeholders into DNS names and reports unfilled ones.
func fillPlaceholders(log *slog.Logger, l *Loaded) {
	values := l.PlaceholderValues()
	for name, ph := range l.Placeholders {
		if ph.Value == nil {
			log.Warn("placeholder has no value; run `modigliani install` with your own capture", "profile", l.ID, "placeholder", name)
		}
	}
	for i, n := range l.DNS.Names {
		l.DNS.Names[i] = phRe.ReplaceAllStringFunc(n, func(m string) string {
			key := phRe.FindStringSubmatch(m)[1]
			if v, ok := values[key]; ok {
				return tmpl.Text(v)
			}
			return m
		})
	}
}

// Hostnames returns every name a profile answers (for DNS and certificates).
func (l *Loaded) Hostnames() []string {
	set := map[string]bool{}
	for _, n := range l.DNS.Names {
		if !strings.Contains(n, "{{") {
			set[strings.ToLower(n)] = true
		}
	}
	for _, n := range l.TLS.Hostnames {
		set[strings.ToLower(n)] = true
	}
	for _, h := range l.Handlers.HTTP {
		if h.Host != "" {
			set[strings.ToLower(h.Host)] = true
		}
	}
	if l.Handlers.MQTT != nil {
		for _, h := range l.Handlers.MQTT.Hosts {
			set[strings.ToLower(h)] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
