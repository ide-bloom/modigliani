// Package logging sets up structured logging and keeps recent records for the status page.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Record is a log entry as shown by the status page.
type Record struct {
	Time    time.Time         `json:"time"`
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Attrs   map[string]string `json:"attrs"`
}

// Ring keeps the most recent records.
type Ring struct {
	mu   sync.Mutex
	recs []Record
	max  int
}

// NewRing creates a ring holding up to max records.
func NewRing(max int) *Ring { return &Ring{max: max} }

func (r *Ring) add(rec Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, rec)
	if len(r.recs) > r.max {
		r.recs = r.recs[len(r.recs)-r.max:]
	}
}

// Records returns a copy, newest last.
func (r *Ring) Records() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Record(nil), r.recs...)
}

type teeHandler struct {
	next  slog.Handler
	ring  *Ring
	attrs []slog.Attr
	group string
}

func (h *teeHandler) Enabled(ctx context.Context, l slog.Level) bool { return h.next.Enabled(ctx, l) }

func (h *teeHandler) Handle(ctx context.Context, r slog.Record) error {
	rec := Record{Time: r.Time, Level: r.Level.String(), Message: r.Message, Attrs: map[string]string{}}
	for _, a := range h.attrs {
		rec.Attrs[a.Key] = a.Value.String()
	}
	r.Attrs(func(a slog.Attr) bool {
		key := a.Key
		if h.group != "" {
			key = h.group + "." + key
		}
		rec.Attrs[key] = a.Value.String()
		return true
	})
	h.ring.add(rec)
	return h.next.Handle(ctx, r)
}

func (h *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &teeHandler{next: h.next.WithAttrs(attrs), ring: h.ring, attrs: append(append([]slog.Attr{}, h.attrs...), attrs...), group: h.group}
}

func (h *teeHandler) WithGroup(name string) slog.Handler {
	return &teeHandler{next: h.next.WithGroup(name), ring: h.ring, attrs: h.attrs, group: name}
}

// New builds a logger writing text or JSON to w and copying records into ring.
func New(w io.Writer, level, format string, ring *Ring) (*slog.Logger, error) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(strings.ToUpper(level))); err != nil {
		return nil, fmt.Errorf("log level %q: %w", level, err)
	}
	opts := &slog.HandlerOptions{Level: lv}
	var h slog.Handler = slog.NewTextHandler(w, opts)
	if format == "json" {
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(&teeHandler{next: h, ring: ring}), nil
}
