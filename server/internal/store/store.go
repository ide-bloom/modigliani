// Package store keeps devices, state, queued commands, tokens and unhandled requests in
// SQLite (pure Go, via modernc.org/sqlite).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// Store is safe for concurrent use.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS devices (
	profile TEXT NOT NULL, key TEXT NOT NULL, vars TEXT NOT NULL DEFAULT '{}',
	remote TEXT NOT NULL DEFAULT '', first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
	PRIMARY KEY (profile, key));
CREATE TABLE IF NOT EXISTS state (
	profile TEXT NOT NULL, key TEXT NOT NULL, variable TEXT NOT NULL,
	reported TEXT, desired TEXT, updated INTEGER NOT NULL,
	PRIMARY KEY (profile, key, variable));
CREATE TABLE IF NOT EXISTS commands (
	id INTEGER PRIMARY KEY AUTOINCREMENT, profile TEXT NOT NULL, key TEXT NOT NULL,
	name TEXT NOT NULL, variable TEXT NOT NULL, value TEXT NOT NULL, status TEXT NOT NULL,
	created INTEGER NOT NULL, delivered INTEGER);
CREATE TABLE IF NOT EXISTS tokens (
	token TEXT PRIMARY KEY, profile TEXT NOT NULL, key TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS counters (
	profile TEXT NOT NULL, key TEXT NOT NULL, name TEXT NOT NULL, value INTEGER NOT NULL,
	PRIMARY KEY (profile, key, name));
CREATE TABLE IF NOT EXISTS unhandled (
	id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, protocol TEXT NOT NULL,
	remote TEXT NOT NULL, summary TEXT NOT NULL, detail TEXT NOT NULL);
`

// Open creates or opens the database file in dir (":memory:" for tests).
func Open(ctx context.Context, dir string) (*Store, error) {
	dsn := ":memory:"
	if dir != ":memory:" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		dsn = "file:" + filepath.ToSlash(filepath.Join(dir, "modigliani.db")) + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serialises writers and keeps ":memory:" databases shared.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Device is a known device instance.
type Device struct {
	Profile   string            `json:"profile"`
	Key       string            `json:"key"`
	Vars      map[string]string `json:"vars"`
	Remote    string            `json:"remote"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
}

// Touch records that a device was seen, merging learned variables. It reports whether the
// device is new.
func (s *Store) Touch(ctx context.Context, profile, key, remote string, vars map[string]string, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var raw string
	err = tx.QueryRowContext(ctx, `SELECT vars FROM devices WHERE profile=? AND key=?`, profile, key).Scan(&raw)
	isNew := errors.Is(err, sql.ErrNoRows)
	if err != nil && !isNew {
		return false, err
	}
	merged := map[string]string{}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &merged)
	}
	for k, v := range vars {
		merged[k] = v
	}
	enc, _ := json.Marshal(merged)
	if isNew {
		_, err = tx.ExecContext(ctx, `INSERT INTO devices(profile,key,vars,remote,first_seen,last_seen) VALUES(?,?,?,?,?,?)`,
			profile, key, string(enc), remote, now.Unix(), now.Unix())
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE devices SET vars=?, remote=?, last_seen=? WHERE profile=? AND key=?`,
			string(enc), remote, now.Unix(), profile, key)
	}
	if err != nil {
		return false, err
	}
	return isNew, tx.Commit()
}

// Devices lists all devices.
func (s *Store) Devices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT profile,key,vars,remote,first_seen,last_seen FROM devices ORDER BY profile,key`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Device
	for rows.Next() {
		var d Device
		var vars string
		var first, last int64
		if err := rows.Scan(&d.Profile, &d.Key, &vars, &d.Remote, &first, &last); err != nil {
			return nil, err
		}
		d.Vars = map[string]string{}
		_ = json.Unmarshal([]byte(vars), &d.Vars)
		d.FirstSeen, d.LastSeen = time.Unix(first, 0).UTC(), time.Unix(last, 0).UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// Device returns one device.
func (s *Store) Device(ctx context.Context, profile, key string) (Device, bool, error) {
	all, err := s.Devices(ctx)
	if err != nil {
		return Device{}, false, err
	}
	for _, d := range all {
		if d.Profile == profile && d.Key == key {
			return d, true, nil
		}
	}
	return Device{}, false, nil
}

// Value is a variable's reported and desired values.
type Value struct {
	Reported any       `json:"reported"`
	Desired  any       `json:"desired,omitempty"`
	Updated  time.Time `json:"updated"`
}

// SetReported stores a reported value; when it equals the desired value, the desired value
// is cleared because the device has carried out the command. Returns whether it changed.
func (s *Store) SetReported(ctx context.Context, profile, key, variable string, value any, now time.Time) (bool, error) {
	enc, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	var prev, desired sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT reported, desired FROM state WHERE profile=? AND key=? AND variable=?`,
		profile, key, variable).Scan(&prev, &desired)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	newDesired := desired
	if desired.Valid && desired.String == string(enc) {
		newDesired = sql.NullString{}
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO state(profile,key,variable,reported,desired,updated) VALUES(?,?,?,?,?,?)
		ON CONFLICT(profile,key,variable) DO UPDATE SET reported=excluded.reported, desired=excluded.desired, updated=excluded.updated`,
		profile, key, variable, string(enc), newDesired, now.Unix())
	return !prev.Valid || prev.String != string(enc), err
}

// SetDesired records what a command asked for.
func (s *Store) SetDesired(ctx context.Context, profile, key, variable string, value any, now time.Time) error {
	enc, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO state(profile,key,variable,reported,desired,updated) VALUES(?,?,?,NULL,?,?)
		ON CONFLICT(profile,key,variable) DO UPDATE SET desired=excluded.desired, updated=excluded.updated`,
		profile, key, variable, string(enc), now.Unix())
	return err
}

// State returns all variables of a device.
func (s *Store) State(ctx context.Context, profile, key string) (map[string]Value, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT variable, reported, desired, updated FROM state WHERE profile=? AND key=?`, profile, key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]Value{}
	for rows.Next() {
		var name string
		var rep, des sql.NullString
		var updated int64
		if err := rows.Scan(&name, &rep, &des, &updated); err != nil {
			return nil, err
		}
		v := Value{Updated: time.Unix(updated, 0).UTC()}
		if rep.Valid {
			_ = json.Unmarshal([]byte(rep.String), &v.Reported)
		}
		if des.Valid {
			_ = json.Unmarshal([]byte(des.String), &v.Desired)
		}
		out[name] = v
	}
	return out, rows.Err()
}

// QueuedCommand is a command waiting for a polling device.
type QueuedCommand struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Variable string `json:"variable"`
	Value    any    `json:"value"`
	Status   string `json:"status"`
}

// Enqueue stores a command for later delivery (status "queued") or records an immediately
// sent one (status "sent").
func (s *Store) Enqueue(ctx context.Context, profile, key, name, variable string, value any, status string, now time.Time) (int64, error) {
	enc, err := json.Marshal(value)
	if err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO commands(profile,key,name,variable,value,status,created) VALUES(?,?,?,?,?,?,?)`,
		profile, key, name, variable, string(enc), status, now.Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// TakeQueued returns queued commands for a device and marks them delivered.
func (s *Store) TakeQueued(ctx context.Context, profile, key string, names []string, now time.Time) ([]QueuedCommand, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT id,name,variable,value FROM commands WHERE profile=? AND key=? AND status='queued' ORDER BY id`, profile, key)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, n := range names {
		allowed[n] = true
	}
	var out []QueuedCommand
	for rows.Next() {
		var c QueuedCommand
		var val string
		if err := rows.Scan(&c.ID, &c.Name, &c.Variable, &val); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if !allowed[c.Name] {
			continue
		}
		_ = json.Unmarshal([]byte(val), &c.Value)
		c.Status = "delivered"
		out = append(out, c)
	}
	_ = rows.Close()
	for _, c := range out {
		if _, err := tx.ExecContext(ctx, `UPDATE commands SET status='delivered', delivered=? WHERE id=?`, now.Unix(), c.ID); err != nil {
			return nil, err
		}
	}
	return out, tx.Commit()
}

// IssueToken stores a token for a device.
func (s *Store) IssueToken(ctx context.Context, token, profile, key string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO tokens(token,profile,key,expires) VALUES(?,?,?,?)`, token, profile, key, expires.Unix())
	return err
}

// TokenDevice returns the device a valid token was issued to.
func (s *Store) TokenDevice(ctx context.Context, token, profile string, now time.Time) (string, bool, error) {
	var key string
	var expires int64
	err := s.db.QueryRowContext(ctx, `SELECT key, expires FROM tokens WHERE token=? AND profile=?`, token, profile).Scan(&key, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return key, expires > now.Unix(), nil
}

// NextSeq increments and returns a per-device counter.
func (s *Store) NextSeq(ctx context.Context, profile, key, name string) (int64, error) {
	var v int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO counters(profile,key,name,value) VALUES(?,?,?,1)
		ON CONFLICT(profile,key,name) DO UPDATE SET value=value+1 RETURNING value`, profile, key, name).Scan(&v)
	return v, err
}

// Unhandled is a request no profile handler answered.
type Unhandled struct {
	ID       int64     `json:"id"`
	TS       time.Time `json:"ts"`
	Protocol string    `json:"protocol"`
	Remote   string    `json:"remote"`
	Summary  string    `json:"summary"`
	Detail   string    `json:"detail"`
}

// AddUnhandled records a request for later inference.
func (s *Store) AddUnhandled(ctx context.Context, u Unhandled) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO unhandled(ts,protocol,remote,summary,detail) VALUES(?,?,?,?,?)`,
		u.TS.Unix(), u.Protocol, u.Remote, u.Summary, u.Detail)
	if err != nil {
		return err
	}
	// Keep the table bounded: a misbehaving device must not fill the disk.
	_, err = s.db.ExecContext(ctx, `DELETE FROM unhandled WHERE id <= (SELECT MAX(id) FROM unhandled) - 5000`)
	return err
}

// ListUnhandled returns the most recent unhandled requests.
func (s *Store) ListUnhandled(ctx context.Context, limit int) ([]Unhandled, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,ts,protocol,remote,summary,detail FROM unhandled ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Unhandled
	for rows.Next() {
		var u Unhandled
		var ts int64
		if err := rows.Scan(&u.ID, &ts, &u.Protocol, &u.Remote, &u.Summary, &u.Detail); err != nil {
			return nil, err
		}
		u.TS = time.Unix(ts, 0).UTC()
		out = append(out, u)
	}
	return out, rows.Err()
}
