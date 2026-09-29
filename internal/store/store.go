package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrNotFound      = errors.New("store: not found")
	ErrUserDisabled  = errors.New("store: user is disabled")
	ErrWrongPassword = errors.New("store: password mismatch")
)

const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Salt         []byte    `json:"salt"`
	PasswordHash []byte    `json:"password_hash"`
	Iterations   int       `json:"iterations"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
}

type Session struct {
	ID               string     `json:"id"`
	UserID           string     `json:"user_id"`
	AccessHash       []byte     `json:"access_hash"`
	RefreshHash      []byte     `json:"refresh_hash"`
	Status           string     `json:"status"`
	CreatedAt        time.Time  `json:"created_at"`
	AccessExpiresAt  time.Time  `json:"access_expires_at"`
	RefreshExpiresAt time.Time  `json:"refresh_expires_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokeReason     string     `json:"revoke_reason,omitempty"`
}

type snapshot struct {
	Version  int       `json:"version"`
	Users    []User    `json:"users"`
	Sessions []Session `json:"sessions"`
	Retired  [][]byte  `json:"retired_refresh_hashes"`
}

// Store is the authoritative, persisted state for test accounts and sessions.
// Authentication decisions always read current in-memory state guarded by mu,
// and every state change is flushed to disk before it is reported as done.
type Store struct {
	mu   sync.RWMutex
	path string

	users      map[string]*User
	byUsername map[string]string
	sessions   map[string]*Session
	access     map[string]string
	refresh    map[string]string
	retired    map[string]string
}

func Open(path string) (*Store, error) {
	s := &Store{
		path:       path,
		users:      map[string]*User{},
		byUsername: map[string]string{},
		sessions:   map[string]*Session{},
		access:     map[string]string{},
		refresh:    map[string]string{},
		retired:    map[string]string{},
	}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		var snap snapshot
		if err := json.Unmarshal(b, &snap); err != nil {
			return nil, fmt.Errorf("store: decode %s: %w", path, err)
		}
		for i := range snap.Users {
			u := snap.Users[i]
			s.users[u.ID] = &u
			s.byUsername[u.Username] = u.ID
		}
		for i := range snap.Sessions {
			sess := snap.Sessions[i]
			s.sessions[sess.ID] = &sess
			if sess.Status == StatusActive {
				s.access[hex.EncodeToString(sess.AccessHash)] = sess.ID
				s.refresh[hex.EncodeToString(sess.RefreshHash)] = sess.ID
			}
		}
		for _, h := range snap.Retired {
			s.retired[hex.EncodeToString(h)] = ""
		}
	case errors.Is(err, os.ErrNotExist):
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return s, nil
}

func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func RandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Store) UserByUsername(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byUsername[username]
	if !ok {
		return nil, false
	}
	u := *s.users[id]
	return &u, true
}

func (s *Store) User(id string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, false
	}
	copy := *u
	return &copy, true
}

func (s *Store) ListUsers() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, *u)
	}
	return out
}

func (s *Store) CreateUser(u User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byUsername[u.Username]; exists {
		return fmt.Errorf("store: user %q already exists", u.Username)
	}
	if u.ID == "" {
		id, err := RandomToken()
		if err != nil {
			return err
		}
		u.ID = "u_" + id[:16]
	}
	stored := u
	s.users[u.ID] = &stored
	s.byUsername[u.Username] = u.ID
	return s.persistLocked()
}

// DisableUser marks the account disabled and revokes every active session.
// The revocation is persisted in the same transaction-like locked section.
func (s *Store) DisableUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byUsername[username]
	if !ok {
		return ErrNotFound
	}
	s.users[id].Enabled = false
	now := time.Now().UTC()
	for _, sess := range s.sessions {
		if sess.UserID == id && sess.Status == StatusActive {
			s.revokeLocked(sess, now, "account disabled")
		}
	}
	return s.persistLocked()
}

func (s *Store) CreateSession(sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.ID == "" {
		id, err := RandomToken()
		if err != nil {
			return err
		}
		sess.ID = "s_" + id[:16]
	}
	stored := *sess
	s.sessions[sess.ID] = &stored
	s.access[hex.EncodeToString(sess.AccessHash)] = sess.ID
	s.refresh[hex.EncodeToString(sess.RefreshHash)] = sess.ID
	return s.persistLocked()
}

// SessionByAccessToken returns a live session only while it is active.
// Revoked entries are removed from lookup indexes, so a cached token cannot
// authenticate after logout or account disabling.
func (s *Store) SessionByAccessToken(token string, now time.Time) (*Session, *User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, err := s.liveByIndexLocked(s.access, token, now)
	if err != nil {
		return nil, nil, err
	}
	u := s.users[sess.UserID]
	if u == nil || !u.Enabled {
		return nil, nil, ErrUserDisabled
	}
	uc := *u
	sc := *sess
	return &sc, &uc, nil
}

// RotateRefresh atomically consumes a refresh token and records replacement
// token hashes. Only one caller can succeed: the old refresh hash is moved to
// the retired set inside the same critical section and durable write.
func (s *Store) RotateRefresh(oldRefresh, newAccess, newRefresh string, now, accessExpiry, refreshExpiry time.Time) (*Session, *User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hex.EncodeToString(HashToken(oldRefresh))
	sid, ok := s.refresh[h]
	if !ok {
		// A retired refresh token was replayed; it never succeeds again.
		return nil, nil, ErrNotFound
	}
	sess := s.sessions[sid]
	if sess.Status != StatusActive || !sess.RefreshExpiresAt.After(now) {
		return nil, nil, ErrNotFound
	}
	u := s.users[sess.UserID]
	if u == nil || !u.Enabled {
		return nil, nil, ErrUserDisabled
	}

	delete(s.access, hex.EncodeToString(sess.AccessHash))
	delete(s.refresh, h)
	s.retired[h] = sess.ID

	sess.AccessHash = HashToken(newAccess)
	sess.RefreshHash = HashToken(newRefresh)
	sess.AccessExpiresAt = accessExpiry
	sess.RefreshExpiresAt = refreshExpiry

	s.access[hex.EncodeToString(sess.AccessHash)] = sess.ID
	s.refresh[hex.EncodeToString(sess.RefreshHash)] = sess.ID
	if err := s.persistLocked(); err != nil {
		return nil, nil, err
	}
	sc, uc := *sess, *u
	return &sc, &uc, nil
}

func (s *Store) RevokeByAccessToken(token, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sid := s.access[hex.EncodeToString(HashToken(token))]
	sess := s.sessions[sid]
	if sess == nil {
		return ErrNotFound
	}
	s.revokeLocked(sess, time.Now().UTC(), reason)
	return s.persistLocked()
}

func (s *Store) liveByIndexLocked(idx map[string]string, token string, now time.Time) (*Session, error) {
	sid := idx[hex.EncodeToString(HashToken(token))]
	sess := s.sessions[sid]
	if sess == nil || sess.Status != StatusActive {
		return nil, ErrNotFound
	}
	if !sess.AccessExpiresAt.After(now) {
		return nil, ErrNotFound
	}
	return sess, nil
}

func (s *Store) revokeLocked(sess *Session, now time.Time, reason string) {
	delete(s.access, hex.EncodeToString(sess.AccessHash))
	delete(s.refresh, hex.EncodeToString(sess.RefreshHash))
	sess.Status = StatusRevoked
	sess.RevokedAt = &now
	sess.RevokeReason = reason
}

func (s *Store) persistLocked() error {
	snap := snapshot{Version: 1}
	for _, u := range s.users {
		snap.Users = append(snap.Users, *u)
	}
	for _, sess := range s.sessions {
		snap.Sessions = append(snap.Sessions, *sess)
	}
	for h := range s.retired {
		b, err := hex.DecodeString(h)
		if err != nil {
			return err
		}
		snap.Retired = append(snap.Retired, b)
	}
	data, err := json.MarshalIndent(&snap, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
