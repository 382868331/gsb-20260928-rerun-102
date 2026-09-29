package auth

import (
	"errors"
	"time"

	"idp/internal/store"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type TokenSet struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
}

type Service struct {
	Store      *store.Store
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

func (s *Service) Login(username, password string) (TokenSet, *store.User, error) {
	u, ok := s.Store.UserByUsername(username)
	if !ok || !VerifyPassword(password, u.Salt, u.PasswordHash, u.Iterations) {
		return TokenSet{}, nil, ErrInvalidCredentials
	}
	if !u.Enabled {
		return TokenSet{}, nil, ErrInvalidCredentials
	}
	access, err := store.RandomToken()
	if err != nil {
		return TokenSet{}, nil, err
	}
	refresh, err := store.RandomToken()
	if err != nil {
		return TokenSet{}, nil, err
	}
	now := time.Now().UTC()
	sess := &store.Session{
		UserID:           u.ID,
		AccessHash:       store.HashToken(access),
		RefreshHash:      store.HashToken(refresh),
		Status:           store.StatusActive,
		CreatedAt:        now,
		AccessExpiresAt:  now.Add(s.AccessTTL),
		RefreshExpiresAt: now.Add(s.RefreshTTL),
	}
	if err := s.Store.CreateSession(sess); err != nil {
		return TokenSet{}, nil, err
	}
	return s.tokenSet(access, refresh), u, nil
}

func (s *Service) Authenticate(accessToken string) (*store.User, *store.Session, error) {
	sess, user, err := s.Store.SessionByAccessToken(accessToken, time.Now().UTC())
	if err != nil {
		return nil, nil, err
	}
	return user, sess, nil
}

func (s *Service) Refresh(oldRefresh string) (TokenSet, error) {
	access, err := store.RandomToken()
	if err != nil {
		return TokenSet{}, err
	}
	refresh, err := store.RandomToken()
	if err != nil {
		return TokenSet{}, err
	}
	now := time.Now().UTC()
	if _, _, err := s.Store.RotateRefresh(
		oldRefresh,
		access,
		refresh,
		now,
		now.Add(s.AccessTTL),
		now.Add(s.RefreshTTL),
	); err != nil {
		return TokenSet{}, err
	}
	return s.tokenSet(access, refresh), nil
}

func (s *Service) Logout(accessToken string) error {
	if err := s.Store.RevokeByAccessToken(accessToken, "logout"); err != nil {
		return err
	}
	return nil
}

func (s *Service) tokenSet(access, refresh string) TokenSet {
	return TokenSet{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.AccessTTL.Seconds()),
	}
}
