package auth

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"idp/internal/store"
)

func newTestService(t *testing.T, accessTTL, refreshTTL time.Duration) (*Service, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	salt, hash, err := NewPasswordHash("generated-password", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(store.User{
		Username:     "alice",
		Salt:         salt,
		PasswordHash: hash,
		Iterations:   1000,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	return &Service{Store: st, AccessTTL: accessTTL, RefreshTTL: refreshTTL}, path
}

func TestLoginRefreshRotationAndReplay(t *testing.T) {
	svc, _ := newTestService(t, 30*time.Millisecond, time.Minute)
	first, _, err := svc.Login("alice", "generated-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Authenticate(first.AccessToken); err != nil {
		t.Fatalf("new access token rejected: %v", err)
	}

	time.Sleep(40 * time.Millisecond)
	if _, _, err := svc.Authenticate(first.AccessToken); err == nil {
		t.Fatal("expired access token still accepted")
	}
	rotated, err := svc.Refresh(first.RefreshToken)
	if err != nil {
		t.Fatalf("valid refresh rejected: %v", err)
	}
	if rotated.AccessToken == first.AccessToken || rotated.RefreshToken == first.RefreshToken {
		t.Fatal("refresh did not rotate token secrets")
	}
	if _, err := svc.Refresh(first.RefreshToken); err == nil {
		t.Fatal("used refresh token accepted on replay")
	}
	if _, _, err := svc.Authenticate(rotated.AccessToken); err != nil {
		t.Fatalf("rotated access token rejected: %v", err)
	}
}

func TestConcurrentRefreshOnlyOneSucceeds(t *testing.T) {
	svc, _ := newTestService(t, time.Minute, time.Minute)
	first, _, err := svc.Login("alice", "generated-password")
	if err != nil {
		t.Fatal(err)
	}

	const count = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, count)
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := svc.Refresh(first.RefreshToken)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("refresh succeeded %d times, want 1", successes)
	}
}

func TestLogoutAndDisableSurviveRestart(t *testing.T) {
	svc, path := newTestService(t, time.Minute, time.Minute)
	first, _, err := svc.Login("alice", "generated-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Logout(first.AccessToken); err != nil {
		t.Fatal(err)
	}

	restartedStore, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Service{Store: restartedStore, AccessTTL: time.Minute, RefreshTTL: time.Minute}
	if _, _, err := restarted.Authenticate(first.AccessToken); err == nil {
		t.Fatal("access token survived logged-out session restart")
	}
	if _, err := restarted.Refresh(first.RefreshToken); err == nil {
		t.Fatal("refresh token survived logged-out session restart")
	}

	second, _, err := restarted.Login("alice", "generated-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := restartedStore.DisableUser("alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.Authenticate(second.AccessToken); err == nil {
		t.Fatal("access token accepted after account disable")
	}
	if _, err := restarted.Refresh(second.RefreshToken); err == nil {
		t.Fatal("refresh token accepted after account disable")
	}

	finalStore, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	final := &Service{Store: finalStore, AccessTTL: time.Minute, RefreshTTL: time.Minute}
	if _, _, err := final.Authenticate(second.AccessToken); err == nil {
		t.Fatal("disabled-session revocation did not survive restart")
	}
	if _, err := final.Refresh(second.RefreshToken); err == nil {
		t.Fatal("disabled-session refresh did not survive restart")
	}
}

func TestWrongPasswordRejected(t *testing.T) {
	svc, _ := newTestService(t, time.Minute, time.Minute)
	if _, _, err := svc.Login("alice", "wrong"); err != ErrInvalidCredentials {
		t.Fatalf("error = %v, want ErrInvalidCredentials", err)
	}
}
