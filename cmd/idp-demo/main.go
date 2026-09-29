// Command idp-demo exercises the local identity service without embedding any
// real credential. It starts an in-process server, creates a generated test
// account, then demonstrates refresh-token rotation, concurrent renewal,
// logout, account disabling, and revocation surviving a restart.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"idp/internal/auth"
	"idp/internal/httpapi"
	"idp/internal/store"
)

type tokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type refreshResult struct {
	status int
	tokens tokenPair
}

func main() {
	dataDir := flag.String("data-dir", filepath.Join(os.TempDir(), "idp-demo"), "persistent demo state directory")
	flag.Parse()
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	statePath := filepath.Join(*dataDir, "demo-state.json")
	_ = os.Remove(statePath)

	generated, err := store.RandomToken()
	must(err)
	password := generated[:18]
	service := openService(statePath)
	salt, hash, err := auth.NewPasswordHash(password, auth.DefaultPBKDF2Iterations)
	must(err)
	must(service.Store.CreateUser(store.User{
		Username:     "demo",
		Salt:         salt,
		PasswordHash: hash,
		Iterations:   auth.DefaultPBKDF2Iterations,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}))

	server := newLocalServer(httpapi.New(service))
	defer server.close()
	base := server.base

	fmt.Println("== 本地身份认证实验：账号和密码均由程序生成，敏感内容不写日志 ==")
	first := login(base, password)
	fmt.Println("1. 登录成功：获得短有效期访问令牌和独立刷新令牌，不是永久登录标记")
	assertMe(base, first.AccessToken, true)

	rotated := refresh(base, first.RefreshToken)
	fmt.Println("2. 正常续期成功：旧令牌对整体轮换，返回新的访问/刷新令牌对")
	assertMe(base, first.AccessToken, false)
	assertMe(base, rotated.AccessToken, true)
	replayStatus := rawRefresh(base, first.RefreshToken)
	fmt.Printf("3. 旧刷新凭据重放：HTTP %d（期望 401，用过即失效）\n", replayStatus)

	competing := rotated.RefreshToken
	results := make(chan refreshResult, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var pair tokenPair
			code := doJSON(http.MethodPost, base+"/v1/auth/refresh", "", map[string]string{
				"refresh_token": competing,
			}, &pair)
			results <- refreshResult{status: code, tokens: pair}
		}()
	}
	wg.Wait()
	close(results)

	ok, failed := 0, 0
	var current tokenPair
	for result := range results {
		if result.status == http.StatusOK {
			ok++
			current = result.tokens
		} else {
			failed++
		}
	}
	if ok != 1 {
		log.Fatalf("concurrent refresh succeeded %d times, want exactly 1", ok)
	}
	fmt.Printf("4. 8 个并发续期同时使用同一旧凭据：成功 %d、失败 %d（原子消费保证仅一次成功）\n", ok, failed)
	assertMe(base, current.AccessToken, true)

	logoutStatus := logout(base, current.AccessToken)
	fmt.Printf("5. 退出登录：HTTP %d；服务端立即撤销会话\n", logoutStatus)
	assertMe(base, current.AccessToken, false)
	if code := rawRefresh(base, current.RefreshToken); code != http.StatusUnauthorized {
		log.Fatalf("refresh after logout status %d, want 401", code)
	}
	fmt.Println("   退出后，本地仍缓存的访问/刷新凭据均无法再通过检查")

	second := login(base, password)
	assertMe(base, second.AccessToken, true)
	must(service.Store.DisableUser("demo"))
	fmt.Println("6. 账户停用：同账户全部活动会话被服务端撤销")
	assertMe(base, second.AccessToken, false)
	if code := rawRefresh(base, second.RefreshToken); code != http.StatusUnauthorized {
		log.Fatalf("refresh after disable status %d, want 401", code)
	}
	server.close()

	restarted := openService(statePath)
	restartServer := newLocalServer(httpapi.New(restarted))
	defer restartServer.close()
	assertMe(restartServer.base, second.AccessToken, false)
	if code := rawRefresh(restartServer.base, second.RefreshToken); code != http.StatusUnauthorized {
		log.Fatalf("refresh after restart status %d, want 401", code)
	}
	fmt.Println("7. 重新打开持久化状态模拟重启：退出和停用造成的撤销仍然有效")
	fmt.Printf("演示状态文件：%s（仅保存哈希、盐和撤销状态，不保存明文密码或令牌）\n", statePath)
}

func openService(path string) *auth.Service {
	st, err := store.Open(path)
	must(err)
	return &auth.Service{Store: st, AccessTTL: 90 * time.Second, RefreshTTL: 30 * time.Minute}
}

func login(base, password string) tokenPair {
	var got tokenPair
	code := doJSON(http.MethodPost, base+"/v1/auth/login", "", map[string]string{
		"username": "demo",
		"password": password,
	}, &got)
	if code != http.StatusOK {
		log.Fatalf("login failed with status %d", code)
	}
	return got
}

func refresh(base, token string) tokenPair {
	var got tokenPair
	code := doJSON(http.MethodPost, base+"/v1/auth/refresh", "", map[string]string{"refresh_token": token}, &got)
	if code != http.StatusOK {
		log.Fatalf("refresh failed with status %d", code)
	}
	return got
}

func rawRefresh(base, token string) int {
	return doJSON(http.MethodPost, base+"/v1/auth/refresh", "", map[string]string{"refresh_token": token}, nil)
}

func logout(base, token string) int {
	return doJSON(http.MethodPost, base+"/v1/auth/logout", token, nil, nil)
}

func assertMe(base, token string, expectOK bool) {
	code := doJSON(http.MethodGet, base+"/v1/me", token, nil, nil)
	got := code == http.StatusOK
	if got != expectOK {
		log.Fatalf("GET /v1/me returned %d, expect success=%v", code, expectOK)
	}
}

func doJSON(method, url, bearer string, body any, out any) int {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		must(err)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, reader)
	must(err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := localHTTPClient.Do(req)
	must(err)
	defer resp.Body.Close()
	if out != nil {
		must(json.NewDecoder(resp.Body).Decode(out))
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	return resp.StatusCode
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type localServer struct {
	base string
	h    http.Handler
}

var activeHandler atomic.Pointer[http.Handler]

var localHTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
	handler := *activeHandler.Load()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
})}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func newLocalServer(h http.Handler) *localServer {
	activeHandler.Store(&h)
	return &localServer{base: "http://idp.local", h: h}
}

func (s *localServer) close() {}
