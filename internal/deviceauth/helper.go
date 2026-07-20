package deviceauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html/template"
	"mime"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"
)

type (
	HelperState string
	RetryFunc   func(context.Context) (HelperView, error)

	HelperView struct {
		State    HelperState
		UserCode string
	}

	Helper struct {
		done         chan error
		host         string
		retry        RetryFunc
		retryContext context.Context
		retrying     bool
		retryToken   string
		revision     uint64
		server       *http.Server
		url          string
		view         HelperView
		mu           sync.RWMutex
	}
)

const (
	HelperReady HelperState = "helper_ready"
	Retrying    HelperState = "retrying"
	Authorized  HelperState = "authorized"
	Enrolled    HelperState = "enrolled"
	Expired     HelperState = "expired"
	HelperError HelperState = "error"
)

var userCodePattern = regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`)

func validHelperView(view HelperView) bool {
	validState := view.State == HelperReady || view.State == Retrying || view.State == Authorized || view.State == Enrolled ||
		view.State == Expired || view.State == HelperError
	return validState && userCodePattern.MatchString(view.UserCode)
}

func StartHelper(ctx context.Context, initial HelperView, retry RetryFunc) (*Helper, error) {
	if !validHelperView(initial) {
		return nil, errors.New("invalid helper view")
	}
	retryTokenBytes := make([]byte, 32)
	if _, err := rand.Read(retryTokenBytes); err != nil {
		return nil, errors.New("create local helper security token")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("start local helper")
	}
	host := listener.Addr().String()
	helper := &Helper{
		done: make(chan error, 1), host: host, retry: retry, retryContext: ctx,
		retryToken: base64.RawURLEncoding.EncodeToString(retryTokenBytes),
		url:        "http://" + host, view: initial,
	}
	helper.server = &http.Server{Handler: helper, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		err := helper.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		helper.done <- err
		close(helper.done)
	}()
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = helper.server.Shutdown(shutdownContext)
	}()
	return helper, nil
}

func (helper *Helper) URL() string        { return helper.url }
func (helper *Helper) Done() <-chan error { return helper.done }

func (helper *Helper) Update(view HelperView) error {
	if !validHelperView(view) {
		return errors.New("invalid helper view")
	}
	helper.mu.Lock()
	helper.view = view
	helper.revision++
	helper.mu.Unlock()
	return nil
}

func (helper *Helper) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	securityHeaders(writer.Header())
	if request.Host != helper.host {
		http.Error(writer, "invalid host", http.StatusMisdirectedRequest)
		return
	}
	if request.URL.RawQuery != "" {
		http.NotFound(writer, request)
		return
	}
	switch request.URL.Path {
	case "/":
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		helper.render(writer)
	case "/retry":
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", http.MethodPost)
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		helper.handleRetry(writer, request)
	default:
		http.NotFound(writer, request)
	}
}

func securityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}

func (helper *Helper) render(writer http.ResponseWriter) {
	helper.mu.RLock()
	view := helper.view
	canRetry := helper.retry != nil && !helper.retrying && (view.State == Expired || view.State == HelperError)
	helper.mu.RUnlock()
	data := helperPageData(view)
	data.CanRetry = canRetry
	data.RetryToken = helper.retryToken
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := helperPage.Execute(writer, data); err != nil {
		return
	}
}

func (helper *Helper) handleRetry(writer http.ResponseWriter, request *http.Request) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		http.Error(writer, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	origin := request.Header.Get("Origin")
	if origin != "" && origin != "null" && origin != helper.url {
		http.Error(writer, "forbidden", http.StatusForbidden)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 1<<10)
	if request.ParseForm() != nil || request.PostForm.Get("action") != "retry" {
		http.Error(writer, "invalid form", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(request.PostForm.Get("csrf")), []byte(helper.retryToken)) != 1 {
		http.Error(writer, "forbidden", http.StatusForbidden)
		return
	}
	helper.mu.Lock()
	if helper.retry == nil || helper.retrying || (helper.view.State != Expired && helper.view.State != HelperError) {
		helper.mu.Unlock()
		http.Error(writer, "retry unavailable", http.StatusConflict)
		return
	}
	helper.retrying = true
	helper.view = HelperView{State: Retrying, UserCode: helper.view.UserCode}
	helper.revision++
	retry := helper.retry
	revision := helper.revision
	retryContext := helper.retryContext
	helper.mu.Unlock()
	go helper.runRetry(retryContext, retry, revision)
	http.Redirect(writer, request, "/", http.StatusSeeOther)
}

func (helper *Helper) runRetry(ctx context.Context, retry RetryFunc, revision uint64) {
	view, retryErr := retry(ctx)
	helper.mu.Lock()
	defer helper.mu.Unlock()
	helper.retrying = false
	if retryErr != nil || !validHelperView(view) {
		if helper.view.State != Enrolled {
			helper.view = HelperView{State: HelperError, UserCode: helper.view.UserCode}
			helper.revision++
		}
		return
	}
	if helper.revision == revision {
		helper.view = view
		helper.revision++
	}
}

type pageData struct {
	CanRetry, Error, Refresh              bool
	Guidance, RetryToken, State, UserCode string
}

func helperPageData(view HelperView) pageData {
	guidance := map[HelperState]string{
		HelperReady: "MitoriqのWeb画面で確認コードと対象Workspaceを確認してください。",
		Retrying:    "新しい確認コードを準備しています。",
		Authorized:  "認証されました。安全な登録情報を受信しています。",
		Enrolled:    "このPCの接続が完了しました。この画面を閉じられます。",
		Expired:     "認証の有効期限が切れました。再試行してください。",
		HelperError: "接続を完了できませんでした。安全に再試行できます。",
	}[view.State]
	refresh := view.State == HelperReady || view.State == Retrying || view.State == Authorized
	return pageData{Error: view.State == HelperError || view.State == Expired, Guidance: guidance, Refresh: refresh, State: string(view.State), UserCode: view.UserCode}
}

var helperPage = template.Must(template.New("helper").Parse(`<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">{{if .Refresh}}<meta http-equiv="refresh" content="1">{{end}}
<title>Mitoriq PC接続</title><style>body{margin:0;font-family:system-ui,sans-serif;background:#f6f7f9;color:#17202a}main,.desktop-guide{margin:4rem auto;padding:2rem}main{max-width: 44rem;background:white;border-radius:1rem}label{display:block;font-weight:700}output{display:block;font:700 2rem ui-monospace,monospace;letter-spacing:.12em;margin:.5rem 0 1.5rem}button{font:inherit;padding:.75rem 1rem}.desktop-guide{display:none}
@media (max-width: 1023px){main{display:none}.desktop-guide{display:block;max-width:32rem}}@media (min-width:1024px){main{display:block}}</style></head><body><p class="desktop-guide" role="status">このHelperはdesktop専用です。1024px以上の画面幅で開いてください。</p>
<main><h1>MitoriqにこのPCを接続</h1><label for="user-code">確認コード</label><output id="user-code">{{.UserCode}}</output><p role="status" aria-live="polite">状態: {{.State}}</p>{{if .Error}}<p role="alert">{{.Guidance}}</p>{{else}}<p>{{.Guidance}}</p>{{end}}
{{if .CanRetry}}<form method="post" action="/retry"><input type="hidden" name="action" value="retry"><input type="hidden" name="csrf" value="{{.RetryToken}}"><button type="submit">再試行</button></form>{{end}}</main></body></html>`))
