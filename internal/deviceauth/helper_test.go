package deviceauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func startTestHelper(t *testing.T, view HelperView, retry RetryFunc) (*Helper, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	helper, err := StartHelper(ctx, view, retry)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-helper.Done():
		case <-time.After(2 * time.Second):
			t.Error("helper did not shut down")
		}
	})
	return helper, cancel
}

var noRedirectClient = &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}}

func mustHelperTestValue[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func TestHelperBindsRandomLoopbackPortAndRendersAccessibleSecureUI(t *testing.T) {
	helper, _ := startTestHelper(t, HelperView{State: HelperError, UserCode: "ABCD-EFGH"}, func(context.Context) (HelperView, error) { return HelperView{}, nil })
	parsed := mustHelperTestValue(url.Parse(helper.URL()))
	if parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.Port() == "0" {
		t.Fatalf("URL() = %q", helper.URL())
	}
	response := mustHelperTestValue(http.Get(helper.URL()))
	defer response.Body.Close()
	body := mustHelperTestValue(io.ReadAll(response.Body))
	html := string(body)
	if response.StatusCode != http.StatusOK || !strings.Contains(html, `role="status" aria-live="polite"`) || !strings.Contains(html, `role="alert"`) ||
		!strings.Contains(html, `<label for="user-code">確認コード</label>`) ||
		!strings.Contains(html, `id="user-code"`) || !strings.Contains(html, `<button type="submit">再試行</button>`) || !strings.Contains(html, "ABCD-EFGH") ||
		!strings.Contains(html, "@media (max-width: 1023px)") ||
		!strings.Contains(html, "1024px以上の画面幅") || !strings.Contains(html, "max-width: 44rem") {
		t.Fatalf("unexpected HTML: %s", html)
	}
	for _, forbidden := range []string{"mtq_d_", "mtq_e_", "deviceCode", "attemptId"} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("HTML contains forbidden value %q", forbidden)
		}
	}
	expectedHeaders := map[string]string{
		"Cache-Control":           "no-store",
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
	}
	for name, expected := range expectedHeaders {
		if actual := response.Header.Get(name); actual != expected {
			t.Errorf("%s = %q, want %q", name, actual, expected)
		}
	}
}

func TestHelperAnnouncesExpiredStateAsAnAlert(t *testing.T) {
	helper, _ := startTestHelper(t, HelperView{State: Expired, UserCode: "ABCD-EFGH"}, nil)
	response, err := http.Get(helper.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `role="alert"`) || !strings.Contains(string(body), "有効期限が切れました") {
		t.Fatalf("expired state was not announced as an alert: %s", body)
	}
}

func TestHelperRejectsUnexpectedHostPathAndMethod(t *testing.T) {
	helper, _ := startTestHelper(t, HelperView{State: Authorized, UserCode: "ABCD-EFGH"}, nil)
	tests := []struct {
		method, path, host string
		want               int
	}{
		{http.MethodGet, "/", "localhost:9999", http.StatusMisdirectedRequest},
		{http.MethodGet, "/other", "", http.StatusNotFound},
		{http.MethodPost, "/", "", http.StatusMethodNotAllowed},
		{http.MethodGet, "/retry", "", http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		request := mustHelperTestValue(http.NewRequest(test.method, helper.URL()+test.path, nil))
		if test.host != "" {
			request.Host = test.host
		}
		response := mustHelperTestValue(noRedirectClient.Do(request))
		response.Body.Close()
		if response.StatusCode != test.want {
			t.Errorf("%s %s host=%q status=%d, want %d", test.method, test.path, test.host, response.StatusCode, test.want)
		}
	}
}

func TestHelperRetryRequiresSameOriginFormAndRunsSingleFlight(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	helper, _ := startTestHelper(t, HelperView{State: HelperError, UserCode: "ABCD-EFGH"}, func(context.Context) (HelperView, error) {
		calls.Add(1)
		close(started)
		<-release
		return HelperView{State: HelperReady, UserCode: "JKLM-NPQR"}, nil
	})
	post := func(origin, contentType string) (*http.Response, error) {
		body := url.Values{"action": {"retry"}, "csrf": {helper.retryToken}}.Encode()
		request := mustHelperTestValue(http.NewRequest(http.MethodPost, helper.URL()+"/retry", strings.NewReader(body)))
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", contentType)
		return noRedirectClient.Do(request)
	}
	for _, invalid := range []struct {
		origin, contentType string
		want                int
	}{
		{"http://example.com", "application/x-www-form-urlencoded", http.StatusForbidden},
		{helper.URL(), "application/json", http.StatusUnsupportedMediaType},
	} {
		response := mustHelperTestValue(post(invalid.origin, invalid.contentType))
		response.Body.Close()
		if response.StatusCode != invalid.want {
			t.Fatalf("invalid retry status=%d, want %d", response.StatusCode, invalid.want)
		}
	}
	firstResult := make(chan int, 1)
	go func() {
		response, err := post(helper.URL(), "application/x-www-form-urlencoded")
		if err != nil {
			firstResult <- 0
			return
		}
		response.Body.Close()
		firstResult <- response.StatusCode
	}()
	<-started
	duplicate := mustHelperTestValue(post(helper.URL(), "application/x-www-form-urlencoded"))
	duplicate.Body.Close()
	if duplicate.StatusCode != http.StatusConflict || calls.Load() != 1 {
		t.Fatalf("duplicate status=%d calls=%d", duplicate.StatusCode, calls.Load())
	}
	close(release)
	if status := <-firstResult; status != http.StatusSeeOther {
		t.Fatalf("first retry status=%d", status)
	}
	deadline := time.Now().Add(time.Second)
	for {
		response := mustHelperTestValue(http.Get(helper.URL()))
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if strings.Contains(string(body), "JKLM-NPQR") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("retry result not rendered: %s", body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHelperRetryAcceptsOpaqueOriginOnlyWithCSRFToken(t *testing.T) {
	var calls atomic.Int32
	completed := make(chan struct{})
	helper, _ := startTestHelper(t, HelperView{State: HelperError, UserCode: "ABCD-EFGH"}, func(context.Context) (HelperView, error) {
		calls.Add(1)
		close(completed)
		return HelperView{State: HelperReady, UserCode: "JKLM-NPQR"}, nil
	})
	missingTokenRequest := mustHelperTestValue(http.NewRequest(http.MethodPost, helper.URL()+"/retry", strings.NewReader("action=retry")))
	missingTokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	missingTokenRequest.Header.Set("Origin", "null")
	missingTokenResponse := mustHelperTestValue(noRedirectClient.Do(missingTokenRequest))
	missingTokenResponse.Body.Close()
	if missingTokenResponse.StatusCode != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("missing CSRF token status=%d calls=%d", missingTokenResponse.StatusCode, calls.Load())
	}

	body := url.Values{"action": {"retry"}, "csrf": {helper.retryToken}}.Encode()
	request := mustHelperTestValue(http.NewRequest(http.MethodPost, helper.URL()+"/retry", strings.NewReader(body)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "null")

	response := mustHelperTestValue(noRedirectClient.Do(request))
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("opaque-origin retry status=%d calls=%d", response.StatusCode, calls.Load())
	}
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("opaque-origin retry callback did not complete")
	}
}

func TestHelperRetryFailureReturnsToRetryableErrorState(t *testing.T) {
	helper, _ := startTestHelper(t, HelperView{State: Expired, UserCode: "ABCD-EFGH"}, func(context.Context) (HelperView, error) {
		return HelperView{}, errors.New("retry failed")
	})
	body := url.Values{"action": {"retry"}, "csrf": {helper.retryToken}}.Encode()
	request := mustHelperTestValue(http.NewRequest(http.MethodPost, helper.URL()+"/retry", strings.NewReader(body)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := mustHelperTestValue(noRedirectClient.Do(request))
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("retry status=%d, want %d", response.StatusCode, http.StatusSeeOther)
	}

	deadline := time.Now().Add(time.Second)
	for {
		statusResponse := mustHelperTestValue(http.Get(helper.URL()))
		statusBody := mustHelperTestValue(io.ReadAll(statusResponse.Body))
		statusResponse.Body.Close()
		statusHTML := string(statusBody)
		if strings.Contains(statusHTML, "状態: error") && strings.Contains(statusHTML, `<button type="submit">再試行</button>`) {
			if !strings.Contains(statusHTML, "ABCD-EFGH") {
				t.Fatalf("retry failure lost the user code: %s", statusHTML)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("retry failure state not rendered: %s", statusHTML)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHelperRetryRedirectsBeforeCallbackCompletesAndUsesLifecycleContext(t *testing.T) {
	started := make(chan struct{})
	callbackCanceled := make(chan struct{})
	helper, cancel := startTestHelper(t, HelperView{State: HelperError, UserCode: "ABCD-EFGH"}, func(ctx context.Context) (HelperView, error) {
		close(started)
		<-ctx.Done()
		close(callbackCanceled)
		return HelperView{}, ctx.Err()
	})
	body := url.Values{"action": {"retry"}, "csrf": {helper.retryToken}}.Encode()
	request := mustHelperTestValue(http.NewRequest(http.MethodPost, helper.URL()+"/retry", strings.NewReader(body)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{
		CheckRedirect: noRedirectClient.CheckRedirect,
		Timeout:       time.Second,
	}

	response := mustHelperTestValue(client.Do(request))
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("retry status=%d, want %d", response.StatusCode, http.StatusSeeOther)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("retry callback did not start")
	}

	statusResponse := mustHelperTestValue(http.Get(helper.URL()))
	statusBody := mustHelperTestValue(io.ReadAll(statusResponse.Body))
	statusResponse.Body.Close()
	statusHTML := string(statusBody)
	if !strings.Contains(statusHTML, "状態: retrying") || !strings.Contains(statusHTML, `<meta http-equiv="refresh" content="1">`) {
		t.Fatalf("retrying state does not auto-refresh: %s", statusHTML)
	}
	select {
	case <-callbackCanceled:
		t.Fatal("retry callback used the request context")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case <-callbackCanceled:
	case <-time.After(time.Second):
		t.Fatal("retry callback did not receive lifecycle cancellation")
	}
}

func TestHelperRetryFailureDoesNotOverwriteTerminalEnrolledUpdate(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	completed := make(chan struct{})
	helper, _ := startTestHelper(t, HelperView{State: HelperError, UserCode: "ABCD-EFGH"}, func(context.Context) (HelperView, error) {
		close(started)
		<-release
		close(completed)
		return HelperView{}, errors.New("retry failed after enrollment")
	})
	body := url.Values{"action": {"retry"}, "csrf": {helper.retryToken}}.Encode()
	request := mustHelperTestValue(http.NewRequest(http.MethodPost, helper.URL()+"/retry", strings.NewReader(body)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := mustHelperTestValue(noRedirectClient.Do(request))
	response.Body.Close()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("retry callback did not start")
	}
	if err := helper.Update(HelperView{State: Enrolled, UserCode: "ABCD-EFGH"}); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("retry callback did not complete")
	}

	deadline := time.Now().Add(time.Second)
	for {
		statusResponse := mustHelperTestValue(http.Get(helper.URL()))
		statusBody := mustHelperTestValue(io.ReadAll(statusResponse.Body))
		statusResponse.Body.Close()
		statusHTML := string(statusBody)
		if strings.Contains(statusHTML, "状態: enrolled") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("newer update not rendered: %s", statusHTML)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHelperRetryFailureOverridesNonterminalUpdate(t *testing.T) {
	for _, test := range []struct {
		name  string
		retry RetryFunc
	}{
		{
			name: "callback error",
			retry: func(context.Context) (HelperView, error) {
				return HelperView{}, errors.New("retry failed after authorization")
			},
		},
		{
			name: "invalid callback view",
			retry: func(context.Context) (HelperView, error) {
				return HelperView{State: "invalid", UserCode: "JKLM-NPQR"}, nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			helper, _ := startTestHelper(t, HelperView{State: HelperError, UserCode: "ABCD-EFGH"}, func(ctx context.Context) (HelperView, error) {
				close(started)
				<-release
				return test.retry(ctx)
			})
			body := url.Values{"action": {"retry"}, "csrf": {helper.retryToken}}.Encode()
			request := mustHelperTestValue(http.NewRequest(http.MethodPost, helper.URL()+"/retry", strings.NewReader(body)))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := mustHelperTestValue(noRedirectClient.Do(request))
			response.Body.Close()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("retry callback did not start")
			}
			if err := helper.Update(HelperView{State: Authorized, UserCode: "JKLM-NPQR"}); err != nil {
				t.Fatal(err)
			}
			close(release)

			deadline := time.Now().Add(time.Second)
			for {
				statusResponse := mustHelperTestValue(http.Get(helper.URL()))
				statusBody := mustHelperTestValue(io.ReadAll(statusResponse.Body))
				statusResponse.Body.Close()
				statusHTML := string(statusBody)
				if strings.Contains(statusHTML, "状態: error") {
					if !strings.Contains(statusHTML, "JKLM-NPQR") || !strings.Contains(statusHTML, `<button type="submit">再試行</button>`) {
						t.Fatalf("retry failure did not preserve current code and retry action: %s", statusHTML)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("retry failure left nonterminal state active: %s", statusHTML)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func TestHelperUpdateIsRaceSafeAndCancellationShutsDown(t *testing.T) {
	helper, cancel := startTestHelper(t, HelperView{State: HelperReady, UserCode: "ABCD-EFGH"}, nil)
	var group sync.WaitGroup
	for index := 0; index < 20; index++ {
		group.Add(2)
		go func() {
			defer group.Done()
			if err := helper.Update(HelperView{State: Enrolled, UserCode: "ABCD-EFGH"}); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer group.Done()
			response, err := http.Get(helper.URL())
			if err == nil {
				response.Body.Close()
			}
		}()
	}
	group.Wait()
	if err := helper.Update(HelperView{State: "invalid", UserCode: "ABCD-EFGH"}); err == nil || strings.Contains(err.Error(), "ABCD") {
		t.Fatalf("invalid update error = %v", err)
	}
	cancel()
	select {
	case err := <-helper.Done():
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("helper shutdown timed out")
	}
}

func TestHelperRefreshesOnlyWhileAuthorizationCanAdvance(t *testing.T) {
	for _, test := range []struct {
		state       HelperState
		wantRefresh bool
		wantRetry   bool
	}{
		{HelperReady, true, false},
		{Retrying, true, false},
		{Authorized, true, false},
		{Enrolled, false, false},
		{Expired, false, true},
		{HelperError, false, true},
	} {
		t.Run(string(test.state), func(t *testing.T) {
			helper, _ := startTestHelper(t, HelperView{State: test.state, UserCode: "ABCD-EFGH"}, func(context.Context) (HelperView, error) {
				return HelperView{State: HelperReady, UserCode: "ABCD-EFGH"}, nil
			})
			response := mustHelperTestValue(http.Get(helper.URL()))
			body := mustHelperTestValue(io.ReadAll(response.Body))
			response.Body.Close()
			html := string(body)
			if got := strings.Contains(html, `<meta http-equiv="refresh" content="1">`); got != test.wantRefresh {
				t.Fatalf("refresh=%t, want %t: %s", got, test.wantRefresh, html)
			}
			if got := strings.Contains(html, `<button type="submit">再試行</button>`); got != test.wantRetry {
				t.Fatalf("retry=%t, want %t: %s", got, test.wantRetry, html)
			}
			if test.state == Enrolled && (!strings.Contains(html, "このPCの接続が完了しました") || !strings.Contains(html, "状態: enrolled")) {
				t.Fatalf("enrolled state is not observable: %s", html)
			}
		})
	}
}
