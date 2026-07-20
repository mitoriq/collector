package deviceauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClientPostsDeviceAuthorizationContractsInBody(t *testing.T) {
	deviceCode := "device-secret"
	bodies := map[string]string{}
	responses := map[string]string{
		startPath: `{"deviceCode":"device-secret","userCode":"ABCD-EFGH","expiresIn":600,"interval":5}`,
		pollPath:  `{"status":"authorization_pending","interval":5}`, completePath: `{"status":"enrolled"}`,
	}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.RawQuery != "" {
			t.Fatalf("request = %s %s", request.Method, request.URL.String())
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies[request.URL.Path] = string(body)
		writer.Header().Set("content-type", "application/json")
		_, _ = io.WriteString(writer, responses[request.URL.Path])
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	client := Client{BaseURL: server.URL, HTTPClient: server.Client()}

	started, err := client.Start(context.Background(), StartRequest{
		PublicKey: "public-key",
		Preflight: Preflight{ConfigWritable: true, CredentialWritable: true, JournalWritable: true, Platform: "macos"},
		Machine:   Machine{DisplayName: "Mac", LocalUUID: "local-uuid", OS: "macos"},
	})
	if err != nil || started.Interval != 5 || started.DeviceCode != deviceCode {
		t.Fatalf("Start() = %#v, %v", started, err)
	}
	poll, err := client.Poll(context.Background(), PollRequest{DeviceCode: deviceCode, CollectorVersion: "0.2.0"})
	if err != nil || poll.Status != StatusAuthorizationPending || poll.Interval != 5 {
		t.Fatalf("Poll() = %#v, %v", poll, err)
	}
	for _, status := range []Status{StatusSlowDown, StatusExpiredToken, StatusAccessDenied, StatusAuthorized, StatusEnrolled} {
		if !validStatus(status) {
			t.Fatalf("status %q is invalid", status)
		}
	}
	complete, err := client.Complete(context.Background(), CompleteRequest{DeviceCode: deviceCode})
	if err != nil || complete.Status != "enrolled" {
		t.Fatalf("Complete() = %#v, %v", complete, err)
	}
	if !strings.Contains(bodies[startPath], `"publicKey":"public-key"`) || !strings.Contains(bodies[startPath], `"localUuid":"local-uuid"`) ||
		bodies[pollPath] != `{"deviceCode":"device-secret","collectorVersion":"0.2.0"}` || bodies[completePath] != `{"deviceCode":"device-secret"}` {
		t.Fatalf("request bodies = %#v", bodies)
	}
}
func TestClientRejectsInvalidResponsesWithoutLeakingBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(writer, "device-secret server-secret")
	}))
	defer server.Close()
	_, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Poll(context.Background(), PollRequest{DeviceCode: "device-secret"})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error = %v", err)
	}
}

func TestClientRejectsRedirectsWithoutForwardingDeviceAuthorizationBody(t *testing.T) {
	redirectStatuses := []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	}
	for _, status := range redirectStatuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var destinationRequests atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				destinationRequests.Add(1)
				_, _ = io.Copy(io.Discard, request.Body)
				writer.WriteHeader(http.StatusNoContent)
			}))
			defer destination.Close()

			origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				http.Redirect(writer, &http.Request{}, destination.URL, status)
			}))
			defer origin.Close()

			_, err := (Client{BaseURL: origin.URL, HTTPClient: origin.Client()}).Poll(
				context.Background(),
				PollRequest{DeviceCode: "device-secret"},
			)
			if err == nil {
				t.Fatal("redirect was accepted")
			}
			if got := destinationRequests.Load(); got != 0 {
				t.Fatalf("destination requests = %d, want 0", got)
			}
		})
	}
}
