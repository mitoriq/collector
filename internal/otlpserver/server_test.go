package otlpserver_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mitoriq/collector/internal/otlpserver"
)

func TestHTTPReceiverAcceptsOTLPSmokeEndpoints(t *testing.T) {
	handler := otlpserver.NewHTTPHandler(otlpserver.Options{})

	for _, path := range []string{"/v1/logs", "/v1/traces", "/v1/metrics"} {
		request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte("{}")))
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusAccepted {
			t.Fatalf("%s status = %d, want 202", path, response.Code)
		}
	}
}

func TestHTTPReceiverRejectsNonPOST(t *testing.T) {
	handler := otlpserver.NewHTTPHandler(otlpserver.Options{})
	request := httptest.NewRequest(http.MethodGet, "/v1/logs", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", response.Code)
	}
}

func TestHTTPReceiverInvokesReceiveHook(t *testing.T) {
	var receivedPath string
	var receivedBody string
	handler := otlpserver.NewHTTPHandler(otlpserver.Options{
		OnReceive: func(endpoint string, body []byte) error {
			receivedPath = endpoint
			receivedBody = string(body)
			return nil
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/traces", bytes.NewReader([]byte(`{"traceId":"1"}`)))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", response.Code)
	}
	if receivedPath != "/v1/traces" || receivedBody != `{"traceId":"1"}` {
		t.Fatalf("received path=%q body=%q", receivedPath, receivedBody)
	}
}

func TestHTTPReceiverReturns500WhenReceiveHookFails(t *testing.T) {
	handler := otlpserver.NewHTTPHandler(otlpserver.Options{
		OnReceive: func(_ string, _ []byte) error {
			return errors.New("queue unavailable")
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader([]byte("{}")))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", response.Code)
	}
}
