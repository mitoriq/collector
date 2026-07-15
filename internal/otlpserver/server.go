package otlpserver

import (
	"io"
	"net/http"
)

type Options struct {
	OnReceive func(endpoint string, body []byte) error
}

func NewHTTPHandler(options Options) http.Handler {
	mux := http.NewServeMux()
	for _, path := range []string{"/v1/logs", "/v1/traces", "/v1/metrics"} {
		mux.HandleFunc(path, receiveOTLP(path, options))
	}

	return mux
}

func receiveOTLP(path string, options Options) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, "request body read failed", http.StatusBadRequest)
			return
		}
		if options.OnReceive != nil {
			if err := options.OnReceive(path, body); err != nil {
				http.Error(writer, "otlp receive failed", http.StatusInternalServerError)
				return
			}
		}

		writer.Header().Set("content-type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_, _ = writer.Write([]byte(`{"accepted":true}`))
	}
}
