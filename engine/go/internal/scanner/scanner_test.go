package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"ignotus/engine/internal/protocol"
)

func TestScanFindsLocalHTTPService(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Server", "ignotus-test")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	_, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	result := (Scanner{UserAgent: "IgnotusTest/1"}).Scan(
		context.Background(),
		protocol.Request{ID: "1", Host: "127.0.0.1", Ports: []int{port}, TimeoutMS: 2000},
	)
	if len(result.IPs) == 0 {
		t.Fatal("expected a resolved address")
	}
	if len(result.Ports) != 1 || !result.Ports[0].Open {
		t.Fatalf("expected port %d to be open: %#v", port, result.Ports)
	}
}

func TestNormalizedPortsFiltersAndSorts(t *testing.T) {
	ports := normalizedPorts([]int{443, 0, 80, 443, 70000})
	if len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Fatalf("unexpected ports: %#v", ports)
	}
}

func TestAlternateApplicationPortsAreWebCandidates(t *testing.T) {
	for _, port := range []int{3000, 3001, 3005, 5000, 8000, 8080, 8443, 8888} {
		if !isWebPort(port) {
			t.Fatalf("expected %d to be an alternate web port", port)
		}
	}
}
