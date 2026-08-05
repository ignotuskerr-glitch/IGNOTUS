package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"ignotus/engine/internal/protocol"
)

type Scanner struct {
	UserAgent string
}

func (s Scanner) Scan(parent context.Context, request protocol.Request) protocol.Response {
	started := time.Now()
	response := protocol.Response{ID: request.ID, Host: request.Host}
	timeout := time.Duration(request.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	addresses, dnsErr := net.DefaultResolver.LookupIPAddr(ctx, request.Host)
	for _, address := range addresses {
		response.IPs = append(response.IPs, address.IP.String())
	}
	sort.Strings(response.IPs)
	if cname, err := net.DefaultResolver.LookupCNAME(ctx, request.Host); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if !strings.EqualFold(cname, request.Host) {
			response.CNAME = cname
		}
	}

	ports := normalizedPorts(request.Ports)
	portResults := make(chan protocol.PortResult, len(ports))
	semaphore := make(chan struct{}, 64)
	var waitGroup sync.WaitGroup
	for _, port := range ports {
		waitGroup.Add(1)
		go func(port int) {
			defer waitGroup.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			portResults <- scanPort(ctx, request.Host, port, timeout)
		}(port)
	}
	waitGroup.Wait()
	close(portResults)
	for result := range portResults {
		response.Ports = append(response.Ports, result)
	}
	sort.Slice(response.Ports, func(left, right int) bool {
		return response.Ports[left].Port < response.Ports[right].Port
	})
	response.HTTP = s.probeHTTP(ctx, request.Host, response.Ports, timeout)

	if dnsErr != nil && len(response.IPs) == 0 {
		response.Error = dnsErr.Error()
	}
	response.DurationMS = time.Since(started).Milliseconds()
	return response
}

func normalizedPorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	clean := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			continue
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		clean = append(clean, port)
	}
	sort.Ints(clean)
	return clean
}

func scanPort(ctx context.Context, host string, port int, timeout time.Duration) protocol.PortResult {
	result := protocol.PortResult{Port: port}
	dialer := net.Dialer{Timeout: min(timeout, 1500*time.Millisecond)}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return result
	}
	result.Open = true
	if !isWebPort(port) {
		_ = connection.SetReadDeadline(time.Now().Add(min(timeout, 500*time.Millisecond)))
		buffer := make([]byte, 256)
		if size, readErr := connection.Read(buffer); readErr == nil && size > 0 {
			result.Banner = strings.TrimSpace(strings.Map(func(character rune) rune {
				if character == '\r' || character == '\n' || (character >= 32 && character < 127) {
					return character
				}
				return -1
			}, string(buffer[:size])))
		}
	}
	_ = connection.Close()
	return result
}

func (s Scanner) probeHTTP(
	ctx context.Context,
	host string,
	ports []protocol.PortResult,
	timeout time.Duration,
) *protocol.HTTPResult {
	for _, port := range ports {
		if !port.Open || !isWebPort(port.Port) {
			continue
		}
		schemes := []string{"https", "http"}
		if port.Port == 80 {
			schemes = []string{"http", "https"}
		}
		for _, scheme := range schemes {
			address := net.JoinHostPort(host, fmt.Sprint(port.Port))
			if (scheme == "https" && port.Port == 443) || (scheme == "http" && port.Port == 80) {
				address = host
			}
			url := scheme + "://" + address + "/"
			result, err := s.get(ctx, url, timeout)
			if err == nil {
				return result
			}
		}
	}
	return nil
}

func (s Scanner) get(ctx context.Context, url string, timeout time.Duration) (*protocol.HTTPResult, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", s.UserAgent)
	client := &http.Client{
		Timeout: min(timeout, 5*time.Second),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Security scanner: inspect self-signed endpoints.
		},
		CheckRedirect: func(_ *http.Request, redirects []*http.Request) error {
			if len(redirects) >= 5 {
				return errors.New("redirect limit reached")
			}
			return nil
		},
	}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	return &protocol.HTTPResult{
		URL:        url,
		Status:     response.StatusCode,
		Server:     response.Header.Get("Server"),
		FinalURL:   response.Request.URL.String(),
		DurationMS: time.Since(started).Milliseconds(),
	}, nil
}

func isWebPort(port int) bool {
	switch port {
	case 80, 443, 3000, 3001, 3005, 5000, 8000, 8080, 8443, 8888:
		return true
	default:
		return false
	}
}
