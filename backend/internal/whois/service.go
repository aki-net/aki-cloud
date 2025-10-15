package whois

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/araddon/dateparse"
)

const (
	defaultServer = "whois.iana.org:43"
)

// ErrDomainRequired indicates no domain was provided to the lookup.
var ErrDomainRequired = errors.New("whois: domain required")

// ErrNoExpiration indicates the WHOIS response did not include an expiry date.
var ErrNoExpiration = errors.New("whois: expiration not found")

// ErrParseExpiry wraps failures when parsing an expiry timestamp.
type ErrParseExpiry struct {
	Value string
	Err   error
}

func (e ErrParseExpiry) Error() string {
	return fmt.Sprintf("whois: parse expiration %q: %v", e.Value, e.Err)
}

func (e ErrParseExpiry) Unwrap() error {
	return e.Err
}

// Result captures a WHOIS lookup result.
type Result struct {
	Domain        string
	Raw           string
	RawExpiration string
	ExpiresAt     time.Time
}

// Service performs WHOIS lookups with basic referral handling.
type Service struct {
	timeout time.Duration
}

// New creates a WHOIS lookup service with the given socket timeout.
func New(timeout time.Duration) *Service {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Service{timeout: timeout}
}

// Lookup resolves WHOIS metadata for the supplied domain.
func (s *Service) Lookup(ctx context.Context, domain string) (Result, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	result := Result{Domain: domain}
	if domain == "" {
		return result, ErrDomainRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	root, body, _, err := s.fetchWithReferral(ctx, domain)
	result.Raw = body
	if result.Raw == "" {
		result.Raw = root
	}
	if err != nil && result.Raw == "" {
		return result, err
	}
	var lookupErr error
	if err != nil {
		lookupErr = err
	}
	expiry := extractExpiration(result.Raw)
	if expiry == "" {
		result.RawExpiration = ""
		if lookupErr != nil {
			return result, lookupErr
		}
		return result, ErrNoExpiration
	}
	result.RawExpiration = expiry
	parsed, err := dateparse.ParseIn(expiry, time.UTC)
	if err != nil {
		return result, ErrParseExpiry{Value: expiry, Err: err}
	}
	result.ExpiresAt = parsed.UTC()
	return result, nil
}

func (s *Service) fetchWithReferral(ctx context.Context, domain string) (string, string, string, error) {
	root, err := s.query(ctx, defaultServer, domain)
	if err != nil {
		return root, "", "", err
	}
	refer := extractReferral(root)
	if refer == "" {
		return root, root, "", nil
	}
	body, err := s.query(ctx, refer, domain)
	if err != nil {
		if body != "" {
			return root, body, refer, err
		}
		return root, root, refer, err
	}
	if body == "" {
		return root, root, refer, nil
	}
	return root, body, refer, nil
}

func (s *Service) query(ctx context.Context, server string, domain string) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		server = defaultServer
	}
	if !strings.Contains(server, ":") {
		server = server + ":43"
	}
	d := &net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(conn, "%s\r\n", domain); err != nil {
		return "", err
	}
	var b strings.Builder
	if _, err := io.Copy(&b, conn); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return b.String(), nil
}

func extractReferral(raw string) string {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := splitKeyValue(line)
		if !ok {
			continue
		}
		key = strings.ToLower(key)
		if key == "refer" || key == "whois" {
			return value
		}
	}
	return ""
}

func extractExpiration(raw string) string {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := splitKeyValue(line)
		if !ok {
			continue
		}
		if value == "" {
			continue
		}
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "expiry") ||
			strings.Contains(lowerKey, "expire") ||
			strings.Contains(lowerKey, "paid-till") ||
			strings.Contains(lowerKey, "renewal") ||
			strings.Contains(lowerKey, "valid-thru") {
			if hasDigits(value) {
				return value
			}
		}
	}
	return ""
}

func splitKeyValue(line string) (string, string, bool) {
	for _, sep := range []string{":", "="} {
		if idx := strings.Index(line, sep); idx != -1 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			return key, value, true
		}
	}
	return "", "", false
}

func hasDigits(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}
