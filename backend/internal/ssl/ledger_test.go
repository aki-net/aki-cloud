package ssl

import (
	"testing"
	"time"
)

func TestIssuanceLedgerReserve(t *testing.T) {
	dir := t.TempDir()
	ledger := newIssuanceLedger(dir)

	now := time.Unix(1_700_000_000, 0).UTC()

	allowed, next, err := ledger.reserve(2, time.Hour, now)
	if err != nil {
		t.Fatalf("reserve failed: %v", err)
	}
	if !allowed {
		t.Fatalf("expected first reservation to succeed")
	}
	if !next.IsZero() {
		t.Fatalf("expected zero next time on success, got %s", next)
	}

	allowed, next, err = ledger.reserve(2, time.Hour, now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("reserve failed: %v", err)
	}
	if !allowed {
		t.Fatalf("expected second reservation to succeed")
	}

	allowed, next, err = ledger.reserve(2, time.Hour, now.Add(20*time.Minute))
	if err != nil {
		t.Fatalf("reserve failed: %v", err)
	}
	if allowed {
		t.Fatalf("expected reservation to be denied when limit exceeded")
	}
	expectedNext := now.Add(time.Hour)
	if !next.Equal(expectedNext) {
		t.Fatalf("expected next=%s, got %s", expectedNext, next)
	}

	allowed, next, err = ledger.reserve(2, time.Hour, now.Add(70*time.Minute))
	if err != nil {
		t.Fatalf("reserve failed: %v", err)
	}
	if !allowed {
		t.Fatalf("expected reservation after window to succeed")
	}
	if !next.IsZero() {
		t.Fatalf("expected zero next time after success")
	}
}
