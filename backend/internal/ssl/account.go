package ssl

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/go-acme/lego/v4/registration"
)

type accountStore struct {
	path string
	mu   sync.Mutex
}

type accountPayload struct {
	Email        string                 `json:"email"`
	KeyPEM       string                 `json:"key_pem"`
	Registration *registration.Resource `json:"registration,omitempty"`
}

func newAccountStore(dataDir string) *accountStore {
	path := filepath.Join(dataDir, "cluster", "acme_account.json")
	return &accountStore{path: path}
}

func (s *accountStore) Load() (*acmeUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var payload accountPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	user := &acmeUser{}
	if err := user.fromSerializable(&payload); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *accountStore) Save(user *acmeUser) error {
	if user == nil {
		return errors.New("user nil")
	}
	payload, err := user.toSerializable()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	temp := s.path + ".tmp"
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, s.path)
}
