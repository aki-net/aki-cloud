package store

import (
	"os"
	"time"

	"aki-cloud/backend/internal/models"
)

// GetLoginAttempt retrieves a login attempt record by key.
func (s *Store) GetLoginAttempt(key string) (models.LoginAttempt, bool, error) {
	if key == "" {
		return models.LoginAttempt{}, false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	attempts, err := s.loadLoginAttempts()
	if err != nil {
		return models.LoginAttempt{}, false, err
	}
	if attempts == nil {
		return models.LoginAttempt{}, false, nil
	}
	attempt, ok := attempts[key]
	return attempt, ok, nil
}

// ModifyLoginAttempts loads the attempts map, allows the caller to mutate in place,
// and persists the result when the modifier reports a change.
func (s *Store) ModifyLoginAttempts(modifier func(map[string]models.LoginAttempt) (bool, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	attempts, err := s.loadLoginAttempts()
	if err != nil {
		return err
	}
	if attempts == nil {
		attempts = make(map[string]models.LoginAttempt)
	}
	changed, err := modifier(attempts)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	return s.saveLoginAttempts(attempts)
}

// ResetLoginAttempts removes the provided keys from the attempts store.
func (s *Store) ResetLoginAttempts(keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	return s.ModifyLoginAttempts(func(attempts map[string]models.LoginAttempt) (bool, error) {
		changed := false
		for _, key := range keys {
			if key == "" {
				continue
			}
			if _, ok := attempts[key]; ok {
				delete(attempts, key)
				changed = true
			}
		}
		return changed, nil
	})
}

func (s *Store) loadLoginAttempts() (map[string]models.LoginAttempt, error) {
	path := s.loginAttemptsFile()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return make(map[string]models.LoginAttempt), nil
		}
		return nil, err
	}
	attempts := make(map[string]models.LoginAttempt)
	if err := readJSON(path, &attempts); err != nil {
		return nil, err
	}
	if attempts == nil {
		attempts = make(map[string]models.LoginAttempt)
	}
	return attempts, nil
}

func (s *Store) saveLoginAttempts(attempts map[string]models.LoginAttempt) error {
	path := s.loginAttemptsFile()
	if len(attempts) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return writeJSONAtomic(path, attempts)
}

// PruneLoginAttempts removes attempts whose last failure is before cutoff and are not locked.
func (s *Store) PruneLoginAttempts(cutoff time.Time) error {
	return s.ModifyLoginAttempts(func(attempts map[string]models.LoginAttempt) (bool, error) {
		if cutoff.IsZero() {
			return false, nil
		}
		now := time.Now().UTC()
		changed := false
		for key, attempt := range attempts {
			if attempt.LockedUntil.After(now) {
				continue
			}
			if attempt.LastFailure.IsZero() || attempt.LastFailure.Before(cutoff) {
				delete(attempts, key)
				changed = true
			}
		}
		return changed, nil
	})
}
