package store

import (
	"errors"
	"strings"
	"time"

	"aki-cloud/backend/internal/models"
)

// ErrNotFound indicates resource missing.
var ErrNotFound = errors.New("not found")

// FindUserByEmail returns the user with the provided email, if any.
func (s *Store) FindUserByEmail(email string) (*models.User, error) {
	users, err := s.GetUsers()
	if err != nil {
		return nil, err
	}
	lower := strings.ToLower(email)
	for _, u := range users {
		if strings.EqualFold(u.Email, lower) {
			return &u, nil
		}
	}
	return nil, ErrNotFound
}

// UpsertUser creates or updates a user.
func (s *Store) UpsertUser(user models.User) error {
	users, err := s.GetUsers()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	user.UpdatedAt = now
	found := false
	for i, existing := range users {
		if existing.ID == user.ID {
			if user.CreatedAt.IsZero() {
				user.CreatedAt = existing.CreatedAt
			}
			users[i] = user
			found = true
			break
		}
	}
	if !found {
		if user.CreatedAt.IsZero() {
			user.CreatedAt = now
		}
		users = append(users, user)
	}
	return s.SaveUsers(users)
}

// DeleteUser removes a user by id.
func (s *Store) DeleteUser(id string) error {
	users, err := s.GetUsers()
	if err != nil {
		return err
	}
	out := make([]models.User, 0, len(users))
	for _, u := range users {
		if u.ID == id {
			continue
		}
		out = append(out, u)
	}
	return s.SaveUsers(out)
}

// GetUserByID returns a user by id.
func (s *Store) GetUserByID(id string) (*models.User, error) {
	users, err := s.GetUsers()
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.ID == id {
			return &u, nil
		}
	}
	return nil, ErrNotFound
}
