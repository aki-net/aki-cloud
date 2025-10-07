package auth

import (
	"time"

	"aki-cloud/backend/internal/models"

	"github.com/go-chi/jwtauth/v5"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Service encapsulates JWT issuance and validation.
type Service struct {
	tokenAuth *jwtauth.JWTAuth
}

// New creates a new auth service.
func New(secret []byte) *Service {
	return &Service{
		tokenAuth: jwtauth.New("HS256", secret, nil),
	}
}

// HashPassword returns a bcrypt hash of the password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPassword compares a bcrypt hash with a clear password.
func CheckPassword(hash string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// IssueToken returns a signed JWT for the provided user.
func (s *Service) IssueToken(user models.User) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   user.ID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	_, tokenString, err := s.tokenAuth.Encode(map[string]interface{}{
		"role":  string(user.Role),
		"email": user.Email,
		"sub":   user.ID,
		"exp":   claims.ExpiresAt.Time.Unix(),
		"iat":   claims.IssuedAt.Time.Unix(),
	})
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// TokenAuth exposes the underlying jwtauth instance for middleware use.
func (s *Service) TokenAuth() *jwtauth.JWTAuth {
	return s.tokenAuth
}
