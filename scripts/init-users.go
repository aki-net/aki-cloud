package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func main() {
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "/data"
	}

	usersDir := filepath.Join(dataDir, "users")
	if err := os.MkdirAll(usersDir, 0755); err != nil {
		fmt.Printf("Failed to create users directory: %v\n", err)
		os.Exit(1)
	}

	// Generate password hash for "test123"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("test123"), 10)
	if err != nil {
		fmt.Printf("Failed to generate password hash: %v\n", err)
		os.Exit(1)
	}

	now := time.Now().UTC()

	// Create admin user
	admin := User{
		ID:        "admin",
		Email:     "admin@aki.cloud",
		Password:  string(passwordHash),
		Role:      "admin",
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Create regular user
	user := User{
		ID:        "user",
		Email:     "user@aki.cloud",
		Password:  string(passwordHash),
		Role:      "user",
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Save admin
	if err := saveUser(usersDir, admin); err != nil {
		fmt.Printf("Failed to save admin user: %v\n", err)
		os.Exit(1)
	}

	// Save user
	if err := saveUser(usersDir, user); err != nil {
		fmt.Printf("Failed to save regular user: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Users created successfully!")
	fmt.Println("\nYou can now login with:")
	fmt.Println("  Admin: admin@aki.cloud / test123")
	fmt.Println("  User:  user@aki.cloud / test123")
}

func saveUser(dir string, user User) error {
	data, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return err
	}

	filename := filepath.Join(dir, user.ID+".json")
	return ioutil.WriteFile(filename, data, 0644)
}
