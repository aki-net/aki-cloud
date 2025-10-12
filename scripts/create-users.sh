#!/bin/bash

# Script to create default users for aki-cloud

set -e

echo "Creating default users..."

# Path to data directory
DATA_DIR="/opt/aki-cloud/data"
if [ ! -d "$DATA_DIR" ]; then
    DATA_DIR="./data"
fi

# Check if API is accessible locally
if curl -s -f "http://localhost:8080/healthz" > /dev/null 2>&1; then
    API_URL="http://localhost:8080"
else
    API_URL="http://127.0.0.1:8080"
fi

echo "Using API at: $API_URL"

# First, try to get existing admin
EXISTING_ADMIN=$(docker compose exec backend sh -c 'find /data/users -name "*.json" -exec grep -l "\"role\":\"admin\"" {} \; | head -1' 2>/dev/null || true)

if [ -n "$EXISTING_ADMIN" ]; then
    echo "Found existing admin, removing old user data..."
    docker compose exec backend sh -c 'rm -rf /data/users/*.json' 2>/dev/null || true
fi

# Create admin user JSON
cat > /tmp/admin-user.json << 'EOF'
{
  "id": "admin",
  "email": "admin@aki.cloud",
  "password": "$2a$10$YourHashWillBeHere",
  "role": "admin",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
EOF

# Create regular user JSON
cat > /tmp/user-user.json << 'EOF'
{
  "id": "user",
  "email": "user@aki.cloud",
  "password": "$2a$10$YourHashWillBeHere",
  "role": "user",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
EOF

# Generate bcrypt hashes for password "test123"
echo "Generating password hashes..."
ADMIN_HASH=$(docker run --rm -i golang:1.21 sh -c 'cat > /tmp/hash.go << '\''EOF'\''
package main
import (
    "fmt"
    "golang.org/x/crypto/bcrypt"
)
func main() {
    hash, _ := bcrypt.GenerateFromPassword([]byte("test123"), 10)
    fmt.Print(string(hash))
}
EOF
go mod init hash && go get golang.org/x/crypto/bcrypt && go run /tmp/hash.go' 2>/dev/null)

# Update JSON files with proper hashes
sed -i "s|\$2a\$10\$YourHashWillBeHere|$ADMIN_HASH|g" /tmp/admin-user.json
sed -i "s|\$2a\$10\$YourHashWillBeHere|$ADMIN_HASH|g" /tmp/user-user.json

# Copy user files to data directory
echo "Creating user files..."
docker compose exec -T backend sh -c 'mkdir -p /data/users' 2>/dev/null || mkdir -p "$DATA_DIR/users"
docker cp /tmp/admin-user.json aki-cloud-backend-1:/data/users/admin.json 2>/dev/null || cp /tmp/admin-user.json "$DATA_DIR/users/admin.json"
docker cp /tmp/user-user.json aki-cloud-backend-1:/data/users/user.json 2>/dev/null || cp /tmp/user-user.json "$DATA_DIR/users/user.json"

# Clean up temp files
rm -f /tmp/admin-user.json /tmp/user-user.json

echo "Users created successfully!"
echo ""
echo "You can now login with:"
echo "  Admin: admin@aki.cloud / test123"
echo "  User:  user@aki.cloud / test123"
