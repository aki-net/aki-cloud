#!/bin/bash

# Reset users with correct credentials

set -e

echo "Resetting users to default credentials..."

cd /opt/aki-cloud

# Stop backend temporarily
docker compose stop backend

# Remove old user data
rm -rf data/users/*

# Create users directory
mkdir -p data/users

# Create admin user with bcrypt hash for "test123"
# Hash generated with python3 bcrypt
cat > data/users/admin.json << 'EOF'
{
  "id": "admin",
  "email": "admin@aki.cloud",
  "password": "$2b$10$3SrxXPcinJEpCp4Eqzska.NB6R/RuhjKYDo9f9WwJMb2Z/.StHJ2C",
  "role": "admin",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z",
  "version": {
    "counter": 1,
    "node_id": "node-1",
    "updated": 1704067200
  }
}
EOF

# Create regular user with same password
cat > data/users/user.json << 'EOF'
{
  "id": "user",
  "email": "user@aki.cloud",
  "password": "$2b$10$3SrxXPcinJEpCp4Eqzska.NB6R/RuhjKYDo9f9WwJMb2Z/.StHJ2C",
  "role": "user",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z",
  "version": {
    "counter": 1,
    "node_id": "node-1",
    "updated": 1704067200
  }
}
EOF

# Set proper permissions
chmod 644 data/users/*.json

# Start backend again
docker compose start backend

echo "Users reset successfully!"
echo ""
echo "Login credentials:"
echo "  Admin: admin@aki.cloud / test123"
echo "  User:  user@aki.cloud / test123"
