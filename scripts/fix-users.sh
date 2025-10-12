#!/bin/bash

# Fix users with correct credentials in users.json

set -e

echo "Fixing user credentials..."

cd /opt/aki-cloud

# Stop backend temporarily
docker compose stop backend

# Create the correct users.json file with bcrypt hash for "test123"
cat > data/users/users.json << 'EOF'
[
  {
    "id": "admin",
    "email": "admin@aki.cloud",
    "password": "$2b$10$3SrxXPcinJEpCp4Eqzska.NB6R/RuhjKYDo9f9WwJMb2Z/.StHJ2C",
    "role": "admin",
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  },
  {
    "id": "user",
    "email": "user@aki.cloud",
    "password": "$2b$10$3SrxXPcinJEpCp4Eqzska.NB6R/RuhjKYDo9f9WwJMb2Z/.StHJ2C",
    "role": "user",
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
]
EOF

# Remove individual user files as they're not used
rm -f data/users/admin.json data/users/user.json

# Set proper permissions
chmod 644 data/users/users.json

# Start backend again
docker compose start backend

echo "Users fixed successfully!"
echo ""
echo "Login credentials:"
echo "  Admin: admin@aki.cloud / test123"
echo "  User:  user@aki.cloud / test123"
