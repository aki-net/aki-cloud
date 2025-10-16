#!/bin/bash

# Seed script for demo domains with various TLS/ACME statuses

API_BASE="${API_BASE:-}"
if [ -z "$API_BASE" ]; then
    API_HOST="${API_HOST:-127.0.0.1}"
    BACKEND_PORT="${BACKEND_PORT:-8080}"
    API_BASE="http://${API_HOST}:${BACKEND_PORT}"
fi

echo "Seeding demo domains via ${API_BASE}..."

# Function to make API calls
api_call() {
    local method=$1
    local endpoint=$2
    local data=$3
    local token=$4
    
    if [ -z "$data" ]; then
        curl -s -X "$method" "${API_BASE}/api/v1$endpoint" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json"
    else
        curl -s -X "$method" "${API_BASE}/api/v1$endpoint" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "$data"
    fi
}

# Login as user
echo "Logging in as user@aki.cloud..."
USER_TOKEN=$(curl -s -X POST "${API_BASE}/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"user@aki.cloud","password":"test123"}' | jq -r '.token')

if [ "$USER_TOKEN" = "null" ] || [ -z "$USER_TOKEN" ]; then
    echo "Failed to login as user. Make sure the backend is running."
    exit 1
fi

echo "User token obtained."

# Create domains with different TLS configurations
echo "Creating demo domains for user..."

# Domain 1: Active TLS with Auto mode
api_call POST "/domains" '{
    "domain": "secure.example.com",
    "origin_ip": "192.168.1.10",
    "proxied": true,
    "ttl": 60,
    "tls": {
        "mode": "full",
        "use_recommended": true
    }
}' "$USER_TOKEN"

# Domain 2: Flexible TLS
api_call POST "/domains" '{
    "domain": "api.example.com",
    "origin_ip": "192.168.1.11",
    "proxied": true,
    "ttl": 300,
    "tls": {
        "mode": "flexible",
        "use_recommended": false
    }
}' "$USER_TOKEN"

# Domain 3: Full Strict TLS
api_call POST "/domains" '{
    "domain": "app.example.com",
    "origin_ip": "192.168.1.12",
    "proxied": true,
    "ttl": 120,
    "tls": {
        "mode": "full_strict",
        "use_recommended": false
    }
}' "$USER_TOKEN"

# Domain 4: DNS-only (no proxy, no TLS)
api_call POST "/domains" '{
    "domain": "dns-only.example.com",
    "origin_ip": "192.168.1.13",
    "proxied": false,
    "ttl": 300
}' "$USER_TOKEN"

# Domain 5: Awaiting DNS
api_call POST "/domains" '{
    "domain": "pending.example.com",
    "origin_ip": "192.168.1.14",
    "proxied": true,
    "ttl": 60,
    "tls": {
        "mode": "full",
        "use_recommended": false
    }
}' "$USER_TOKEN"

# Domain 6: TLS Off but proxied
api_call POST "/domains" '{
    "domain": "no-tls.example.com",
    "origin_ip": "192.168.1.15",
    "proxied": true,
    "ttl": 60,
    "tls": {
        "mode": "off",
        "use_recommended": false
    }
}' "$USER_TOKEN"

# Login as admin
echo "Logging in as admin@aki.cloud..."
ADMIN_TOKEN=$(curl -s -X POST "${API_BASE}/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@aki.cloud","password":"test123"}' | jq -r '.token')

if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo "Failed to login as admin."
    exit 1
fi

echo "Admin token obtained."

# Create domains for admin
echo "Creating demo domains for admin..."

# Admin Domain 1: Production site
api_call POST "/domains" '{
    "domain": "production.aki.cloud",
    "origin_ip": "10.0.0.100",
    "proxied": true,
    "ttl": 60,
    "tls": {
        "mode": "full_strict",
        "use_recommended": false
    }
}' "$ADMIN_TOKEN"

# Admin Domain 2: Staging site
api_call POST "/domains" '{
    "domain": "staging.aki.cloud",
    "origin_ip": "10.0.0.101",
    "proxied": true,
    "ttl": 300,
    "tls": {
        "mode": "flexible",
        "use_recommended": true
    }
}' "$ADMIN_TOKEN"

# Admin Domain 3: Dev site
api_call POST "/domains" '{
    "domain": "dev.aki.cloud",
    "origin_ip": "10.0.0.102",
    "proxied": true,
    "ttl": 60,
    "tls": {
        "mode": "full",
        "use_recommended": false
    }
}' "$ADMIN_TOKEN"

# Bulk import for variety
echo "Bulk importing subdomains..."
api_call POST "/domains/bulk" '{
    "domains": [
        "service1.example.com",
        "service2.example.com",
        "service3.example.com",
        "test1.example.com",
        "test2.example.com"
    ],
    "origin_ip": "192.168.1.20",
    "proxied": true,
    "ttl": 120,
    "tls": {
        "mode": "flexible",
        "use_recommended": true
    }
}' "$USER_TOKEN"

# Alias and redirect showcase
echo "Configuring alias and redirect scenarios..."

api_call POST "/domains" '{
    "domain": "store.example.com",
    "origin_ip": "10.0.0.120",
    "proxied": true,
    "ttl": 60,
    "tls": {
        "mode": "full_strict",
        "use_recommended": false
    }
}' "$ADMIN_TOKEN"

api_call POST "/domains" '{
    "domain": "www.store.example.com",
    "origin_ip": "",
    "proxied": true,
    "ttl": 60,
    "role": "alias",
    "alias": {
        "target": "store.example.com"
    }
}' "$ADMIN_TOKEN"

api_call POST "/domains" '{
    "domain": "legacy-store.example.com",
    "origin_ip": "",
    "proxied": false,
    "ttl": 60,
    "role": "redirect",
    "redirect_rules": [
        {
            "source": "",
            "target": "https://store.example.com",
            "status_code": 301,
            "preserve_path": true,
            "preserve_query": true
        }
    ]
}' "$ADMIN_TOKEN"

api_call PATCH "/domains/store.example.com" '{
    "role": "primary",
    "redirect_rules": [
        {
            "source": "/outlet",
            "target": "https://marketing.example.com/outlet",
            "status_code": 302,
            "preserve_path": false,
            "preserve_query": false
        },
        {
            "source": "/blog",
            "target": "https://blog.store.example.com",
            "status_code": 307,
            "preserve_path": true,
            "preserve_query": true
        }
    ]
}' "$ADMIN_TOKEN"

api_call POST "/domains" '{
    "domain": "external-redirect.example.com",
    "origin_ip": "",
    "proxied": false,
    "ttl": 60,
    "role": "redirect",
    "redirect_rules": [
        {
            "source": "",
            "target": "https://statuspage.io/store-status",
            "status_code": 302,
            "preserve_path": false,
            "preserve_query": true
        }
    ]
}' "$ADMIN_TOKEN"

echo "Demo data seeded successfully!"
echo ""
echo "Summary:"
echo "- User domains: sample set covering multiple TLS configurations"
echo "- Admin domains: production/staging/dev plus store.example.com family"
echo "- Alias/redirect demo: store.example.com with www alias, internal and external redirects"
echo "- Different TLS modes: Off, Flexible, Full, Full Strict, Auto"
echo "- Mixed proxy states: Proxied and DNS-only"
echo "- Includes path-based redirects and external target samples"
echo ""
echo "You can now login and see the domains with their TLS statuses."
