#!/bin/bash

# Enhanced seed script for demo domains with aliases, redirects and various TLS/ACME statuses

API_BASE="${API_BASE:-}"
if [ -z "$API_BASE" ]; then
    API_HOST="${API_HOST:-127.0.0.1}"
    BACKEND_PORT="${BACKEND_PORT:-8080}"
    API_BASE="http://${API_HOST}:${BACKEND_PORT}"
fi

echo "Seeding enhanced demo domains with aliases and redirects via ${API_BASE}..."

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

# Create primary domains first
echo "Creating primary domains for alias/redirect demonstration..."

# Primary domain 1 - will have aliases
api_call POST "/domains" '{
    "domain": "mainsite.com",
    "origin_ip": "192.168.1.100",
    "proxied": true,
    "ttl": 60,
    "tls": {
        "mode": "full",
        "use_recommended": true
    },
    "role": "primary"
}' "$USER_TOKEN"

# Primary domain 2 - will have both aliases and redirects
api_call POST "/domains" '{
    "domain": "company.com",
    "origin_ip": "192.168.1.101",
    "proxied": true,
    "ttl": 60,
    "tls": {
        "mode": "full_strict",
        "use_recommended": false
    },
    "role": "primary"
}' "$USER_TOKEN"

# Primary domain 3 - standalone
api_call POST "/domains" '{
    "domain": "standalone.com",
    "origin_ip": "192.168.1.102",
    "proxied": true,
    "ttl": 300,
    "tls": {
        "mode": "flexible",
        "use_recommended": true
    },
    "role": "primary"
}' "$USER_TOKEN"

# Sleep a bit to ensure domains are created
sleep 1

# Create aliases for mainsite.com
echo "Creating aliases for mainsite.com..."

api_call POST "/domains" '{
    "domain": "www.mainsite.com",
    "origin_ip": "192.168.1.100",
    "proxied": true,
    "ttl": 60,
    "role": "alias",
    "alias": {
        "target": "mainsite.com"
    }
}' "$USER_TOKEN"

api_call POST "/domains" '{
    "domain": "mainsite.org",
    "origin_ip": "192.168.1.100",
    "proxied": true,
    "ttl": 60,
    "role": "alias",
    "alias": {
        "target": "mainsite.com"
    }
}' "$USER_TOKEN"

api_call POST "/domains" '{
    "domain": "mainsite.net",
    "origin_ip": "192.168.1.100",
    "proxied": true,
    "ttl": 60,
    "role": "alias",
    "alias": {
        "target": "mainsite.com"
    }
}' "$USER_TOKEN"

# Create aliases and redirects for company.com
echo "Creating aliases and redirects for company.com..."

# Aliases
api_call POST "/domains" '{
    "domain": "www.company.com",
    "origin_ip": "192.168.1.101",
    "proxied": true,
    "ttl": 60,
    "role": "alias",
    "alias": {
        "target": "company.com"
    }
}' "$USER_TOKEN"

api_call POST "/domains" '{
    "domain": "company.io",
    "origin_ip": "192.168.1.101",
    "proxied": true,
    "ttl": 60,
    "role": "alias",
    "alias": {
        "target": "company.com"
    }
}' "$USER_TOKEN"

# Redirects to company.com
api_call POST "/domains" '{
    "domain": "oldcompany.com",
    "origin_ip": "192.168.1.101",
    "proxied": true,
    "ttl": 60,
    "role": "redirect",
    "redirect_rules": [
        {
            "source": "",
            "target": "company.com",
            "status_code": 301,
            "preserve_path": true,
            "preserve_query": true
        }
    ]
}' "$USER_TOKEN"

api_call POST "/domains" '{
    "domain": "company-old.com",
    "origin_ip": "192.168.1.101",
    "proxied": true,
    "ttl": 60,
    "role": "redirect",
    "redirect_rules": [
        {
            "source": "",
            "target": "company.com",
            "status_code": 301,
            "preserve_path": false,
            "preserve_query": true
        }
    ]
}' "$USER_TOKEN"

# External redirect example
api_call POST "/domains" '{
    "domain": "blog.company.com",
    "origin_ip": "192.168.1.101",
    "proxied": true,
    "ttl": 60,
    "role": "redirect",
    "redirect_rules": [
        {
            "source": "",
            "target": "https://medium.com/@company",
            "status_code": 302,
            "preserve_path": false,
            "preserve_query": false
        }
    ]
}' "$USER_TOKEN"

# Create a primary domain with path-specific redirects
echo "Creating domain with path redirects..."

api_call POST "/domains" '{
    "domain": "shop.com",
    "origin_ip": "192.168.1.110",
    "proxied": true,
    "ttl": 60,
    "tls": {
        "mode": "full",
        "use_recommended": true
    },
    "role": "primary",
    "redirect_rules": [
        {
            "source": "/old-products",
            "target": "/products",
            "status_code": 301,
            "preserve_path": true,
            "preserve_query": true
        },
        {
            "source": "/sale",
            "target": "https://shop.com/special-offers",
            "status_code": 302,
            "preserve_path": false,
            "preserve_query": true
        },
        {
            "source": "/blog",
            "target": "https://blog.shop.com",
            "status_code": 301,
            "preserve_path": true,
            "preserve_query": false
        }
    ]
}' "$USER_TOKEN"

# Create complex redirect scenarios
echo "Creating complex redirect scenarios..."

# Domain with whole-domain redirect and ignored path rules
api_call POST "/domains" '{
    "domain": "old-service.com",
    "origin_ip": "192.168.1.120",
    "proxied": true,
    "ttl": 60,
    "role": "redirect",
    "redirect_rules": [
        {
            "source": "",
            "target": "https://new-service.com",
            "status_code": 301,
            "preserve_path": true,
            "preserve_query": true
        },
        {
            "source": "/api",
            "target": "/v2/api",
            "status_code": 301,
            "preserve_path": true,
            "preserve_query": true
        }
    ]
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

# Create admin domains with relationships
echo "Creating admin demo domains with relationships..."

# Admin primary domain
api_call POST "/domains" '{
    "domain": "aki.cloud",
    "origin_ip": "10.0.0.100",
    "proxied": true,
    "ttl": 60,
    "tls": {
        "mode": "full_strict",
        "use_recommended": false
    },
    "role": "primary"
}' "$ADMIN_TOKEN"

# Admin aliases
api_call POST "/domains" '{
    "domain": "www.aki.cloud",
    "origin_ip": "10.0.0.100",
    "proxied": true,
    "ttl": 60,
    "role": "alias",
    "alias": {
        "target": "aki.cloud"
    }
}' "$ADMIN_TOKEN"

api_call POST "/domains" '{
    "domain": "aki.io",
    "origin_ip": "10.0.0.100",
    "proxied": true,
    "ttl": 60,
    "role": "alias",
    "alias": {
        "target": "aki.cloud"
    }
}' "$ADMIN_TOKEN"

# Admin redirects
api_call POST "/domains" '{
    "domain": "old.aki.cloud",
    "origin_ip": "10.0.0.100",
    "proxied": true,
    "ttl": 60,
    "role": "redirect",
    "redirect_rules": [
        {
            "source": "",
            "target": "aki.cloud",
            "status_code": 301,
            "preserve_path": true,
            "preserve_query": false
        }
    ]
}' "$ADMIN_TOKEN"

# Create orphaned examples (domains without relationships)
echo "Creating orphaned domains for demonstration..."

api_call POST "/domains" '{
    "domain": "orphan1.com",
    "origin_ip": "192.168.1.200",
    "proxied": false,
    "ttl": 300,
    "role": "primary"
}' "$USER_TOKEN"

api_call POST "/domains" '{
    "domain": "orphan2.net",
    "origin_ip": "192.168.1.201",
    "proxied": true,
    "ttl": 60,
    "tls": {
        "mode": "off",
        "use_recommended": false
    },
    "role": "primary"
}' "$USER_TOKEN"

echo ""
echo "Enhanced demo data seeded successfully!"
echo ""
echo "Summary:"
echo "- Primary domains with multiple aliases"
echo "- Domains with internal redirects (to other domains)"
echo "- Domains with external redirects (to external URLs)"
echo "- Domains with path-specific redirect rules"
echo "- Complex redirect scenarios with preserve path/query options"
echo "- Standalone domains without relationships"
echo "- Admin domain family (aki.cloud with aliases and redirects)"
echo ""
echo "Visual features demonstrated:"
echo "- Parent indicators only shown for domains with children"
echo "- Color coding only applied to domain families (not standalone)"
echo "- Redirect arrows instead of menu icons"
echo "- Proper alias and redirect modal layouts with tooltips"
echo ""
echo "You can now login and see the enhanced domain management interface!"
