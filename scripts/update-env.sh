#!/bin/bash
set -e

echo "=== Updating .env on all nodes ==="
echo ""

# Remove outdated parameters from .env on all nodes
for ip_pass in "45.32.233.182:2=bECtBbY)=+@v3r:node-1" "45.76.35.20:E)9xCBexgSMH,,wT:node-2" "95.179.130.238:9,ZbfY)nAg*Qk.6Z:node-3" "136.244.107.242:S#b6S}!sQ**iJakW:node-4"; do
  IFS=':' read -r ip pass name <<< "$ip_pass"
  echo "Updating $name ($ip)..."
  
  sshpass -p "$pass" ssh -o StrictHostKeyChecking=no root@$ip "
    # Remove outdated parameters
    sed -i '/ENABLE_COREDNS/d' /opt/aki-cloud/.env
    sed -i '/ENABLE_OPENRESTY/d' /opt/aki-cloud/.env
    
    echo 'Removed outdated parameters ENABLE_COREDNS and ENABLE_OPENRESTY'
  "
done

echo ""
echo "✅ All .env files updated"
