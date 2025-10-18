#!/bin/bash
set -e

echo "=== Removing NODE_ID from .env files on all nodes ==="
echo ""

# Remove NODE_ID from .env on all nodes
for ip_pass in "45.32.233.182:2=bECtBbY)=+@v3r:node-1" "45.76.35.20:E)9xCBexgSMH,,wT:node-2" "95.179.130.238:9,ZbfY)nAg*Qk.6Z:node-3" "136.244.107.242:S#b6S}!sQ**iJakW:node-4"; do
  IFS=':' read -r ip pass name <<< "$ip_pass"
  echo "Updating $name ($ip)..."
  
  sshpass -p "$pass" ssh -o StrictHostKeyChecking=no root@$ip "
    # Remove NODE_ID from .env
    sed -i '/NODE_ID=/d' /opt/aki-cloud/.env
    
    # Remove files with saved NODE_ID if any
    rm -f /opt/aki-cloud/data/cluster/node_id
    rm -f /opt/aki-cloud/data/cluster/node_stable_id
    
    echo 'NODE_ID removed from .env and files'
  "
done

echo ""
echo "✅ NODE_ID removed from all nodes"
