#!/bin/bash
set -e

echo "=== Обновление .env на всех нодах ==="
echo ""

# Удаляем неактуальные параметры из .env на всех нодах
for ip_pass in "45.32.233.182:2=bECtBbY)=+@v3r:node-1" "45.76.35.20:E)9xCBexgSMH,,wT:node-2" "95.179.130.238:9,ZbfY)nAg*Qk.6Z:node-3" "136.244.107.242:S#b6S}!sQ**iJakW:node-4"; do
  IFS=':' read -r ip pass name <<< "$ip_pass"
  echo "Обновляем $name ($ip)..."
  
  sshpass -p "$pass" ssh -o StrictHostKeyChecking=no root@$ip "
    # Удаляем устаревшие параметры
    sed -i '/ENABLE_COREDNS/d' /opt/aki-cloud/.env
    sed -i '/ENABLE_OPENRESTY/d' /opt/aki-cloud/.env
    
    echo 'Удалены устаревшие параметры ENABLE_COREDNS и ENABLE_OPENRESTY'
  "
done

echo ""
echo "✅ Все .env файлы обновлены"
