#!/bin/bash
# fix_docker_network.sh — Linux/Mac version
echo ""
echo "=== Aegis Docker Network Fix ==="
echo "Finding networks of running module containers..."

CONTAINERS=("aegis-link" "aegis-qr" "aegis-credential" "aegis-profile")
NETWORKS=()

for name in "${CONTAINERS[@]}"; do
    net=$(docker inspect "$name" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | tr ' ' '\n' | grep -v '^$' | head -1)
    if [ -n "$net" ]; then
        echo "  $name → network: $net"
        NETWORKS+=("$net")
    else
        echo "  $name → not running (skip)"
    fi
done

# Deduplicate
UNIQUE_NETS=($(echo "${NETWORKS[@]}" | tr ' ' '\n' | sort -u))

echo ""
echo "Connecting aegis-orchestra-dev to module networks..."
for net in "${UNIQUE_NETS[@]}"; do
    echo "  Connecting to: $net"
    docker network connect "$net" aegis-orchestra-dev 2>/dev/null && echo "  ✅ Connected!" || echo "  ⚠️  Already connected (ok)"
done

echo ""
echo "✅ Done. Restart: docker-compose -f docker-compose.dev.yml restart"
