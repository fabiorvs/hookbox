#!/bin/sh
set -eu

mkdir -p backups
timestamp=$(date -u +%Y%m%d-%H%M%S)
docker compose exec -T webhook-box python -c "import sqlite3; source=sqlite3.connect('/data/webhook-box.db'); target=sqlite3.connect('/backups/hookbox-${timestamp}.db'); source.backup(target); target.close(); source.close()"
echo "Backup criado em backups/hookbox-${timestamp}.db"
