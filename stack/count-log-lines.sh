#!/usr/bin/env bash
# Print how many documents Logstash should have stored for the files under stack/logs:
# one per JSON line and one per distinct line of the text logs.
set -euo pipefail

cd "$(dirname "$0")/logs"
json=0
if compgen -G "windows/*.json" > /dev/null; then
    json="$(cat windows/*.json | wc -l)"
fi
text=0
for file in linux/auth.log network/firewall.log; do
    if [ -f "$file" ]; then
        text=$((text + $(sort -u "$file" | wc -l)))
    fi
done
echo $((json + text))
