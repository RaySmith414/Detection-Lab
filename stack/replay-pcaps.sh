#!/usr/bin/env bash
# Run every capture in simulations/pcaps through Suricata in a container and
# collect the alerts in stack/output/network-alerts.ndjson.
#
# `python -m detlab replay-check stack/output/network-alerts.ndjson` compares the
# alerts with what each capture must raise. `python -m detlab siem load` stores
# them in Elasticsearch.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p output
docker compose run --rm -T suricata > output/network-alerts.ndjson.tmp
mv output/network-alerts.ndjson.tmp output/network-alerts.ndjson
echo "$(wc -l < output/network-alerts.ndjson | tr -d ' ') alert(s) written to stack/output/network-alerts.ndjson"
