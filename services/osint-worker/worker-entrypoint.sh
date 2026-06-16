#!/bin/sh
set -e

PROFILE="${EPSOK_MODULE_PROFILE:-passive_ru}"
TARGET="${EPSOK_TARGET:?EPSOK_TARGET required}"
TARGET_TYPE="${EPSOK_TARGET_TYPE:?EPSOK_TARGET_TYPE required}"

# Module list resolved by Orchestrator in production; fallback for local dev:
MODULES="${EPSOK_MODULES:-sfp__stor_stdout,sfp_email,sfp_phone,sfp_whois}"

cd /app/spiderfoot

exec python3 sfcli.py -s "$TARGET" -t "$TARGET_TYPE" -m "$MODULES" -q -maximize
