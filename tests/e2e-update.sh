#!/usr/bin/env bash
set -u -o pipefail

veseer="${VESEER_BIN:-./veseer}"
tmpdb=$(mktemp)
trap 'rm -f "$tmpdb"' EXIT

echo "Test: veseer update processes the live feeds..."
if update_output=$("$veseer" -l debug update --db-path "$tmpdb" 2>&1); then
	echo "PASS: veseer update exited successfully"
else
	update_rc=$?
	echo "$update_output"
	echo "FAIL: veseer update exited non-zero (exit code $update_rc)"
	exit "$update_rc"
fi

echo "Test: veseer scan exits successfully after update..."
if scan_output=$("$veseer" -l debug scan --db-path "$tmpdb" 2>&1); then
	if echo "$scan_output" | grep -qi "ERR"; then
		echo "$scan_output"
		echo "FAIL: veseer scan produced errors"
		exit 1
	fi
	echo "PASS: veseer scan exited successfully"
else
	scan_rc=$?
	echo "$scan_output"
	echo "FAIL: veseer scan exited non-zero (exit code $scan_rc)"
	exit "$scan_rc"
fi
