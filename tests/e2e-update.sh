#!/usr/bin/env bash
set -u -o pipefail

cvetool="${CVETOOL_BIN:-./cvetool}"
tmpdb=$(mktemp)
trap 'rm -f "$tmpdb"' EXIT

echo "Test: cvetool update processes the live feeds..."
if update_output=$("$cvetool" -l debug update --db-path "$tmpdb" 2>&1); then
	echo "PASS: cvetool update exited successfully"
else
	update_rc=$?
	echo "$update_output"
	echo "FAIL: cvetool update exited non-zero (exit code $update_rc)"
	exit "$update_rc"
fi

echo "Test: cvetool scan exits successfully after update..."
if scan_output=$("$cvetool" -l debug scan --db-path "$tmpdb" 2>&1); then
	if echo "$scan_output" | grep -qi "ERR"; then
		echo "$scan_output"
		echo "FAIL: cvetool scan produced errors"
		exit 1
	fi
	echo "PASS: cvetool scan exited successfully"
else
	scan_rc=$?
	echo "$scan_output"
	echo "FAIL: cvetool scan exited non-zero (exit code $scan_rc)"
	exit "$scan_rc"
fi
