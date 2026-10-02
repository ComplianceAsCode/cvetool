#!/usr/bin/env bash
set -u -o pipefail

cvetool="${CVETOOL_BIN:-./cvetool}"
expected_cve="CVE-2099-0001"
failures=0

fail() {
	echo ""
	echo "=========================================="
	echo "FAIL: $1"
	echo "=========================================="
	if [ -n "${2:-}" ]; then
		echo "--- output ---"
		echo "$2"
		echo "--- end output ---"
	fi
	echo ""
	failures=$((failures + 1))
}

# Test: `cvetool --version` exits successfully
echo "Test: cvetool --version exits successfully..."
version_output=$("$cvetool" --version 2>&1) || {
	fail "cvetool --version exited non-zero" "${version_output:-}"
}
if [ -z "${version_output:-}" ]; then
	fail "cvetool --version produced no output"
else
	echo "PASS: cvetool --version output: $version_output"
fi

# Scan tests use a copy because scan runs database migrations.
echo "Test: cvetool scan uses the bundled matcher fixture..."
tmpdb=$(mktemp)
tmpcatalog=$(mktemp)
tmpstdout=$(mktemp)
tmpstderr=$(mktemp)
unwritable_dir=""
cleanup() {
	[ -n "$unwritable_dir" ] && chmod 0755 "$unwritable_dir" 2>/dev/null && rm -rf "$unwritable_dir"
	rm -f "$tmpdb" "$tmpcatalog" "$tmpstdout" "$tmpstderr"
}
trap cleanup EXIT
fixture_ok=true
if cp -- tests/testdata/matcher.db "$tmpdb"; then
	echo "PASS: copied matcher fixture"
else
	fail "could not copy matcher fixture"
	fixture_ok=false
fi
if [ "$fixture_ok" = true ]; then
	# Test: a default root scan automatically generates a catalog and produces JSON
	echo "Test: cvetool scan without --catalog-path automatically generates a root catalog..."
	if "$cvetool" -l debug scan --db-path "$tmpdb" --format clair >"$tmpstdout" 2>"$tmpstderr"; then
		echo "PASS: default root scan exited successfully"
	else
		fail "cvetool scan without --catalog-path exited non-zero" "$(<"$tmpstderr")"
	fi
	if grep -qi "ERR" "$tmpstderr"; then
		fail "cvetool scan produced errors" "$(<"$tmpstderr")"
	else
		echo "PASS: default root scan produced no errors"
	fi
	if ! jq -e 'type == "object"' "$tmpstdout" >/dev/null 2>&1; then
		fail "cvetool scan without --catalog-path produced invalid JSON" "$(<"$tmpstdout")"
	else
		echo "PASS: cvetool scan without --catalog-path produced valid JSON"
	fi
	if sed -E $'s/\x1B\\[[0-9;]*m//g' "$tmpstderr" | grep -Eq '(^|[^[:alnum:]_])"?catalog_matches"?[[:space:]]*[:=][[:space:]]*[1-9][0-9]*([[:space:]]|$)'; then
		echo "PASS: automatic root catalog scan reported positive catalog_matches"
	else
		fail "automatic root catalog scan did not report positive catalog_matches" "$(<"$tmpstderr")"
	fi
	scan_output=$(<"$tmpstdout")
	if [[ "${scan_output:-}" != *"$expected_cve"* ]]; then
		fail "cvetool scan did not report $expected_cve" "${scan_output:-}"
	else
		echo "PASS: cvetool scan reported $expected_cve"
	fi

	# Generate one reusable catalog for the format scans below.
	echo "Test: cvetool catalog generates a reusable package catalog..."
	catalog_ok=true
	catalog_output=$("$cvetool" -l debug catalog --output-path "$tmpcatalog" 2>&1) || {
		fail "cvetool catalog exited non-zero" "${catalog_output:-}"
		catalog_ok=false
	}
	if [ "$catalog_ok" = true ]; then
		echo "PASS: cvetool catalog generated a reusable package catalog"
	fi

	if [ "$catalog_ok" = true ]; then
		# Test: `cvetool scan --format sarif` produces valid JSON with an explicit catalog
		echo "Test: cvetool scan --format sarif produces valid JSON..."
		json_output=$("$cvetool" -l debug scan --db-path "$tmpdb" --catalog-path "$tmpcatalog" --format sarif 2>/dev/null) || {
			fail "cvetool scan --format sarif exited non-zero" "${json_output:-}"
		}
		if ! echo "${json_output:-}" | jq . >/dev/null 2>&1; then
			fail "cvetool scan --format sarif produced invalid JSON" "$json_output"
		else
			echo "PASS: cvetool scan --format sarif output is valid JSON"
		fi

		# Test: `cvetool scan --format quay` produces valid JSON with an explicit catalog
		echo "Test: cvetool scan --format quay produces valid JSON..."
		json_output=$("$cvetool" -l debug scan --db-path "$tmpdb" --catalog-path "$tmpcatalog" --format quay 2>/dev/null) || {
			fail "cvetool scan --format quay exited non-zero" "${json_output:-}"
		}
		if ! echo "${json_output:-}" | jq . >/dev/null 2>&1; then
			fail "cvetool scan --format quay produced invalid JSON" "$json_output"
		else
			echo "PASS: cvetool scan --format quay output is valid JSON"
		fi
	else
		echo "SKIP: format scan tests skipped because cvetool catalog failed"
	fi
else
	echo "SKIP: scan tests skipped because the matcher fixture was unavailable"
fi

# Test: `cvetool scan` with a bad db path should fail
echo "Test: cvetool scan with bad db path fails..."
if bad_db_output=$("$cvetool" scan --db-path /nonexistent/bad.db 2>&1); then
	fail "cvetool scan with bad db path exited 0 (expected failure)" "$bad_db_output"
else
	echo "PASS: cvetool scan with bad db path exits non-zero"
fi

# Test: `cvetool update` with an unwritable db path should fail
echo "Test: cvetool update with unwritable db path fails..."
unwritable_dir=$(mktemp -d)
chmod 0000 "$unwritable_dir"
if [ "$(id -u)" -eq 0 ]; then
	if unwritable_output=$(runuser -u nobody -- "$cvetool" update --db-path "$unwritable_dir/db" 2>&1); then
		fail "cvetool update with unwritable db path exited 0 (expected failure)" "${unwritable_output:-}"
	else
		echo "PASS: cvetool update with unwritable db path exits non-zero"
	fi
else
	if unwritable_output=$("$cvetool" update --db-path "$unwritable_dir/db" 2>&1); then
		fail "cvetool update with unwritable db path exited 0 (expected failure)" "${unwritable_output:-}"
	else
		echo "PASS: cvetool update with unwritable db path exits non-zero"
	fi
fi

# Summary
echo ""
echo "=========================================="
if [ $failures -gt 0 ]; then
	echo "DONE: $failures test(s) FAILED"
	echo "=========================================="
	exit 1
else
	echo "DONE: all tests passed"
	echo "=========================================="
fi
