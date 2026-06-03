#!/usr/bin/env bash
# Simple test script for the dns-from-scratch project. It builds the project and runs a test query.

set -e # Exit immediately if a command exits with a non-zero status.

DNS=./dns-from-scratch
PASS=0
FAIL=0

check_pass() {
  local desc="$1"
  shift # Description of the test
  if "$@" > /dev/null 2>&1; then
    echo "  PASS: $desc"
    ((++PASS))
  else
    echo "  FAIL: $desc"
    ((++FAIL))
  fi
}

check_fail() {
  local desc="$1"
  shift # Description of the test
  if ! "$@" > /dev/null 2>&1; then
    echo "  PASS: $desc"
    ((++PASS))
  else
    echo "  FAIL: $desc (expected non-zero exit)"
    ((++FAIL))
  fi
}

echo "=== Valid usage ==="
check_pass "Query for example.com" $DNS example.com
check_pass "Query for google.com" $DNS google.com
check_pass "Query for edu23.itivinci.mo.it" $DNS edu23.itivinci.mo.it

echo "=== Invalid usage ==="
check_fail "No arguments" $DNS
check_fail "Too many arguments" $DNS example.com extra_arg

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
