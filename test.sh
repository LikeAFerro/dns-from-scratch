#!/usr/bin/env bash
# Improved test script for the dns-from-scratch project.

DNS=./dns-from-scratch
LOG_FILE="test.log"
PASS=0
FAIL=0

# Clear previous log
echo "" > "$LOG_FILE"

# Helper to log and check just the exit code
check_exit() {
  local desc="$1"
  local expected_exit="$2"
  shift 2

  echo -e "\n[TEST]: $desc -> $DNS $*" >> "$LOG_FILE"

  # Run the command, append all output to the log file
  $DNS "$@" >> "$LOG_FILE" 2>&1
  local exit_code=$?

  if [ "$exit_code" -eq "$expected_exit" ]; then
    echo -e "  [\033[32mPASS\033[0m] $desc"
    ((++PASS))
  else
    echo -e "  [\033[31mFAIL\033[0m] $desc (Expected exit $expected_exit, got $exit_code. Check test.log)"
    ((++FAIL))
  fi
}

# Helper to verify specific text exists in the output
check_output() {
  local desc="$1"
  local expected_string="$2"
  shift 2

  echo -e "\n[TEST]: $desc -> $DNS $*" >> "$LOG_FILE"

  # Capture output and append to log
  local output
  output=$($DNS "$@" 2>&1 | tee -a "$LOG_FILE")
  local exit_code=${PIPESTATUS[0]}

  # Check if exit is 0 AND the output contains our expected string
  if [ "$exit_code" -eq 0 ] && echo "$output" | grep -q "$expected_string"; then
    echo -e "  [\033[32mPASS\033[0m] $desc"
    ((++PASS))
  else
    echo -e "  [\033[31mFAIL\033[0m] $desc (Failed to find '$expected_string' or crashed. Check test.log)"
    ((++FAIL))
  fi
}

echo "=== Valid Usage & Resolution ==="
check_output "Query for example.com" "Answers received:" example.com
check_output "Query for google.com" "Address:" google.com
check_exit "Query for edu23.itivinci.mo.it" 0 edu23.itivinci.mo.it
check_exit "IPv6 Flag (-6) sets correctly" 0 -6 google.com
check_exit "Help flag (-h) shows usage" 0 -h

echo "=== Invalid Usage ==="
check_exit "No arguments" 1
check_exit "Too many arguments" 1 example.com extra_arg
check_exit "Invalid hostname format (spaces)" 1 "my domain.com"
check_exit "Invalid hostname format (double dots)" 1 "example..com"

echo ""
echo "=== Summary ==="
echo "Results: $PASS passed, $FAIL failed"

# Exit with an error code if any tests failed so CI pipelines catch it
[ $FAIL -eq 0 ]
