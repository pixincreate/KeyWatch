#!/bin/sh

EXIT_CODE=0
for FILE in "$@"; do
  # Only scan text files
  if file "$FILE" | grep -q text; then
    echo "Scanning $FILE for secrets..."
    REPORT=$(key-watch --file "$FILE" --verbose)
    if echo "$REPORT" | grep -q '"status": "FAIL"'; then
      echo "Secret found in $FILE:"
      echo "$REPORT"
      EXIT_CODE=1
    fi
  fi
done
exit $EXIT_CODE
