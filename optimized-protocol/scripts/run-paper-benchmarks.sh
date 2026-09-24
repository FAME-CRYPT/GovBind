#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

: "${ZKDEVLET_TAX_DEBT_PDF_A:?Set ZKDEVLET_TAX_DEBT_PDF_A to participant A's private tax-debt PDF}"
: "${ZKDEVLET_TAX_DEBT_PDF_B:?Set ZKDEVLET_TAX_DEBT_PDF_B to participant B's private tax-debt PDF}"
: "${ZKDEVLET_DRIVER_LICENSE_PDF_A:?Set ZKDEVLET_DRIVER_LICENSE_PDF_A to participant A's private driver-license PDF}"
: "${ZKDEVLET_DRIVER_LICENSE_PDF_B:?Set ZKDEVLET_DRIVER_LICENSE_PDF_B to participant B's private driver-license PDF}"
: "${ZKDEVLET_RESIDENCE_PDF_A:?Set ZKDEVLET_RESIDENCE_PDF_A to participant A's private residence PDF}"
: "${ZKDEVLET_RESIDENCE_PDF_B:?Set ZKDEVLET_RESIDENCE_PDF_B to participant B's private residence PDF}"

for pdf in \
  "$ZKDEVLET_TAX_DEBT_PDF_A" \
  "$ZKDEVLET_TAX_DEBT_PDF_B" \
  "$ZKDEVLET_DRIVER_LICENSE_PDF_A" \
  "$ZKDEVLET_DRIVER_LICENSE_PDF_B" \
  "$ZKDEVLET_RESIDENCE_PDF_A" \
  "$ZKDEVLET_RESIDENCE_PDF_B"; do
  if [[ ! -f "$pdf" ]]; then
    echo "Benchmark input does not exist: $pdf" >&2
    exit 1
  fi
done

TOTAL_SESSIONS=24
SESSION_NUMBER=0

begin_session() {
  SESSION_NUMBER=$((SESSION_NUMBER + 1))
  echo "Session ${SESSION_NUMBER}/${TOTAL_SESSIONS}: $1"
}

finish_session() {
  local remaining=$((TOTAL_SESSIONS - SESSION_NUMBER))
  echo "Completed session ${SESSION_NUMBER}/${TOTAL_SESSIONS}; ${remaining} session(s) remaining."
  if ((remaining > 0)); then
    echo "Cooling down for 30 seconds..."
    sleep 30
  fi
}

run_tax_debt() {
  local participant="$1"
  local pdf="$2"
  begin_session "tax debt, participant ${participant}"
  npm run benchmark -- --profile tax-debt --pdf "$pdf" --runs 3 --verification-runs 10
  finish_session
}

run_driver_license() {
  local participant="$1"
  local pdf="$2"
  begin_session "driver licence, participant ${participant}"
  npm run benchmark -- \
    --profile driver-license \
    --pdf "$pdf" \
    --maximum-traffic-tickets 1 \
    --maximum-total-penalty-points 1 \
    --maximum-active-penalty-points 1 \
    --runs 3 \
    --verification-runs 10
  finish_session
}

run_residence() {
  local participant="$1"
  local pdf="$2"
  begin_session "residence, participant ${participant}"
  npm run benchmark -- --profile residence --pdf "$pdf" --city-code 34 --runs 3 --verification-runs 10
  finish_session
}

echo "Round 1/4"
run_tax_debt A "$ZKDEVLET_TAX_DEBT_PDF_A"
run_driver_license B "$ZKDEVLET_DRIVER_LICENSE_PDF_B"
run_residence A "$ZKDEVLET_RESIDENCE_PDF_A"
run_tax_debt B "$ZKDEVLET_TAX_DEBT_PDF_B"
run_driver_license A "$ZKDEVLET_DRIVER_LICENSE_PDF_A"
run_residence B "$ZKDEVLET_RESIDENCE_PDF_B"

echo "Round 2/4"
run_driver_license B "$ZKDEVLET_DRIVER_LICENSE_PDF_B"
run_residence A "$ZKDEVLET_RESIDENCE_PDF_A"
run_tax_debt B "$ZKDEVLET_TAX_DEBT_PDF_B"
run_driver_license A "$ZKDEVLET_DRIVER_LICENSE_PDF_A"
run_residence B "$ZKDEVLET_RESIDENCE_PDF_B"
run_tax_debt A "$ZKDEVLET_TAX_DEBT_PDF_A"

echo "Round 3/4"
run_residence A "$ZKDEVLET_RESIDENCE_PDF_A"
run_tax_debt B "$ZKDEVLET_TAX_DEBT_PDF_B"
run_driver_license A "$ZKDEVLET_DRIVER_LICENSE_PDF_A"
run_residence B "$ZKDEVLET_RESIDENCE_PDF_B"
run_tax_debt A "$ZKDEVLET_TAX_DEBT_PDF_A"
run_driver_license B "$ZKDEVLET_DRIVER_LICENSE_PDF_B"

echo "Round 4/4"
run_tax_debt B "$ZKDEVLET_TAX_DEBT_PDF_B"
run_driver_license A "$ZKDEVLET_DRIVER_LICENSE_PDF_A"
run_residence B "$ZKDEVLET_RESIDENCE_PDF_B"
run_tax_debt A "$ZKDEVLET_TAX_DEBT_PDF_A"
run_driver_license B "$ZKDEVLET_DRIVER_LICENSE_PDF_B"
run_residence A "$ZKDEVLET_RESIDENCE_PDF_A"

echo "All 24 benchmark sessions completed."
