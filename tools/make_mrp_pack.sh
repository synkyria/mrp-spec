#!/usr/bin/env bash
set -euo pipefail

# make_mrp_pack.sh
# Build an MRP pack from an existing evidence directory.
#
# Usage:
#   ./make_mrp_pack.sh /path/to/evidence_dir /path/to/output_dir/MRP_pack_name
#
# The evidence_dir must contain at minimum:
#   frames.jsonl
# and SHOULD contain:
#   actions.jsonl, summary.csv or PACK_SUMMARY.json
#
# This script will:
#   - copy evidence files into output pack dir
#   - create manifest.json (minimal, user-editable)
#   - create checksums.sha256 (sha256 of all files)
#
# Note: This is intentionally agnostic: no repo, no git required.

EVID_DIR="${1:-}"
OUT_DIR="${2:-}"

if [[ -z "${EVID_DIR}" || -z "${OUT_DIR}" ]]; then
  echo "Usage: $0 /path/to/evidence_dir /path/to/output_dir/MRP_pack_name" >&2
  exit 2
fi

EVID_DIR="$(cd "${EVID_DIR}" && pwd)"
OUT_DIR="$(mkdir -p "${OUT_DIR}" && cd "${OUT_DIR}" && pwd)"

if [[ ! -f "${EVID_DIR}/frames.jsonl" ]]; then
  echo "ERROR: evidence_dir missing frames.jsonl: ${EVID_DIR}" >&2
  exit 2
fi

mkdir -p "${OUT_DIR}"

# Copy known files if present
cp "${EVID_DIR}/frames.jsonl" "${OUT_DIR}/frames.jsonl"
[[ -f "${EVID_DIR}/actions.jsonl" ]] && cp "${EVID_DIR}/actions.jsonl" "${OUT_DIR}/actions.jsonl"
[[ -f "${EVID_DIR}/summary.csv" ]] && cp "${EVID_DIR}/summary.csv" "${OUT_DIR}/summary.csv"
[[ -f "${EVID_DIR}/PACK_SUMMARY.json" ]] && cp "${EVID_DIR}/PACK_SUMMARY.json" "${OUT_DIR}/PACK_SUMMARY.json"
[[ -f "${EVID_DIR}/PACK_EXPLANATION.md" ]] && cp "${EVID_DIR}/PACK_EXPLANATION.md" "${OUT_DIR}/PACK_EXPLANATION.md"

# Create minimal manifest (editable)
cat > "${OUT_DIR}/manifest.json" <<'JSON'
{
  "pack_version": "MRP_v1.0",
  "generated_utc": "REPLACE_WITH_UTC_TIMESTAMP",
  "generator": {
    "name": "REPLACE_WITH_GENERATOR_NAME",
    "version": "REPLACE_WITH_GENERATOR_VERSION"
  },
  "experiment": {
    "seed": null,
    "policies": ["REPLACE_POLICY_1", "REPLACE_POLICY_2"],
    "workloads": [
      { "id": "REPLACE_WORKLOAD_ID_1", "symmetry_break": "none" },
      { "id": "REPLACE_WORKLOAD_ID_2", "symmetry_break": "hetero_mu" }
    ],
    "metrics": ["p95_q_overall", "slo_viol_steps", "refused_total", "completed_total", "meltdown_step"]
  }
}
JSON

# Compute checksums (portable macOS/Linux)
(
  cd "${OUT_DIR}"
  rm -f checksums.sha256
  # List all files deterministically
  if command -v shasum >/dev/null 2>&1; then
    find . -type f -maxdepth 1 -print0 | sort -z | xargs -0 shasum -a 256 | sed 's#\s\+\*\?#  #g' > checksums.sha256
  elif command -v sha256sum >/dev/null 2>&1; then
    find . -type f -maxdepth 1 -print0 | sort -z | xargs -0 sha256sum > checksums.sha256
  else
    echo "ERROR: need shasum (macOS) or sha256sum (linux)" >&2
    exit 2
  fi
)

echo "OK: built MRP pack at ${OUT_DIR}"
echo "Next: edit manifest.json (timestamps/policies/workloads), then run:"
echo "  python3 validate_mrp.py --pack ${OUT_DIR}"
