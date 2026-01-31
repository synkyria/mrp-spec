MRP v1.0 — Minimum Review Pack (Agnostic) — Spec & Tools
========================================================

What this repo is
-----------------
MRP is a small, portable evidence bundle format for audit-ready review of refusal-capable /
viability-gated controllers under finite horizons.

A minimum MRP pack contains:
- frames.jsonl (step-by-step evidence)
- manifest.json (experiment metadata)
- checksums.sha256 (integrity verification)

This repository contains:
- the v1.0 specification (spec/)
- validation + pack utilities (tools/)

Requirements
------------
- Python 3.10+ (validator/tools)
- bash + shasum (macOS) or sha256sum (Linux) for checksums

Quick start (Happy Path)
------------------------
1) Validate an existing pack:
   python3 tools/validate_mrp.py --pack /path/to/MRP_pack_xyz

2) Build a pack from an evidence directory:
   bash tools/make_mrp_pack.sh /path/to/evidence_dir /path/to/output/MRP_pack_001

3) Edit manifest.json (fill policy ids / workload ids / timestamps)

4) Validate:
   python3 tools/validate_mrp.py --pack /path/to/output/MRP_pack_001

5) (Optional) Strict validation (treat WARN as failure):
   python3 tools/validate_mrp.py --pack /path/to/output/MRP_pack_001 --strict

Build a pack from an evidence directory
--------------------------------------
Evidence directory MUST contain at minimum:
- frames.jsonl

(and may contain: actions.jsonl, summary.csv, PACK_SUMMARY.json, PACK_EXPLANATION.md)

Create pack:
  bash tools/make_mrp_pack.sh /path/to/evidence_dir /path/to/output_dir/MRP_pack_name

Then edit manifest.json and validate:
  python3 tools/validate_mrp.py --pack /path/to/output_dir/MRP_pack_name

Compare packs (multi-policy)
----------------------------
If you have multiple single-policy packs, merge them into one compare pack:

  python3 tools/tools_merge_mrp_packs_v1.py \
    --out /path/to/MRP_pack_compare_001 \
    --packs \
      /path/to/MRP_pack_policyA_001 \
      /path/to/MRP_pack_policyB_001 \
      /path/to/MRP_pack_policyC_001

Optional: normalise frames (fill action_type / reason_code / witness) and fix manifest.policies:

  python3 tools/tools_normalize_mrp_pack.py \
    --pack /path/to/MRP_pack_compare_001 \
    --inplace \
    --fix-manifest-policies

Then validate:
  python3 tools/validate_mrp.py --pack /path/to/MRP_pack_compare_001

Specification
-------------
See spec/MRP_v1_0.md for:
- Required file schemas
- Conformance levels (MRP-A, MRP-B)
- Reviewer procedure (7 steps)

Notes
-----
- Real evidence packs should live outside git (zip + sha256), or be attached as releases.
- Using --strict is intended for CI / certification-style checks.
- MRP v1.0 is a format proposal, not a certified standard (yet).

License
-------
Apache License 2.0 (see LICENSE)

Citation
--------
See CITATION.cff
