MRP (Minimal Reproducible Pack) — Spec & Tools
=============================================

What this repo is
-----------------
MRP is a small, portable evidence bundle format:

- frames.jsonl
- manifest.json
- checksums.sha256

This repository contains:
- the v1.0 specification (spec/)
- validation + pack utilities (tools/)

Requirements
------------
- Python 3.10+ (validator/tools)
- bash + shasum (macOS) or sha256sum (Linux) for checksums

Quick start
-----------
Validate a pack:

    python3 tools/validate_mrp.py --pack /path/to/MRP_pack_xyz

Strict validation (treat WARN as failure):

    python3 tools/validate_mrp.py --pack /path/to/MRP_pack_xyz --strict

Build a pack from an evidence directory
---------------------------------------
Evidence directory must contain at minimum:
- frames.jsonl
(and may contain actions.jsonl, summary.csv, PACK_SUMMARY.json, PACK_EXPLANATION.md)

Create pack:

    bash tools/make_mrp_pack.sh /path/to/evidence_dir /path/to/output_dir/MRP_pack_name

Then edit manifest.json (policy/workload ids), and validate:

    python3 tools/validate_mrp.py --pack /path/to/output_dir/MRP_pack_name

Compare packs (multi-policy)
----------------------------
If you have multiple single-policy packs, merge them into one compare pack:

    python3 tools/tools_merge_mrp_packs_v1.py \
      --out packs/MRP_pack_compare_001 \
      --packs \
        packs/MRP_pack_envoy_proxy_001 \
        packs/MRP_pack_p2c_001 \
        packs/MRP_pack_synkyrian_001

Optional: normalise frames (fill action_type / reason_code / witness) and fix manifest.policies:

    python3 tools/tools_normalize_mrp_pack.py \
      --pack packs/MRP_pack_compare_001 \
      --inplace \
      --fix-manifest-policies

Then validate:

    python3 tools/validate_mrp.py --pack packs/MRP_pack_compare_001

Notes
-----
- Real evidence packs should live outside git (zip + sha256), or be attached as releases.
- If you use --strict, any WARN becomes failure (intended for CI / certification style use).
