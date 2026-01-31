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

Quick start
-----------
Validate a pack:

    python3 tools/validate_mrp.py --pack /path/to/MRP_pack_xyz

Strict validation:

    python3 tools/validate_mrp.py --pack /path/to/MRP_pack_xyz --strict

Build a pack from an evidence directory:

    bash tools/make_mrp_pack.sh /path/to/evidence_dir /path/to/output_dir/MRP_pack_name

Notes
-----
- Real evidence packs should live outside git (zip + sha256), or be attached as releases.
