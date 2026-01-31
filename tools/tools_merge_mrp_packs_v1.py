#!/usr/bin/env python3
from __future__ import annotations

import argparse, json, hashlib
from datetime import datetime, timezone
from pathlib import Path

def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="Output pack dir")
    ap.add_argument("--packs", nargs="+", required=True, help="Input pack dirs (each must contain frames.jsonl + manifest.json)")
    args = ap.parse_args()

    out = Path(args.out).resolve()
    in_dirs = [Path(x).resolve() for x in args.packs]

    for d in in_dirs:
        if not (d/"frames.jsonl").exists() or not (d/"manifest.json").exists():
            raise SystemExit(f"Missing manifest/frames in {d}")

    frames_all = []
    policies = []

    for d in in_dirs:
        man = load_json(d/"manifest.json")
        exp = man.get("experiment") or {}
        pols = exp.get("policies") or []
        for p in pols:
            if p not in policies:
                policies.append(p)

        for line in (d/"frames.jsonl").read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            fr = json.loads(line)

            # ensure policy is present inside the frame
            if "policy" not in fr and pols:
                fr["policy"] = pols[0]

            frames_all.append(fr)

    if len(policies) < 2:
        raise SystemExit(f"Need >=2 policies across inputs for compare pack; got: {policies}")

    out.mkdir(parents=True, exist_ok=True)

    (out/"frames.jsonl").write_text(
        "\n".join(json.dumps(x, ensure_ascii=False) for x in frames_all) + "\n",
        encoding="utf-8",
    )

    manifest = {
        "pack_version": "MRP_v1.0",
        "generated_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z"),
        "generator": {"name": "tools_merge_mrp_packs_v1", "version": "1.0"},
        "experiment": {
            "seed": None,
            "policies": policies,
            "workloads": [
                {"id": "merged_none", "symmetry_break": "none"},
                {"id": "merged_hetero_mu", "symmetry_break": "hetero_mu"},
            ],
            "metrics": ["p95_q_overall", "slo_viol_steps", "refused_total", "completed_total", "meltdown_step"],
        },
    }

    (out/"manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    lines = []
    for fp in sorted(out.rglob("*")):
        if not fp.is_file():
            continue
        if fp.name in {".DS_Store", "checksums.sha256"}:
            continue
        lines.append(f"{sha256_file(fp)}  {fp.relative_to(out).as_posix()}")
    (out/"checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("OK: compare pack written:", out)
    print("Policies:", policies)
    print("Frames:", len(frames_all))

if __name__ == "__main__":
    main()
