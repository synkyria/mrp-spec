#!/usr/bin/env python3
from __future__ import annotations
import json, hashlib
from pathlib import Path

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--packs", nargs="+", required=True)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    frames_all = []
    policies = []

    sources = []
    for d_str in args.packs:
        d = Path(d_str)
        mf = d/"manifest.json"
        fr = d/"frames.jsonl"
        if not mf.exists() or not fr.exists():
            raise SystemExit(f"Missing manifest/frames in {d}")

        m = json.loads(mf.read_text(encoding="utf-8"))
        exp = m.get("experiment") or {}
        pols = exp.get("policies") or []
        if len(pols) >= 1:
            pol = pols[0]
        else:
            # fallback: read first frame
            first = json.loads(fr.read_text(encoding="utf-8").splitlines()[0])
            pol = first.get("policy", d.name)
        policies.append(pol)
        sources.append({"policy": pol, "pack_dir": str(d.resolve())})

        for line in fr.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            obj.setdefault("policy", pol)
            frames_all.append(obj)

    (out/"frames.jsonl").write_text(
        "\n".join(json.dumps(x, ensure_ascii=False) for x in frames_all) + "\n",
        encoding="utf-8",
    )

    manifest = {
        "mrp_version": "1.0",
        "pack_type": "compare",
        "experiment": {"policies": policies},
        "sources": sources,
    }
    (out/"manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    cs = out/"checksums.sha256"
    lines = []
    for fp in sorted(out.rglob("*")):
        if fp.is_file() and fp.name not in {".DS_Store", "checksums.sha256"}:
            h = hashlib.sha256(fp.read_bytes()).hexdigest()
            lines.append(f"{h}  {fp.relative_to(out).as_posix()}")
    cs.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("OK: compare pack written:", out)
    print("Policies:", policies)
    print("Frames:", len(frames_all))

if __name__ == "__main__":
    main()
