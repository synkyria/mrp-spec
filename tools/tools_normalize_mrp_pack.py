#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Optional


ALLOWED = {"ACCEPT", "DROP", "HOLD", "REFUSE"}


def get_nested(d: Any, path: list[str]) -> Any:
    cur = d
    for k in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _norm_action(x: Any) -> Optional[str]:
    if isinstance(x, str):
        x = x.strip().upper()
        return x if x in ALLOWED else None
    return None


def infer_action(fr: dict) -> Optional[str]:
    # 1) canonical fields
    a = fr.get("action")
    if isinstance(a, dict):
        # sometimes nested
        for k in ("type", "action", "outcome"):
            got = _norm_action(a.get(k))
            if got:
                return got
    got = _norm_action(a)
    if got:
        return got

    got = _norm_action(fr.get("action_type"))
    if got:
        return got

    # 2) legacy decision.* patterns
    dec = fr.get("decision")
    if isinstance(dec, dict):
        # common: decision.outcome = "ACCEPT"
        got = _norm_action(dec.get("outcome"))
        if got:
            return got

        # sometimes: decision.action
        got = _norm_action(dec.get("action"))
        if got:
            return got

        # sometimes: decision.outcome is dict
        out = dec.get("outcome")
        if isinstance(out, dict):
            for k in ("outcome", "action", "type", "result"):
                got = _norm_action(out.get(k))
                if got:
                    return got

    # 3) nested fallbacks
    got = _norm_action(get_nested(fr, ["decision", "outcome"]))
    if got:
        return got

    got = _norm_action(get_nested(fr, ["decision", "action"]))
    if got:
        return got

    return None


def infer_reason(fr: dict, action: str) -> str:
    rc = (
        fr.get("reason_code")
        or fr.get("action_reason")
        or get_nested(fr, ["decision", "reason"])
        or fr.get("reason")
    )

    if isinstance(rc, str) and rc.strip():
        return rc.strip()

    # fallback defaults
    if action == "ACCEPT":
        return "ok"
    if action == "DROP":
        return "drop"
    if action == "HOLD":
        return "hold"
    if action == "REFUSE":
        return "refuse"
    return "unknown"


def ensure_witness(fr: dict, action: str, reason: str) -> None:
    if action not in {"HOLD", "REFUSE"}:
        return

    w = fr.get("witness")
    if not isinstance(w, dict):
        w = {}

    # try to recover something meaningful
    threshold_id = (
        w.get("threshold_id")
        or fr.get("threshold_id")
        or get_nested(fr, ["decision", "threshold_id"])
        or get_nested(fr, ["threshold", "id"])
        or "unspecified"
    )

    # witness_value can be numeric or string; keep as-is if present
    if "witness_value" in w:
        witness_value = w.get("witness_value")
    else:
        witness_value = (
            fr.get("witness_value")
            or fr.get("H")
            or fr.get("Hrig")
            or fr.get("h")
            or reason
        )

    w["threshold_id"] = str(threshold_id) if threshold_id is not None else "unspecified"
    w["witness_value"] = witness_value
    fr["witness"] = w


def write_checksums(pack: Path) -> None:
    cs = pack / "checksums.sha256"
    lines = []
    for fp in sorted(pack.rglob("*")):
        if not fp.is_file():
            continue
        if fp.name in {".DS_Store", "checksums.sha256"}:
            continue
        h = hashlib.sha256(fp.read_bytes()).hexdigest()
        rel = fp.relative_to(pack).as_posix()
        lines.append(f"{h}  {rel}")
    cs.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", required=True, help="Pack dir containing frames.jsonl + manifest.json")
    ap.add_argument("--inplace", action="store_true")
    ap.add_argument("--fix-manifest-policies", action="store_true")
    args = ap.parse_args()

    pack = Path(args.pack)
    fp = pack / "frames.jsonl"
    mp = pack / "manifest.json"
    if not fp.exists():
        raise SystemExit(f"Missing {fp}")
    if not mp.exists():
        raise SystemExit(f"Missing {mp}")

    policies_seen = set()
    out_lines = []
    changed_action = 0
    changed_reason = 0
    changed_witness = 0

    for line in fp.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        fr = json.loads(line)

        pol = fr.get("policy")
        if isinstance(pol, str) and pol.strip():
            policies_seen.add(pol.strip())

        action = infer_action(fr) or "UNKNOWN"
        if action != fr.get("action_type"):
            fr["action_type"] = action
            changed_action += 1

        reason = infer_reason(fr, action)
        if reason != fr.get("reason_code"):
            fr["reason_code"] = reason
            changed_reason += 1

        before_w = fr.get("witness")
        ensure_witness(fr, action, reason)
        after_w = fr.get("witness")
        if action in {"HOLD", "REFUSE"} and before_w != after_w:
            changed_witness += 1

        out_lines.append(json.dumps(fr, ensure_ascii=False))

    out_text = "\n".join(out_lines) + "\n"

    if args.inplace:
        fp.write_text(out_text, encoding="utf-8")

        if args.fix_manifest_policies:
            man = json.loads(mp.read_text(encoding="utf-8"))
            exp = man.get("experiment")
            if not isinstance(exp, dict):
                exp = {}
                man["experiment"] = exp
            exp["policies"] = sorted(policies_seen) if policies_seen else exp.get("policies", [])
            mp.write_text(json.dumps(man, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        write_checksums(pack)
        print(f"OK: normalised {pack}")
        print(f"  action_type filled/overwritten: {changed_action}")
        print(f"  reason_code filled/overwritten: {changed_reason}")
        print(f"  witness ensured (HOLD/REFUSE):  {changed_witness}")
    else:
        print(out_text, end="")


if __name__ == "__main__":
    main()
