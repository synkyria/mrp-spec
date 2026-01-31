#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


ACTIONS = {"ACCEPT", "HOLD", "REFUSE", "DROP"}

# Minimum integrity contract: checksums.sha256 must cover at least these files.
# Note: we deliberately do NOT require checksums.sha256 to cover itself.
REQUIRED_CHECKSUM_COVERAGE = {"frames.jsonl", "manifest.json"}

# Global strictness flag.
# - If STRICT_MODE is False (default), the validator is *compatibility tolerant*
#   (it accepts common legacy aliases like action_reason for reason_code and
#   does not require checksums to cover every file in the directory).
# - If STRICT_MODE is True, the validator enforces a tighter contract.
STRICT_MODE = False


@dataclass
class Issue:
    level: str   # "ERROR" | "WARN"
    msg: str


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    out = []
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as e:
                raise ValueError(f"{path.name}: invalid JSON on line {i}: {e}") from e
            if not isinstance(obj, dict):
                raise ValueError(f"{path.name}: line {i}: expected object, got {type(obj)}")
            out.append(obj)
    return out


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_checksums(path: Path) -> List[Tuple[str, str]]:
    """
    Accepts common formats:
      <hash>  <filename>
      <hash> *<filename>
    """
    entries = []
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^([0-9a-fA-F]{64})\s+[\*\s]?(.*)$", line)
            if not m:
                # allow comments
                if line.startswith("#"):
                    continue
                raise ValueError(f"{path.name}: cannot parse line {i}: {line}")
            hexd, fname = m.group(1).lower(), m.group(2).strip()
            if not fname:
                raise ValueError(f"{path.name}: missing filename on line {i}")
            entries.append((hexd, fname))
    return entries


def check_integrity(pack_dir: Path, issues: List[Issue]) -> None:
    """Validate checksums.sha256.

    Compatibility notes:
    - We do NOT require checksums.sha256 to checksum itself (avoids circularity).
    - In non-strict mode, we only require checksums coverage for a minimal set
      (frames.jsonl + manifest.json). Extra files missing from checksums are WARN.
    """

    chk = pack_dir / "checksums.sha256"
    if not chk.exists():
        issues.append(Issue("ERROR", "Missing checksums.sha256"))
        return

    try:
        entries = parse_checksums(chk)
    except Exception as e:
        issues.append(Issue("ERROR", f"checksums.sha256 parse failed: {e}"))
        return

    # Ensure all pack files are covered (excluding directories)
    pack_files = sorted([p for p in pack_dir.rglob("*") if p.is_file()])
    rels = {str(p.relative_to(pack_dir)) for p in pack_files}

    listed: set[str] = set()
    bad = 0

    def norm_name(name: str) -> str:
        name = name.strip().replace("\\", "/")
        if name.startswith("./"):
            name = name[2:]
        return name

    for hexd, fname_raw in entries:
        fname = norm_name(fname_raw)
        listed.add(fname)

        # Avoid self-checksum circularity.
        if fname == "checksums.sha256":
            issues.append(Issue("WARN", "checksums.sha256 includes itself; skipping self-hash check"))
            continue

        fp = pack_dir / fname
        if not fp.exists():
            issues.append(Issue("ERROR", f"Checksum lists missing file: {fname}"))
            bad += 1
            continue
        got = sha256_file(fp)
        if got != hexd:
            issues.append(Issue("ERROR", f"Checksum mismatch: {fname}"))
            bad += 1

    # Required minimum coverage (always enforced)
    missing_required = [r for r in sorted(REQUIRED_CHECKSUM_COVERAGE) if r not in listed]
    if missing_required:
        issues.append(Issue(
            "ERROR",
            "checksums.sha256 missing required file(s): " + ", ".join(missing_required),
        ))

    # Full directory coverage: strict → ERROR, non-strict → WARN
    missing_all = [r for r in sorted(rels) if r not in listed and r != "checksums.sha256"]
    if missing_all:
        lvl = "ERROR" if STRICT_MODE else "WARN"
        issues.append(Issue(
            lvl,
            f"checksums.sha256 does not cover {len(missing_all)} extra file(s): "
            + ", ".join(missing_all[:12])
            + (" ..." if len(missing_all) > 12 else ""),
        ))

    if bad == 0 and not missing_required:
        pass  # Integrity OK (hashes match)


def check_manifest(pack_dir: Path, issues: List[Issue]) -> Dict[str, Any]:
    mp = pack_dir / "manifest.json"
    if not mp.exists():
        issues.append(Issue("ERROR", "Missing manifest.json"))
        return {}

    try:
        manifest = json.loads(mp.read_text(encoding="utf-8"))
    except Exception as e:
        issues.append(Issue("ERROR", f"manifest.json invalid JSON: {e}"))
        return {}

    if not isinstance(manifest, dict):
        issues.append(Issue("ERROR", "manifest.json must be a JSON object"))
        return {}

    for k in ["pack_version", "generated_utc", "generator", "experiment"]:
        if k not in manifest:
            issues.append(Issue("ERROR", f"manifest.json missing required key: {k}"))

    gen = manifest.get("generator", {})
    if isinstance(gen, dict):
        for k in ["name", "version"]:
            if k not in gen:
                issues.append(Issue("ERROR", f"manifest.generator missing required key: {k}"))
    else:
        issues.append(Issue("ERROR", "manifest.generator must be an object"))

    exp = manifest.get("experiment", {})
    if isinstance(exp, dict):
        for k in ["policies", "workloads", "metrics"]:
            if k not in exp:
                issues.append(Issue("ERROR", f"manifest.experiment missing required key: {k}"))
        # seed can be int or null
        if "seed" not in exp:
            issues.append(Issue("WARN", "manifest.experiment has no seed; reproducibility may be limited"))
        pol = exp.get("policies")
        if not isinstance(pol, list) or not all(isinstance(x, str) for x in pol):
            issues.append(Issue("ERROR", "manifest.experiment.policies must be list[string]"))
        wls = exp.get("workloads")
        if not isinstance(wls, list) or not all(isinstance(x, dict) for x in wls):
            issues.append(Issue("ERROR", "manifest.experiment.workloads must be list[object]"))
        else:
            for i, w in enumerate(wls):
                if "id" not in w or not isinstance(w["id"], str) or not w["id"]:
                    issues.append(Issue("ERROR", f"manifest.experiment.workloads[{i}].id must be non-empty string"))
    else:
        issues.append(Issue("ERROR", "manifest.experiment must be an object"))

    return manifest


def _extract_action_type(fr: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """Return (action_type, source).

    Canonical key is 'action_type'. Common alternatives:
    - 'action' (string)
    - decision.outcome / decision.action_type
    - router.action / router.outcome
    """
    if isinstance(fr.get("action_type"), str):
        return fr["action_type"], "action_type"
    if isinstance(fr.get("action"), str):
        return fr["action"], "action"
    dec = fr.get("decision")
    if isinstance(dec, dict):
        for k in ("action_type", "outcome", "action"):
            v = dec.get(k)
            if isinstance(v, str):
                return v, f"decision.{k}"
    rout = fr.get("router")
    if isinstance(rout, dict):
        for k in ("action_type", "outcome", "action"):
            v = rout.get(k)
            if isinstance(v, str):
                return v, f"router.{k}"
    return None, ""


def _extract_reason_code(fr: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """Return (reason_code, source).

    Canonical key is 'reason_code'. Common alternatives:
    - 'action_reason' (legacy helper)
    - 'reason' (string)
    - decision.reason / decision.reason_code
    - router.reason / router.reason_code
    """
    if isinstance(fr.get("reason_code"), str):
        return fr["reason_code"], "reason_code"
    if isinstance(fr.get("action_reason"), str):
        return fr["action_reason"], "action_reason"
    if isinstance(fr.get("reason"), str):
        return fr["reason"], "reason"
    dec = fr.get("decision")
    if isinstance(dec, dict):
        for k in ("reason_code", "reason"):
            v = dec.get(k)
            if isinstance(v, str):
                return v, f"decision.{k}"
    rout = fr.get("router")
    if isinstance(rout, dict):
        for k in ("reason_code", "reason"):
            v = rout.get(k)
            if isinstance(v, str):
                return v, f"router.{k}"
    return None, ""


def check_frames(pack_dir: Path, issues: List[Issue]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    fp = pack_dir / "frames.jsonl"
    if not fp.exists():
        issues.append(Issue("ERROR", "Missing frames.jsonl"))
        return [], {}

    try:
        frames = read_jsonl(fp)
    except Exception as e:
        issues.append(Issue("ERROR", str(e)))
        return [], {}

    if not frames:
        issues.append(Issue("ERROR", "frames.jsonl is empty"))
        return [], {}

    per_policy_counts = defaultdict(Counter)
    witness_missing = 0
    bad_action = 0
    bad_reason = 0
    missing_step = 0
    missing_policy = 0
    missing_action_type = 0
    missing_reason_code = 0
    alias_action_type = 0
    alias_reason_code = 0

    for f in frames:
        if "step" not in f:
            missing_step += 1
            continue
        if "policy" not in f:
            missing_policy += 1
            continue

        pol = f.get("policy")
        if not isinstance(pol, str) or not pol:
            issues.append(Issue("ERROR", "Frame policy must be non-empty string"))
            continue

        act, act_src = _extract_action_type(f)
        if act is None:
            missing_action_type += 1
            continue
        if "action_type" not in f:
            alias_action_type += 1

        rc, rc_src = _extract_reason_code(f)
        if rc is None:
            missing_reason_code += 1
            continue
        if "reason_code" not in f:
            alias_reason_code += 1

        act_norm = act.strip().upper()
        if act_norm not in ACTIONS:
            bad_action += 1

        if not isinstance(rc, str) or not rc.strip():
            bad_reason += 1

        per_policy_counts[pol][act_norm] += 1

        if act_norm in {"HOLD", "REFUSE"}:
            w = f.get("witness")
            if not isinstance(w, dict) or not w.get("threshold_id") or "witness_value" not in w:
                witness_missing += 1

    if missing_step:
        issues.append(Issue("ERROR", f"{missing_step} frame(s) missing required key 'step'"))
    if missing_policy:
        issues.append(Issue("ERROR", f"{missing_policy} frame(s) missing required key 'policy'"))
    if missing_action_type:
        issues.append(Issue("ERROR", f"{missing_action_type} frame(s) missing action_type (or compatible alias)"))
    if missing_reason_code:
        issues.append(Issue("ERROR", f"{missing_reason_code} frame(s) missing reason_code (or compatible alias)"))

    if alias_action_type:
        lvl = "ERROR" if STRICT_MODE else "WARN"
        issues.append(Issue(lvl, f"{alias_action_type} frame(s) use legacy action field (source: action/decision.*). Consider adding canonical 'action_type'."))
    if alias_reason_code:
        lvl = "ERROR" if STRICT_MODE else "WARN"
        issues.append(Issue(lvl, f"{alias_reason_code} frame(s) use legacy reason field (e.g., action_reason/decision.reason). Consider adding canonical 'reason_code'."))

    if bad_action:
        issues.append(Issue("ERROR", f"{bad_action} frame(s) have invalid action_type (must be one of {sorted(ACTIONS)})"))
    if bad_reason:
        issues.append(Issue("ERROR", f"{bad_reason} frame(s) have invalid reason_code (must be non-empty string)"))
    if witness_missing:
        lvl = "ERROR" if STRICT_MODE else "WARN"
        issues.append(Issue(lvl, f"{witness_missing} HOLD/REFUSE frame(s) missing witness tuple (threshold_id, witness_value)"))

    summary = {
        "total_frames": len(frames),
        "policies": {p: dict(c) for p, c in per_policy_counts.items()},
    }
    return frames, summary


def infer_identifiability_from_manifest(manifest: Dict[str, Any]) -> Tuple[Optional[bool], str]:
    """Infer whether the pack satisfies MRP-B (identifiability) from manifest.

    Returns:
      - (True, msg)  : evidence of both symmetric and symmetry-broken workloads
      - (False, msg) : workloads present but do not show both regimes
      - (None, msg)  : manifest does not specify the needed structure; treat as SKIP unless --require_b
    """
    exp = manifest.get("experiment")
    if exp is None:
        return None, "No experiment section (MRP-B not specified)"
    if not isinstance(exp, dict):
        return None, "experiment is not an object (MRP-B not specified)"

    wls = exp.get("workloads")
    if wls is None:
        return None, "No experiment.workloads (MRP-B not specified)"
    if not isinstance(wls, list):
        return None, "experiment.workloads is not a list (MRP-B not specified)"

    # Look for at least one symmetric and one symmetry-broken workload
    sym = 0
    brk = 0
    for w in wls:
        if not isinstance(w, dict):
            continue
        sb = w.get("symmetry_break")
        # Accept several common spellings
        if sb in (None, "", "none", "symmetric"):
            sym += 1
        elif sb in ("hetero_mu", "hetero-mu", "asymmetric", "symmetry_broken"):
            brk += 1
    if sym >= 1 and brk >= 1:
        return True, "Found symmetric + symmetry-broken workloads in manifest"
    return False, "Did not find both symmetric and symmetry-broken workloads in manifest (MRP-B may fail)"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", default=".", help="Pack directory (default: current dir)")
    ap.add_argument("--strict", action="store_true", help="Fail on WARNs as well (optional)")
    ap.add_argument(
        "--require_b",
        action="store_true",
        help="Require MRP-B identifiability checks to pass (default: only enforce MRP-A)",
    )
    args = ap.parse_args()

    # Expose strictness to the lower-level checks.
    global STRICT_MODE
    STRICT_MODE = bool(args.strict)

    pack_dir = Path(args.pack).resolve()
    if not pack_dir.exists() or not pack_dir.is_dir():
        print(f"ERROR: pack dir not found: {pack_dir}", file=sys.stderr)
        return 2

    issues: List[Issue] = []

    check_integrity(pack_dir, issues)
    manifest = check_manifest(pack_dir, issues)
    frames, frame_summary = check_frames(pack_dir, issues)

    # Conformance decision
    has_error = any(i.level == "ERROR" for i in issues)
    mrp_a = not has_error

    mrp_b_ok, mrp_b_msg = infer_identifiability_from_manifest(manifest)

    # MRP-B is only meaningful if the pack declares >=2 policies.
    pols = []
    try:
        pols = manifest.get("experiment", {}).get("policies", [])
    except Exception:
        pols = []
    if not (isinstance(pols, list) and len(pols) >= 2):
        mrp_b_ok = None
        mrp_b_msg = "SKIP — <2 policies in manifest.experiment.policies"

    # Print report
    print("MRP v1.0 Validation Report")
    print("=========================")
    print(f"Pack dir  : {pack_dir}")
    print(f"Files     : {', '.join([p.name for p in pack_dir.iterdir()])}")
    print()

    # Action summary
    if frame_summary:
        print("Frames summary")
        print("-------------")
        print(f"Total frames: {frame_summary.get('total_frames')}")
        for p, cnts in sorted(frame_summary.get("policies", {}).items()):
            c = Counter(cnts)
            print(f"- {p}: " + ", ".join([f"{k}={c.get(k,0)}" for k in sorted(ACTIONS)]))
        print()

    print("Issues")
    print("------")
    for it in issues:
        print(f"{it.level}: {it.msg}")
    if not issues:
        print("WARN: No issues reported (unexpected).")
    print()

    print("Conformance")
    print("-----------")
    print(f"MRP-A (baseline): {'PASS' if mrp_a else 'FAIL'}")
    if mrp_b_ok is None:
        b_status = "SKIP"
    else:
        b_status = "PASS" if (mrp_a and mrp_b_ok) else "FAIL"
    print(f"MRP-B (identifiability): {b_status} — {mrp_b_msg}")
    print()

    if args.strict and any(i.level == "WARN" for i in issues):
        print("STRICT mode: WARN treated as failure.")
        return 1

    if not mrp_a:
        return 1

    if args.require_b:
        # In require_b mode, SKIP is treated as failure.
        if mrp_b_ok is not True:
            print("require_b: MRP-B did not PASS.", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
