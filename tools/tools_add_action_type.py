#!/usr/bin/env python3
import json
from pathlib import Path

def main():
    pack = Path("packs/MRP_pack_envoy_proxy_001").resolve()
    fp = pack / "frames.jsonl"
    out = pack / "frames.jsonl.tmp"

    with fp.open("r", encoding="utf-8") as f_in, out.open("w", encoding="utf-8") as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)

            # Map existing structure -> required key
            # decision.outcome seems to be like "ACCEPT", "DROP", etc.
            outcome = None
            if isinstance(obj.get("decision"), dict):
                outcome = obj["decision"].get("outcome")

            if "action_type" not in obj:
                obj["action_type"] = outcome if outcome is not None else "UNKNOWN"

            # Optional: keep a canonical reason key too (safe, doesn’t break older readers)
            if "action_reason" not in obj:
                reason = None
                if isinstance(obj.get("decision"), dict):
                    reason = obj["decision"].get("reason")
                obj["action_reason"] = reason if reason is not None else ""

            f_out.write(json.dumps(obj, ensure_ascii=False) + "\n")

    fp.unlink()
    out.rename(fp)
    print(f"OK: normalized frames -> {fp}")

if __name__ == "__main__":
    main()
