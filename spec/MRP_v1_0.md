# MRP v1.0 — Minimum Review Pack for Audit-Ready Refusal (Agnostic)
Status: Draft v1.0  
Scope: Evidence-first verification for refusal-capable, viability-gated controllers under finite horizons.

## 0) Purpose
MRP is a carryable evidence bundle that enables a third-party reviewer to verify:
1) Refusal is explicit (not silent drop),
2) Refusal is audit-ready (reason + witness + threshold id),
3) Ablations are identifiable under symmetry-breaking workloads,
4) Results are reproducible (manifest + checksums).

MRP does NOT certify production superiority or universal safety.

---

## 1) Required files (MUST)
An MRP pack MUST contain:
- frames.jsonl
- manifest.json
- checksums.sha256

Optional (SHOULD):
- actions.jsonl (if actions are separated from frames)
- PACK_EXPLANATION.md
- PACK_SUMMARY.json (or summary.csv)

---

## 2) Minimal frame schema (MUST)
Each JSON object in frames.jsonl MUST include:
- step: integer >= 0
- policy: string (controller/baseline identifier)
- action_type: string in {ACCEPT, HOLD, REFUSE, DROP}
- reason_code: string (typed) OR "NONE" (required if ACCEPT)
- witness: object (MUST exist when action_type in {HOLD, REFUSE})

Minimal witness schema (MUST when HOLD/REFUSE):
- threshold_id: string
- witness_value: number (or string if domain requires)
- witness_unit: string (optional but recommended)

Recommended fields (SHOULD):
- ts_utc: RFC3339 timestamp
- state: object containing queue/latency/load proxies
- cfg: object containing seed/workload_id/symmetry_break flags

---

## 3) Manifest schema (MUST)
manifest.json MUST include:
- pack_version: string (e.g., "MRP_v1.0")
- generated_utc: RFC3339 timestamp
- generator: object with at least name and version (strings)
- experiment: object with at least:
  - seed (integer) OR "seed": null with explanation
  - policies: list[string]
  - workloads: list[object], each with an "id" string
  - metrics: list[string] (names only)

---

## 4) Integrity (MUST)
checksums.sha256 MUST list sha256 checksums for all files in the pack.
Verification must pass via:
- sha256sum -c checksums.sha256 (Linux)
- shasum -a 256 -c checksums.sha256 (macOS)

---

## 5) Conformance levels
### MRP-A (Baseline compliance)
MUST:
- Provide required files,
- Provide typed action_type and reason_code,
- Provide witness tuple for HOLD/REFUSE,
- Checksums verify.

### MRP-B (Identifiability compliance)
All MRP-A, plus MUST:
- Include at least two workloads:
  - one symmetric (symmetry_break = "none" or equivalent),
  - one symmetry-broken (symmetry_break = "hetero_mu" or equivalent),
- Include at least two policies enabling ablation comparison
  (e.g., gate-only vs coupled; or baseline vs governed controller).

---

## 6) Reviewer procedure (7 steps)
1) Verify checksums.
2) Inspect manifest: seed/workloads/policies/metrics present.
3) Parse frames: count action_type frequencies per policy.
4) For each HOLD/REFUSE: witness must exist (threshold_id, witness_value).
5) Check no silent refusal: DROP must be explicit and distinguishable from REFUSE/HOLD.
6) Compare workloads: symmetry-broken case should separate mechanisms more clearly than symmetric case.
7) Produce a short review note: pass/fail for MRP-A and MRP-B.

---

## 7) Minimal outputs (SHOULD)
A pack SHOULD include either:
- PACK_SUMMARY.json with key totals, or
- summary.csv with per-policy metric rows.

But a reviewer MUST be able to reconstruct totals from frames.jsonl alone.
