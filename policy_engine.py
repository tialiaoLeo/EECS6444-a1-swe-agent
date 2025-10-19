#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

SEVERITY_ORDER = ["INFO", "LOW", "WARN", "MEDIUM", "HIGH", "ERROR", "CRITICAL"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}

def _e(msg: str) -> None:
    sys.stderr.write(msg.rstrip() + "\n")

def relpath(path: Union[str, Path], root: Union[str, Path]) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve()))
    except Exception:
        return str(path)

def load_policies(p: Path) -> List[Dict[str, Any]]:
    if not p.exists():
        _e(f"[policy-engine] policy file not found: {p}")
        return []  # run with default severities
    try:
        import yaml  # type: ignore
        with p.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        _e(f"[policy-engine] loaded YAML policies: {p}")
    except Exception as ex_yaml:
        try:
            with p.open("r", encoding="utf-8") as f:
                data = json.load(f)
            _e(f"[policy-engine] loaded JSON policies: {p}")
        except Exception as ex_json:
            _e(f"[policy-engine] failed to parse policies: {ex_yaml} / {ex_json}")
            return []
    if not isinstance(data, list):
        _e("[policy-engine] policies must be a list; proceeding with empty set.")
        return []
    out = []
    for q in data:
        if not isinstance(q, dict):
            continue
        q = dict(q)
        q.setdefault("severity", "WARN")
        q["severity"] = str(q["severity"]).upper()
        out.append(q)
    return out

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def make_fp(path: str, code: str, message: str, line: int) -> str:
    return sha256(f"{path}:{line}:{code}:{message}")

def try_json_or_ndjson(s: str):
    s = s.strip()
    if not s:
        return []
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        items = []
        for ln in s.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                items.append(json.loads(ln))
            except Exception:
                pass
        return items

def run(args: List[str], expect_json=False):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    data = None
    if expect_json:
        try:
            data = try_json_or_ndjson(p.stdout)
        except Exception:
            data = None
    return p.returncode, data, p.stdout, p.stderr

@dataclasses.dataclass
class Finding:
    policy_id: str
    tool: str
    code: str
    severity: str
    message: str
    path: str
    line: int
    column: int = 0
    snippet: Optional[str] = None
    fingerprint: Optional[str] = None
    extra: Dict[str, Any] = dataclasses.field(default_factory=dict)
    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

# ---------------- tool adapters (always run if installed) ----------------

def run_ruff(files: List[str], repo: str) -> List[Dict[str, Any]]:
    import shutil
    if not shutil.which("ruff"):
        _e("[policy-engine] ruff not found; skipping.")
        return []
    cmd = ["ruff","check","--format","json","--force-exclude","--quiet",*files]
    code, data, out, err = run(cmd, expect_json=True)
    if data is None:
        cmd = ["ruff","check","--output-format","json","--force-exclude","--quiet",*files]
        code, data, out, err = run(cmd, expect_json=True)
    if data is None:
        _e("[policy-engine] ruff produced non-JSON; skipping.")
        return []
    diags = data["diagnostics"] if isinstance(data, dict) and "diagnostics" in data else data
    res = []
    for d in diags or []:
        filename = d.get("filename") or d.get("file") or ""
        loc = d.get("location") or {}
        row = int(loc.get("row") or loc.get("line") or d.get("line") or 1)
        col = int(loc.get("column") or d.get("column") or 0)
        code_s = str(d.get("code") or d.get("rule") or "")
        message = d.get("message") or d.get("description") or ""
        path_rel = relpath(filename, repo)
        snippet = None
        try:
            text = Path(filename).read_text(encoding="utf-8", errors="replace").splitlines()
            if 1 <= row <= len(text):
                snippet = text[row-1]
        except Exception:
            pass
        res.append({"tool":"ruff","code":code_s,"message":message,"path":path_rel,"line":row,"column":col,"snippet":snippet,"raw":d})
    _e(f"[policy-engine] ruff findings: {len(res)}")
    return res

def run_mypy(files: List[str], repo: str) -> List[Dict[str, Any]]:
    import shutil
    if not shutil.which("mypy"):
        _e("[policy-engine] mypy not found; skipping.")
        return []
    code, data, out, err = run(["mypy","--output","json",*files], expect_json=True)
    if data is None:
        code, _, out, err = run(["mypy","--no-error-summary","--hide-error-context","--show-column-numbers","--show-error-code",*files])
        pat = re.compile(r"^(?P<file>.*?):(?P<line>\d+):(?P<col>\d+): (?:error|note): (?P<msg>.*?)(?: \[(?P<code>[-_a-zA-Z0-9]+)\])?$")
        items=[]
        for ln in out.splitlines():
            m = pat.match(ln.strip())
            if not m: continue
            items.append({"tool":"mypy","code":m.group("code") or "mypy","message":m.group("msg"),
                          "path":relpath(m.group("file"),repo),"line":int(m.group("line")),"column":int(m.group("col"))})
        _e(f"[policy-engine] mypy findings: {len(items)} (text mode)")
        return items
    seq = data if isinstance(data, list) else data.get("errors", [])
    items=[]
    for e in seq or []:
        items.append({"tool":"mypy","code":(e.get("code") or "mypy"),"message":e.get("message") or "",
                      "path":relpath(e.get("path") or e.get("filename") or "", repo),
                      "line":int(e.get("line") or 1),"column":int(e.get("column") or 0),"raw":e})
    _e(f"[policy-engine] mypy findings: {len(items)}")
    return items

def run_bandit(files: List[str], repo: str) -> List[Dict[str, Any]]:
    import shutil
    if not shutil.which("bandit"):
        _e("[policy-engine] bandit not found; skipping.")
        return []
    dirs = sorted({str(Path(f).parent) for f in files})
    if not dirs:
        return []
    cmd = ["bandit","-q","-f","json"]
    for d in dirs: cmd.extend(["-r", d])
    code, data, out, err = run(cmd, expect_json=True)
    if not isinstance(data, dict):
        _e("[policy-engine] bandit non-JSON output; skipping.")
        return []
    issues = data.get("results") or data.get("issues") or []
    res=[]
    for it in issues:
        fname = it.get("filename") or ""
        res.append({"tool":"bandit","code":str(it.get("test_id") or it.get("test_name") or "bandit"),
                    "message":it.get("issue_text") or it.get("message") or "",
                    "path":relpath(fname,repo),"line":int(it.get("line_number") or it.get("line") or 1),
                    "column":0,"raw":it})
    _e(f"[policy-engine] bandit findings: {len(res)}")
    return res

def run_detect_secrets(files: List[str], repo: str) -> List[Dict[str, Any]]:
    import shutil
    if not shutil.which("detect-secrets"):
        _e("[policy-engine] detect-secrets not found; skipping.")
        return []
    dirs = sorted({str(Path(f).parent) for f in files})
    if not dirs:
        return []
    cmd = ["detect-secrets","scan","--json","--force-use-all-plugins",*dirs]
    code, data, out, err = run(cmd, expect_json=True)
    if not isinstance(data, dict):
        _e("[policy-engine] detect-secrets non-JSON output; skipping.")
        return []
    res=[]
    for fname, items in (data.get("results") or {}).items():
        for it in items:
            typ = it.get("type") or it.get("name") or "secret"
            res.append({"tool":"detect-secrets","code":str(typ),
                        "message":f"Potential secret detected ({typ})",
                        "path":relpath(fname,repo),"line":int(it.get("line_number") or 1),
                        "column":0,"raw":it})
    _e(f"[policy-engine] detect-secrets findings: {len(res)}")
    return res

# ---------------- policy mapping / output ----------------

def assign_sev(tool: str, code: str) -> str:
    if tool == "ruff":
        c = (code or "").upper()
        if c.startswith("F"): return "ERROR"
        if c.startswith("E"): return "WARN"
        return "INFO"
    if tool == "mypy": return "ERROR"
    if tool in {"bandit","detect-secrets"}: return "HIGH"
    return "WARN"

@dataclasses.dataclass
class FindingRaw:
    tool:str; code:str; message:str; path:str; line:int; column:int; snippet:Optional[str]; raw:Any

def map_findings(raw: List[Dict[str, Any]], policies: List[Dict[str, Any]]) -> List[Finding]:
    # Optional policy-based overrides (by tool+code or regex "match" on message)
    by_key: Dict[Tuple[str,str], List[Dict[str, Any]]] = {}
    regex_pols: List[Dict[str, Any]] = []
    for p in policies:
        tool = str(p.get("tool","")).strip()
        code = str(p.get("code") or "").strip()
        if tool and code:
            by_key.setdefault((tool, code), []).append(p)
        elif p.get("match"):
            try: p["_regex"] = re.compile(p["match"])
            except Exception: p["_regex"] = re.compile(re.escape(str(p["match"])))
            regex_pols.append(p)

    out: List[Finding] = []
    for rf in raw:
        R = FindingRaw(
            tool=str(rf.get("tool","")),
            code=str(rf.get("code") or ""),
            message=rf.get("message") or "",
            path=rf.get("path") or "",
            line=int(rf.get("line") or 1),
            column=int(rf.get("column") or 0),
            snippet=rf.get("snippet"),
            raw=rf.get("raw"),
        )
        used_policy = None
        for pol in by_key.get((R.tool, R.code), []):
            used_policy = pol; break
        if used_policy is None:
            for pol in regex_pols:
                rgx = pol.get("_regex")
                if rgx and rgx.search(R.message):
                    used_policy = pol; break

        severity = assign_sev(R.tool, R.code)
        pid = f"{R.tool}:{R.code or 'GEN'}"
        if used_policy:
            custom = str(used_policy.get("severity","")).upper()
            if custom in SEVERITY_RANK:
                severity = custom
            pid = str(used_policy.get("id") or pid)

        out.append(Finding(
            policy_id=pid, tool=R.tool, code=R.code or "GEN", severity=severity,
            message=R.message, path=R.path, line=R.line, column=R.column,
            snippet=R.snippet, fingerprint=make_fp(R.path, R.code or pid, R.message, R.line),
            extra=dict(policy=used_policy, raw=R.raw)
        ))
    return out

def write_yaml(path: str, data: Any) -> None:
    try:
        import yaml  # type: ignore
        from yaml import safe_dump  # type: ignore
        Path(path).write_text(safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
        _e(f"[policy-engine] wrote YAML: {path}")
    except Exception as e:
        _e(f"[policy-engine] YAML dump unavailable ({e}); writing a minimal YAML note instead.")
        # Minimal fallback so the file exists (helps agent loops that expect the path)
        content = "# YAML unavailable (missing PyYAML?). See violations.json for full output.\n"
        try:
            Path(path).write_text(content, encoding="utf-8")
        except Exception as e2:
            _e(f"[policy-engine] failed to write YAML fallback: {e2}")

def to_sarif(findings: List[Finding]) -> Dict[str, Any]:
    rules = {}
    results = []
    for f in findings:
        rid = f.policy_id
        rules.setdefault(rid, {"id": rid, "shortDescription": {"text": f.tool},
                               "properties": {"security-severity": str(SEVERITY_RANK.get(f.severity,1))}})
        results.append({"ruleId": rid, "message": {"text": f.message},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path.replace(os.sep,"/")},
                                                            "region": {"startLine": f.line, "startColumn": f.column or 1}}}],
                        "fingerprints": {"primaryLocationLineHash": f.fingerprint or ""}})
    return {"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json",
            "runs":[{"tool":{"driver":{"name":"policy-engine","rules":list(rules.values())}},"results":results}]}

def gate_fail(findings: List[Finding], threshold: str) -> bool:
    thr = threshold.upper()
    if thr not in SEVERITY_RANK:
        thr = "ERROR"
    return any(SEVERITY_RANK.get(f.severity,0) >= SEVERITY_RANK[thr] for f in findings)

def format_feedback(findings: List[Finding], max_per_file: int = 15) -> str:
    by_file: Dict[str, List[Finding]] = {}
    for f in findings: by_file.setdefault(f.path, []).append(f)
    lines = ["# Static Analysis Findings (summary)\n"]
    for path, items in sorted(by_file.items()):
        items = sorted(items, key=lambda x: (-SEVERITY_RANK.get(x.severity,0), x.line))
        if max_per_file: items = items[:max_per_file]
        lines.append(f"## {path}")
        for f in items:
            lines.append(f"- [{f.severity}] {f.policy_id} L{f.line}: {f.message}")
        lines.append("")
    return "\n".join(lines)

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="SWE-bench-friendly static analysis (no AST)")
    ap.add_argument("--policies", default="Policies.yaml")
    ap.add_argument("--files", nargs="*", default=[])
    ap.add_argument("--repo-root", default=os.getcwd())
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--gate-min-severity", default="ERROR")
    ap.add_argument("--out-json", default="violations.json")
    ap.add_argument("--out-yaml", default="violations.yaml")
    ap.add_argument("--out-sarif", default="")
    ap.add_argument("--llm-feedback", default=".middleware_feedback.md")
    ap.add_argument("--max-findings-per-file", type=int, default=15)
    args = ap.parse_args(argv)

    _e(f"[policy-engine] repo-root={args.repo-root} files={len(args.files)} gate={args.gate} policies={args.policies}")

    repo = args.repo_root
    policies = load_policies(Path(args.policies))

    files = [f for f in args.files if f.endswith(".py") and Path(f).exists()]
    if not files:
        _e("[policy-engine] no files to analyze (empty set).")

    # Always run installed tools (even if policies are empty); map severities afterward.
    raw: List[Dict[str, Any]] = []
    if files:
        raw.extend(run_ruff(files, repo))
        raw.extend(run_mypy(files, repo))
        raw.extend(run_bandit(files, repo))
        raw.extend(run_detect_secrets(files, repo))

    findings = map_findings(raw, policies)

    # fingerprint & snippet enrichment
    for f in findings:
        if not f.fingerprint:
            f.fingerprint = make_fp(f.path, f.code or f.policy_id, f.message, f.line)

    data = [x.to_dict() for x in findings]
    try:
        Path(args.out_json).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        _e(f"[policy-engine] wrote JSON: {args.out_json} ({len(findings)} findings)")
    except Exception as e:
        _e(f"[policy-engine] failed to write JSON: {e}")

    write_yaml(args.out_yaml, data)

    if args.out_sarif:
        try:
            Path(args.out_sarif).write_text(json.dumps(to_sarif(findings), indent=2), encoding="utf-8")
            _e(f"[policy-engine] wrote SARIF: {args.out_sarif}")
        except Exception as e:
            _e(f"[policy-engine] failed to write SARIF: {e}")

    if args.llm_feedback:
        try:
            Path(args.llm_feedback).write_text(format_feedback(findings, args.max_findings_per_file), encoding="utf-8")
            _e(f"[policy-engine] wrote feedback: {args.llm_feedback}")
        except Exception as e:
            _e(f"[policy-engine] failed to write feedback: {e}")

    if args.gate and gate_fail(findings, args.gate_min_severity):
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())