#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from __future__ import annotations
import argparse
import json
import os
import sys
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Iterable
import importlib.util

# ---------------- Config & Globals ----------------

DEFAULT_PLUGIN_DIRS: List[Path] = []
SEVERITY_ORDER = {"INFO": 0, "LOW": 0, "WARN": 1, "WARNING": 1, "MEDIUM": 1,
                  "ERROR": 2, "HIGH": 2, "CRITICAL": 3}

# ---------------- Utilities ----------------

def load_yaml(path: str | Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def dump_yaml(obj: Any, path: str | Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(obj, f, sort_keys=False, allow_unicode=True)

def dump_json(obj: Any, path: str | Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def severity_rank(s: Optional[str]) -> int:
    if not s:
        return 0
    return SEVERITY_ORDER.get(str(s).upper(), 0)

# ---------------- Plugin SPI ----------------

class PreprocessorBase:
    """
    Plugin hook: run(ctx) may append ctx.violations and/or set state.
    A 'violation' dict typically includes:
      policy_id, title, severity, description, file, span, target, type
    """
    def run(self, ctx: "Context") -> None:
        raise NotImplementedError

class PatternStrategyBase:
    """Optional: node-based matching if you use AST inputs."""
    name: str = ""
    def candidate_types(self) -> Optional[set]:  # pragma: no cover
        return None
    def matches(self, node: Dict[str, Any], ctx: "Context") -> bool:  # pragma: no cover
        raise NotImplementedError

class PreprocessorRegistry:
    _pre: List[PreprocessorBase] = []
    @classmethod
    def register(cls, pre_cls):
        cls._pre.append(pre_cls())
        return pre_cls
    @classmethod
    def all(cls) -> List[PreprocessorBase]:
        return cls._pre[:]

class PatternRegistry:
    _strategies: Dict[str, PatternStrategyBase] = {}
    @classmethod
    def register(cls, name: str):
        def deco(strategy_cls):
            inst = strategy_cls()
            inst.name = name
            cls._strategies[name] = inst
            return strategy_cls
        return deco
    @classmethod
    def get(cls, name: str) -> Optional[PatternStrategyBase]:
        return cls._strategies.get(name)

def _discover_plugin_dirs(cli_dirs: Optional[List[str]]) -> List[Path]:
    here = Path(__file__).resolve().parent
    dirs: List[Path] = [here / "policy_plugins"]
    if cli_dirs:
        dirs.extend(Path(p) for p in cli_dirs)
    env = os.environ.get("POLICY_PLUGIN_DIRS")
    if env:
        dirs.extend(Path(p) for p in env.split(os.pathsep) if p)
    return [d for d in dirs if d.exists() and d.is_dir()]

def load_plugins(cli_dirs: Optional[List[str]] = None) -> None:
    for d in _discover_plugin_dirs(cli_dirs):
        for py in sorted(d.glob("*.py")):
            name = f"policy_plugin_{py.stem}"
            if name in sys.modules:
                continue
            spec = importlib.util.spec_from_file_location(name, str(py))
            if not spec or not spec.loader:
                continue
            mod = importlib.util.module_from_spec(spec)
            # expose registries & base classes
            mod.__dict__.update({
                "PreprocessorRegistry": PreprocessorRegistry,
                "PatternRegistry": PatternRegistry,
                "PreprocessorBase": PreprocessorBase,
                "PatternStrategyBase": PatternStrategyBase,
            })
            sys.modules[name] = mod
            try:
                spec.loader.exec_module(mod)  # type: ignore[attr-defined]
            except Exception as e:
                print(f"[plugin-load] Skipped {py.name}: {e}", file=sys.stderr)

# ---------------- Engine Core ----------------

class Context:
    def __init__(
        self,
        repo_root: Path,
        policies: List[Dict[str, Any]],
        ast: Optional[Dict[str, Any]] = None,
        files: Optional[List[str]] = None,
    ):
        # Normalize severities early
        for p in policies:
            if isinstance(p.get("severity"), str):
                p["severity"] = p["severity"].upper()
        self.repo_root: Path = repo_root
        self.policies: List[Dict[str, Any]] = policies
        self.ast: Dict[str, Any] = ast or {}
        self.files: List[str] = files or []
        self.violations: List[Dict[str, Any]] = []
        # Arbitrary cross-pass state available to plugins
        self.state: Dict[str, Any] = {}

    # Utility for plugins: find the policy entry for a given tool/code
    def policy_for_tool(self, tool: str, code: Optional[str]) -> Optional[Dict[str, Any]]:
        tool = (tool or "").lower()
        code = (code or "").strip() if code else None

        # Exact match first
        if code:
            for p in self.policies:
                if (p.get("tool", "").lower() == tool) and (p.get("code") == code):
                    return p
        # Regex / wildcard
        if code:
            import re
            for p in self.policies:
                if p.get("tool", "").lower() == tool and p.get("match"):
                    try:
                        if re.fullmatch(str(p["match"]), code):
                            return p
                    except re.error:
                        continue
        # Tool-only default
        for p in self.policies:
            if p.get("tool", "").lower() == tool and not p.get("code") and not p.get("match"):
                return p
        return None

class PolicyEngine:
    def __init__(self, ctx: Context):
        self.ctx = ctx

    def run(self) -> List[Dict[str, Any]]:
        # Only preprocessors are required for this middleware (tool-driven).
        # Pattern strategies (AST) can be added via plugins if you need them.
        for pre in PreprocessorRegistry.all():
            try:
                pre.run(self.ctx)
            except Exception as e:
                print(f"[plugin] {pre.__class__.__name__} failed: {e}", file=sys.stderr)
        return self.ctx.violations

# ---------------- Feedback & Gating ----------------

def format_llm_feedback(violations: List[Dict[str, Any]], max_per_file: int = 8) -> str:
    if not violations:
        return "Static analysis found no issues.\n"

    # Group by file
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for v in violations:
        by_file.setdefault(v.get("file", "<unknown>"), []).append(v)

    lines: List[str] = []
    lines.append("### Static Analysis Findings")
    for fpath, vs in sorted(by_file.items()):
        lines.append(f"\n**{fpath}**")
        # stable/simple sort: severity desc, line asc
        def _sort_key(v):
            s = severity_rank(v.get("severity"))
            line = (((v.get("span") or {}).get("start") or {}).get("line")) or 0
            return (-s, line)
        vs_sorted = sorted(vs, key=_sort_key)[:max_per_file]
        for v in vs_sorted:
            pid = v.get("policy_id", "?")
            title = v.get("title", "")
            sev = v.get("severity", "INFO")
            span = v.get("span") or {}
            start = span.get("start") or {}
            l = start.get("line", "?")
            c = start.get("column", "?")
            desc = (v.get("description") or "").strip()
            if len(desc) > 180:
                desc = desc[:177] + "..."
            lines.append(f"- **{sev}** [{pid}] {title} @ L{l}:{c} — {desc}")
    lines.append("\n> Fix these before re-running tests.")
    return "\n".join(lines) + "\n"

def violations_block(violations: List[Dict[str, Any]]) -> bool:
    return any(severity_rank(v.get("severity")) >= severity_rank("ERROR") for v in violations)

# ---------------- CLI ----------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Static Analysis Policy Engine")
    p.add_argument("--policies", required=True, help="Path to Policies.yaml")
    p.add_argument("--ast", default=None, help="Optional AST JSON file (for AST-based plugins)")
    p.add_argument("--files", nargs="*", help="Files to analyze (typically the git diff)")

    p.add_argument("--plugin-dirs", nargs="*", default=None,
                   help="Additional plugin directories (overrides defaults/env)")

    p.add_argument("--repo-root", default=".", help="Repository root (for path normalization)")
    p.add_argument("--gate", action="store_true", help="Exit 1 if blocking violations exist")
    p.add_argument("--llm-feedback", default=None, help="Write compact markdown for LLM prompt")
    p.add_argument("--out-json", default="violations.json", help="Write violations JSON here")
    p.add_argument("--out-yaml", default="violations.yaml", help="Write violations YAML here")
    p.add_argument("--max-findings-per-file", type=int, default=8)
    return p.parse_args(argv)

def main(argv: Optional[List[str]] = None) -> int:
    try:
        args = parse_args(argv)
        load_plugins(args.plugin_dirs)

        policies = load_yaml(args.policies) or []
        if not isinstance(policies, list):
            raise ValueError("Policies.yaml must be a list of policy entries")

        ast_doc = None
        if args.ast and Path(args.ast).exists():
            with open(args.ast, "r", encoding="utf-8") as f:
                ast_doc = json.load(f)

        repo_root = Path(args.repo_root).resolve()
        files = args.files or []
        # Normalize file paths relative to repo root
        files = [str(Path(f).resolve()) for f in files if Path(f).exists()]

        ctx = Context(repo_root=repo_root, policies=policies, ast=ast_doc, files=files)
        engine = PolicyEngine(ctx)
        violations = engine.run()

        if args.out_json:
            dump_json(violations, args.out_json)
        if args.out_yaml:
            dump_yaml(violations, args.out_yaml)
        if args.llm_feedback:
            Path(args.llm_feedback).write_text(
                format_llm_feedback(violations, args.max_findings_per_file),
                encoding="utf-8"
            )

        if args.gate and violations_block(violations):
            return 1
        return 0

    except Exception as e:
        print(f"[policy-engine] error: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
