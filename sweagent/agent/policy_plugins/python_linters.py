"""
Plugin: Python linters (ruff + mypy)

Maps external tool findings to Policies.yaml entries, then emits normalized
violations into the engine context.

Policies examples:

- id: RUFF_F821
  title: Undefined name
  tool: ruff
  code: F821
  severity: ERROR
  primary_for_pattern: true
  description: Name is not defined.

- id: RUFF_F401
  title: Unused import
  tool: ruff
  code: F401
  severity: WARN
  description: Imported but unused.

- id: MYPY_ALL
  title: MyPy type error
  tool: mypy
  match: ".*"
  severity: ERROR
  primary_for_pattern: true
  description: Static type checker error.
"""
from __future__ import annotations
import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

# Provided by the engine loader:
# - PreprocessorRegistry
# - PreprocessorBase

def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def _run(cmd: List[str], cwd: Optional[str] = None) -> tuple[int, str, str]:
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err

def _span(start_line: int, start_col: int, end_line: Optional[int] = None, end_col: Optional[int] = None) -> Dict[str, Any]:
    return {
        "start": {"line": start_line, "column": start_col},
        "end": {"line": end_line or start_line, "column": end_col or start_col},
    }

def _emit(ctx, pol: Dict[str, Any], file_path: str, code: str, message: str, line: int, col: int):
    ctx.violations.append({
        "policy_id": pol.get("id"),
        "title": pol.get("title", f"{pol.get('tool','tool')} {code}"),
        "severity": str(pol.get("severity", "WARN")).upper(),
        "description": message,
        "target": code,
        "type": "external_tool",
        "file": file_path,
        "span": _span(line, col),
        "node_id": None,
    })

def _choose_policy(ctx, tool: str, code: Optional[str]) -> Optional[Dict[str, Any]]:
    return ctx.policy_for_tool(tool, code)

def _filter_files(files: List[str]) -> List[str]:
    # Only python files
    return [f for f in files if f.endswith(".py")]

@PreprocessorRegistry.register
class PythonLintersPreprocessor(PreprocessorBase):
    def run(self, ctx) -> None:
        files = _filter_files(ctx.files)
        if not files:
            return

        # -------- ruff --------
        if _which("ruff"):
            # ruff check --format json --exit-zero files...
            cmd = ["ruff", "check", "--format", "json", "--exit-zero", "--quiet", *files]
            code, out, err = _run(cmd, cwd=str(ctx.repo_root))
            if err.strip():
                # ruff prints warnings on stderr sometimes (unused settings, etc) — ignore
                pass
            try:
                results = json.loads(out or "[]")
            except json.JSONDecodeError:
                results = []
            for item in results:
                fpath = os.path.abspath(os.path.join(ctx.repo_root, item.get("filename", "")))
                rule = item.get("code") or ""
                msg = item.get("message") or ""
                loc = item.get("location") or {}
                line = int(loc.get("row", 1))
                col = int(loc.get("column", 1))
                pol = _choose_policy(ctx, "ruff", rule) or _choose_policy(ctx, "ruff", None)
                if pol:
                    _emit(ctx, pol, fpath, rule, msg, line, col)

        # -------- mypy --------
        if _which("mypy"):
            # mypy json output; ignore missing imports to reduce noise
            mypy_args = os.environ.get("MYPY_ARGS", "")
            base_cmd = ["mypy", "--hide-error-context", "--no-error-summary",
                        "--error-format=json", "--namespace-packages", "--ignore-missing-imports"]
            if mypy_args:
                base_cmd.extend(mypy_args.split())
            cmd = [*base_cmd, *files]
            code, out, err = _run(cmd, cwd=str(ctx.repo_root))
            # mypy places json on stdout; non-zero exit is expected when errors exist
            try:
                # could be "[]\n" or multiple JSON objects; handle list only
                data = json.loads(out or "[]")
                if isinstance(data, dict) and "messages" in data:
                    messages = data["messages"]
                elif isinstance(data, list):
                    messages = data
                else:
                    messages = []
            except json.JSONDecodeError:
                messages = []

            for m in messages:
                fpath = os.path.abspath(os.path.join(ctx.repo_root, m.get("path", "")))
                code = (m.get("code") or "").strip()
                msg = m.get("message", "")
                line = int(m.get("line", 1))
                col = int(m.get("column", 1))
                pol = _choose_policy(ctx, "mypy", code) or _choose_policy(ctx, "mypy", None) or _choose_policy(ctx, "mypy", "ANY")
                if pol:
                    _emit(ctx, pol, fpath, code, msg, line, col)

        # You can add more Python tools here (bandit, pyright, etc.).
