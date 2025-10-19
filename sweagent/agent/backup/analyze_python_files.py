#!/usr/bin/env python3
"""
Recursive Python File Analyzer
Scans all Python files in a directory tree and generates violations.json
with per-file analysis results from ruff and mypy.
Uses Policies.yaml to determine severity and descriptions.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import shutil
import subprocess
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_policies(policy_file: Path) -> List[Dict[str, Any]]:
    """Load and parse the Policies.yaml file."""
    if not policy_file.exists():
        print(f"Warning: Policies file '{policy_file}' not found, using defaults")
        return []
    
    try:
        with open(policy_file, 'r', encoding='utf-8') as f:
            policies = yaml.safe_load(f) or []
            # Normalize severities
            for p in policies:
                if isinstance(p.get("severity"), str):
                    p["severity"] = p["severity"].upper()
            return policies
    except Exception as e:
        print(f"Warning: Failed to load policies: {e}")
        return []


def find_policy(policies: List[Dict[str, Any]], tool: str, code: Optional[str]) -> Optional[Dict[str, Any]]:
    """Find the matching policy for a given tool and error code."""
    tool = (tool or "").lower()
    code = (code or "").strip() if code else None
    
    # Exact match first
    if code:
        for p in policies:
            if (p.get("tool", "").lower() == tool) and (p.get("code") == code):
                return p
    
    # Regex/wildcard match
    if code:
        for p in policies:
            if p.get("tool", "").lower() == tool and p.get("match"):
                try:
                    if re.fullmatch(str(p["match"]), code):
                        return p
                except re.error:
                    continue
    
    # Tool-only default
    for p in policies:
        if p.get("tool", "").lower() == tool and not p.get("code") and not p.get("match"):
            return p
    
    return None


def find_python_files(root_dir: Path, exclude_dirs: Optional[List[str]] = None) -> List[Path]:
    """Recursively find all .py files, excluding common virtual env directories."""
    if exclude_dirs is None:
        exclude_dirs = ['.venv', 'venv', '.pytest_cache', '__pycache__', 
                       '.git', 'node_modules', '.tox', 'build', 'dist']
    
    python_files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Remove excluded directories from the search
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        
        for filename in filenames:
            if filename.endswith('.py'):
                python_files.append(Path(dirpath) / filename)
    
    return sorted(python_files)


def run_tool(cmd: List[str], cwd: Optional[Path] = None) -> tuple[int, str, str]:
    """Run a command and capture output."""
    p = subprocess.Popen(
        cmd, 
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        text=True
    )
    out, err = p.communicate()
    return p.returncode, out, err


def get_source_line(file_path: str, line_number: int) -> str:
    """Extract the source code line as evidence."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if 0 < line_number <= len(lines):
                return lines[line_number - 1].rstrip()
    except Exception:
        pass
    return ""


def generate_suggested_fix(code: str, message: str, tool: str) -> str:
    """Generate a suggested fix based on the error code and message."""
    # Common fix suggestions based on error patterns
    fix_map = {
        "E999": "Check for syntax errors like missing colons, parentheses, or quotes.",
        "F821": "Define the variable before using it, or check for typos in the variable name.",
        "F401": "Remove the unused import or use the imported module.",
        "E501": "Break the line into multiple lines or use parentheses for implicit line continuation.",
        "F841": "Either use the variable in your code or remove the assignment.",
        "E711": "Use 'is None' or 'is not None' instead of '== None' or '!= None'.",
        "E712": "Use 'if condition:' instead of 'if condition == True:'.",
    }
    
    # Check for specific patterns in message
    if "expected ':'" in message.lower():
        return "Add a colon ':' at the end of the function definition line."
    elif "not defined" in message.lower():
        return "Define the variable or import the required module before using it."
    elif "syntax error" in message.lower():
        return "Fix the syntax error by checking for missing colons, parentheses, or proper indentation."
    elif tool == "mypy" and "syntax" in code.lower():
        return "Fix the syntax error identified by the parser."
    
    # Use code-based suggestions
    return fix_map.get(code, f"Review and fix the {tool} violation: {message}")


def get_ruff_command(files: List[Path]) -> List[str]:
    """Build ruff command with correct flags for the installed version."""
    # Use --output-format for newer ruff versions
    return ["ruff", "check", "--output-format", "json"] + [str(f) for f in files]


def analyze_with_ruff(files: List[Path], repo_root: Path, policies: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Run ruff on files and return violations grouped by file."""
    if not shutil.which("ruff"):
        print("Warning: ruff not found, skipping ruff analysis")
        return {}
    
    violations_by_file: Dict[str, List[Dict[str, Any]]] = {}
    
    if not files:
        return violations_by_file
    
    cmd = get_ruff_command(files)
    
    print(f"[DEBUG] Running ruff command: {' '.join(cmd)}")
    print(f"[DEBUG] Working directory: {repo_root}")
    
    # Don't pass cwd, use absolute paths instead
    code, out, err = run_tool(cmd, cwd=None)
    
    print(f"[DEBUG] Ruff exit code: {code}")
    print(f"[DEBUG] Ruff stdout length: {len(out)}")
    if out:
        print(f"[DEBUG] Ruff stdout preview: {out[:1000]}")
    else:
        print("[DEBUG] Ruff stdout: empty")
    if err:
        print(f"[DEBUG] Ruff stderr preview: {err[:500]}")
    
    # Ruff outputs JSON to stdout
    if not out or out.strip() == "":
        print("[DEBUG] No output from ruff")
        return violations_by_file
    
    try:
        results = json.loads(out)
        print(f"[DEBUG] Ruff parsed {len(results)} violations")
    except json.JSONDecodeError as e:
        print(f"[DEBUG] JSON decode error: {e}")
        print(f"[DEBUG] Raw output: {out}")
        results = []
    
    for item in results:
        filename = item.get("filename", "")
        fpath = filename if os.path.isabs(filename) else str(Path(repo_root) / filename)
        
        rule_code = item.get("code", "")
        msg = item.get("message", "")
        loc = item.get("location", {})
        line = int(loc.get("row", 1))
        col = int(loc.get("column", 1))
        end_loc = item.get("end_location", {})
        end_line = int(end_loc.get("row", line))
        end_col = int(end_loc.get("column", col))
        
        # Map invalid-syntax to E999 for policy matching
        if rule_code == "invalid-syntax":
            policy_code = "E999"
        else:
            policy_code = rule_code
        
        # Find matching policy
        policy = find_policy(policies, "ruff", policy_code)
        
        if policy:
            policy_id = policy.get("id", f"RUFF_{policy_code}")
            title = policy.get("title", f"Ruff: {rule_code}")
            severity = policy.get("severity", "WARN")
            description = policy.get("description", msg)
        else:
            # Default if no policy found
            policy_id = f"RUFF_{rule_code}"
            title = f"Ruff: {rule_code}"
            severity = "ERROR" if rule_code.startswith("E") or rule_code.startswith("F") or rule_code == "invalid-syntax" else "WARN"
            description = msg
        
        # Get the source line as evidence
        evidence = get_source_line(fpath, line)
        
        # Generate suggested fix
        suggested_fix = generate_suggested_fix(rule_code, msg, "ruff")
        
        violation = {
            "id": policy_id,
            "title": title,
            "tool": "ruff",
            "code": rule_code,
            "severity": severity,
            "message": msg,
            "description": description,
            "line": line,
            "column": col,
            "end_line": end_line,
            "end_column": end_col,
            "evidence": evidence,
            "suggested_fix": suggested_fix
        }
        
        violations_by_file.setdefault(fpath, []).append(violation)
    
    return violations_by_file


def analyze_with_mypy(files: List[Path], repo_root: Path, policies: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Run mypy on files and return violations grouped by file."""
    if not shutil.which("mypy"):
        print("Warning: mypy not found, skipping mypy analysis")
        return {}
    
    violations_by_file: Dict[str, List[Dict[str, Any]]] = {}
    
    if not files:
        return violations_by_file
    
    cmd = [
        "mypy",
        "--hide-error-context",
        "--no-error-summary",
        "--error-format=json",
        "--ignore-missing-imports",
        "--namespace-packages"
    ] + [str(f) for f in files]
    
    code, out, err = run_tool(cmd, cwd=repo_root)
    
    try:
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
        path = m.get("path", "")
        fpath = str(Path(repo_root) / path)
        
        error_code = (m.get("code") or "").strip() or "syntax"
        msg = m.get("message", "")
        line = int(m.get("line", 1))
        col = int(m.get("column", 1))
        
        # Find matching policy
        policy = find_policy(policies, "mypy", error_code)
        
        if policy:
            policy_id = policy.get("id", "MYPY_ALL")
            title = policy.get("title", "MyPy type error")
            severity = policy.get("severity", "ERROR")
            description = policy.get("description", msg)
        else:
            # Default if no policy found
            policy_id = "MYPY_ALL"
            title = "MyPy type error"
            severity = "ERROR"
            description = msg
        
        # Get the source line as evidence
        evidence = get_source_line(fpath, line)
        
        # Generate suggested fix
        suggested_fix = generate_suggested_fix(error_code, msg, "mypy")
        
        violation = {
            "id": policy_id,
            "title": title,
            "tool": "mypy",
            "code": error_code,
            "severity": severity,
            "message": msg,
            "description": description,
            "line": line,
            "column": col,
            "end_line": line,
            "end_column": col,
            "evidence": evidence,
            "suggested_fix": suggested_fix
        }
        
        violations_by_file.setdefault(fpath, []).append(violation)
    
    return violations_by_file


def generate_report(files: List[Path], repo_root: Path, policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate analysis report for all files."""
    # Run both tools
    ruff_violations = analyze_with_ruff(files, repo_root, policies)
    mypy_violations = analyze_with_mypy(files, repo_root, policies)
    
    # Merge violations by file
    all_files = set(str(f.resolve()) for f in files)
    all_files.update(ruff_violations.keys())
    all_files.update(mypy_violations.keys())
    
    report = []
    file_id = 0
    
    for fpath in sorted(all_files):
        violations = []
        violations.extend(ruff_violations.get(fpath, []))
        violations.extend(mypy_violations.get(fpath, []))
        
        # Count by severity
        error_count = sum(1 for v in violations if v["severity"] == "ERROR")
        warn_count = sum(1 for v in violations if v["severity"] == "WARN")
        info_count = sum(1 for v in violations if v["severity"] == "INFO")
        
        # Determine relative file path
        try:
            rel_path = str(Path(fpath).relative_to(repo_root))
        except ValueError:
            rel_path = fpath
        
        file_report = {
            "id": file_id,
            "file": rel_path,
            "summary": {
                "ERROR": error_count,
                "WARN": warn_count,
                "INFO": info_count,
                "total": len(violations)
            },
            "violations": violations
        }
        
        report.append(file_report)
        file_id += 1
    
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Recursively analyze Python files and generate violations.json",
        epilog="Example: python analyze_python_files.py /path/to/testbed"
    )
    parser.add_argument(
        "testbed_dir",
        help="Directory containing Python files to analyze (testbed directory)"
    )
    parser.add_argument(
        "--policies",
        "-p",
        default="Policies.yaml",
        help="Path to Policies.yaml file (default: Policies.yaml in current dir)"
    )
    parser.add_argument(
        "--output",
        "-o",
        default="violations.json",
        help="Output JSON file (default: violations.json)"
    )
    parser.add_argument(
        "--exclude",
        nargs="*",
        default=None,
        help="Additional directories to exclude from scanning"
    )
    
    args = parser.parse_args()
    
    testbed_root = Path(args.testbed_dir).resolve()
    if not testbed_root.exists():
        print(f"Error: Testbed directory '{args.testbed_dir}' does not exist")
        return 1
    
    if not testbed_root.is_dir():
        print(f"Error: '{args.testbed_dir}' is not a directory")
        return 1
    
    # Load policies
    policies_path = Path(args.policies)
    policies = load_policies(policies_path)
    print(f"Loaded {len(policies)} policies from {policies_path}")
    
    print(f"Scanning Python files in testbed: {testbed_root}")
    
    # Find all Python files
    python_files = find_python_files(testbed_root, exclude_dirs=args.exclude)
    print(f"Found {len(python_files)} Python file(s)")
    
    if not python_files:
        print("No Python files found to analyze")
        return 0
    
    # Generate report
    print("Running analysis...")
    report = generate_report(python_files, testbed_root, policies)
    
    # Write output
    output_path = Path(args.output)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\nAnalysis complete! Report written to: {output_path}")
    
    # Print summary
    total_files = len(report)
    total_violations = sum(f["summary"]["total"] for f in report)
    total_errors = sum(f["summary"]["ERROR"] for f in report)
    total_warns = sum(f["summary"]["WARN"] for f in report)
    
    print(f"\nSummary:")
    print(f"  Files analyzed: {total_files}")
    print(f"  Total violations: {total_violations}")
    print(f"  Errors: {total_errors}")
    print(f"  Warnings: {total_warns}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
