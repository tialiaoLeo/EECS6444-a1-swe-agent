#!/usr/bin/env python3
"""
Astropy JSON Issue Analyzer
Reads Astropy-style JSON files, extracts file locations from the JSON content,
and generates violations.json with per-file analysis results.
If analysis fails, retains original JSON data without violation info.
Uses Policies.yaml to determine severity and descriptions.
"""
from __future__ import annotations
import json
import os
import re
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional

# ============================================================================
# CONFIGURATION: Set your input file/directory locations here
# ============================================================================
input_files = [
    "/home/tianpei/IdeaProjects/SWE-agent/sweagent/agent/unrelated/out",  # Directory with JSON files
    # "/path/to/single/file.json",      # Or a single file
    # "issue1.json",                     # Multiple files
    # "issue2.json",
]

policies_file = "Policies.yaml"
output_file = "violations.json"
# ============================================================================


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


def find_json_files(input_paths: List[str]) -> List[Path]:
    """Find all JSON files from the provided paths (files or directories)."""
    json_files = []
    
    for input_path in input_paths:
        path = Path(input_path).resolve()
        
        if not path.exists():
            print(f"Warning: Path '{input_path}' does not exist, skipping")
            continue
        
        if path.is_file() and path.suffix == '.json':
            json_files.append(path)
        elif path.is_dir():
            # Recursively find all .json files in directory
            json_files.extend(path.rglob('*.json'))
    
    return sorted(set(json_files))


def parse_astropy_json(json_file: Path) -> Optional[Dict[str, Any]]:
    """Parse an Astropy-style JSON file and extract issue information."""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Validate required fields
        if not isinstance(data, dict):
            print(f"Warning: {json_file} does not contain a JSON object")
            return None
        
        return data
    
    except json.JSONDecodeError as e:
        print(f"Warning: Failed to parse {json_file}: {e}")
        return None
    except Exception as e:
        print(f"Warning: Error reading {json_file}: {e}")
        return None


def extract_file_locations_from_json(issue_data: Dict[str, Any]) -> List[str]:
    """Extract file locations/paths from the JSON data itself."""
    file_locations = []
    
    # Method 1: Extract from 'code' section if it exists
    code_section = issue_data.get("code", "")
    if code_section:
        # Look for file paths in [start of filename] and [end of filename] markers
        start_pattern = r'\[start of (.*?)\]'
        matches = re.findall(start_pattern, code_section)
        file_locations.extend(matches)
    
    # Method 2: Extract from patch in meta
    meta = issue_data.get("meta", {})
    patch = meta.get("patch", "")
    if patch:
        # Match file paths in diff headers
        diff_pattern = r'diff --git a/(.*?) b/'
        matches = re.findall(diff_pattern, patch)
        file_locations.extend(matches)
        
        # Also match --- and +++ headers
        header_pattern = r'(?:---|\+\+\+) [ab]/(.*?)(?:\s|$)'
        header_matches = re.findall(header_pattern, patch)
        file_locations.extend(header_matches)
    
    # Method 3: Extract from test_patch
    test_patch = meta.get("test_patch", "")
    if test_patch:
        diff_pattern = r'diff --git a/(.*?) b/'
        matches = re.findall(diff_pattern, test_patch)
        file_locations.extend(matches)
        
        header_pattern = r'(?:---|\+\+\+) [ab]/(.*?)(?:\s|$)'
        header_matches = re.findall(header_pattern, test_patch)
        file_locations.extend(header_matches)
    
    # Return unique file locations
    return sorted(set(f for f in file_locations if f))


def extract_bug_details_from_patch(patch: str, issue_text: str) -> tuple:
    """Extract specific bug details from patch and issue text.
    
    Returns
    -------
    tuple of (specific_message, evidence, line_num, column)
    """
    
    # Default values
    line_num = 1
    column = 1
    evidence = ""
    specific_message = ""
    
    if patch:
        # Parse the patch to find the actual bug location
        lines = patch.split('\n')
        for i, line in enumerate(lines):
            # Look for the line number in diff format (@@ -X,Y +A,B @@)
            if line.startswith('@@'):
                match = re.search(r'@@ -(\d+)', line)
                if match:
                    line_num = int(match.group(1))
            
            # Find lines being removed (the bug)
            elif line.startswith('-') and not line.startswith('---'):
                evidence = line[1:].strip()
                # Look ahead for the fix
                if i + 1 < len(lines) and lines[i + 1].startswith('+'):
                    fix_line = lines[i + 1][1:].strip()
                    # Create a specific message about what's wrong
                    if evidence and fix_line and evidence != fix_line:
                        specific_message = f"Incorrect code: '{evidence[:50]}' should be '{fix_line[:50]}'"
                        break
    
    # If we didn't find evidence from patch, try to extract from issue text
    if not evidence and issue_text:
        # Look for code blocks in issue text
        code_match = re.search(r'```python\s*\n(.+?)\n```', issue_text, re.DOTALL)
        if code_match:
            code_lines = code_match.group(1).strip().split('\n')
            evidence = code_lines[0][:100] if code_lines else ""
    
    return specific_message, evidence, line_num, column


def create_violation_from_issue(
    issue_data: Dict[str, Any],
    policies: List[Dict[str, Any]],
    source_file: str
) -> Dict[str, Any]:
    """Create a violation entry from issue data."""
    
    instance_id = issue_data.get("instance_id", "unknown")
    meta = issue_data.get("meta", {})
    
    # Extract information - handle missing fields gracefully
    repo = meta.get("repo", "unknown/unknown")
    base_commit = meta.get("base_commit", "unknown")
    version = meta.get("version", "unknown")
    patch = meta.get("patch", "")
    test_patch = meta.get("test_patch", "")
    
    # Get failing and passing tests
    fail_to_pass = meta.get("FAIL_TO_PASS", [])
    pass_to_pass = meta.get("PASS_TO_PASS", [])
    
    # Create issue description
    issue_text = issue_data.get("text", "No description provided")
    
    # Extract specific bug details from patch - MUST unpack all 4 values
    specific_message, evidence, line_num, column = extract_bug_details_from_patch(patch, issue_text)
    
    # Use instance_id as the code for policy matching
    code = instance_id
    
    # Determine default severity based on test failures
    default_severity = "ERROR" if fail_to_pass else "WARN"
    
    # Find matching policy by instance_id
    policy = find_policy(policies, "astropy", code)
    
    if policy:
        policy_id = policy.get("id", instance_id.upper().replace("-", "_"))
        title = policy.get("title", f"Issue: {instance_id}")
        severity = policy.get("severity", default_severity)
        description = policy.get("description", issue_text)
    else:
        # Fallback if no specific policy found
        policy_id = instance_id.upper().replace("-", "_")
        title = f"Issue: {instance_id}"
        severity = default_severity
        description = issue_text
    
    # Create a better message
    if specific_message:
        message = specific_message
    elif fail_to_pass:
        num_failing = len(fail_to_pass) if isinstance(fail_to_pass, list) else 1
        message = f"{num_failing} test(s) failing"
    else:
        # Extract first sentence from issue text as message
        first_sentence = issue_text.split('.')[0] if issue_text else "Issue detected"
        message = first_sentence[:100]
    
    # Get file locations from JSON
    modified_files = extract_file_locations_from_json(issue_data)
    
    # Better evidence
    if not evidence:
        evidence = f"Instance: {instance_id}, Repo: {repo}, Version: {version}"
    
    # Create suggested fix from patch analysis
    if modified_files and patch:
        # Try to extract the actual fix from the patch
        fix_lines = [line[1:].strip() for line in patch.split('\n') 
                     if line.startswith('+') and not line.startswith('+++')]
        if fix_lines:
            suggested_fix = f"Apply fix: {fix_lines[0][:80]}"
        else:
            suggested_fix = f"Review and apply patch modifying: {', '.join(modified_files[:2])}"
    elif modified_files:
        suggested_fix = f"Review and apply patch modifying: {', '.join(modified_files[:3])}"
        if len(modified_files) > 3:
            suggested_fix += f" and {len(modified_files) - 3} more file(s)"
    else:
        suggested_fix = "Review the issue description and patch for resolution steps"
    
    violation = {
        "id": policy_id,
        "title": title,
        "tool": "astropy",
        "code": code,
        "severity": severity,
        "message": message,
        "description": description[:500] + "..." if len(description) > 500 else description,
        "line": line_num,
        "column": column,
        "end_line": line_num,
        "end_column": column,
        "evidence": evidence,
        "suggested_fix": suggested_fix,
        "metadata": {
            "instance_id": instance_id,
            "repo": repo,
            "base_commit": base_commit,
            "version": version,
            "fail_to_pass_tests": fail_to_pass,
            "pass_to_pass_tests": pass_to_pass,
            "modified_files": modified_files,
            "source_file": source_file
        }
    }
    
    return violation


def generate_report(json_files: List[Path], policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate analysis report from JSON files."""
    
    report = []
    file_id = 0
    
    for json_file in json_files:
        print(f"Processing: {json_file.name}")
        
        issue_data = parse_astropy_json(json_file)
        
        # If we can't parse the JSON, retain original data without violations
        if not issue_data:
            report.append({
                "id": file_id,
                "file": str(json_file.name),
                "summary": {
                    "ERROR": 0,
                    "WARN": 0,
                    "INFO": 0,
                    "total": 0
                },
                "violations": [],
                "original_data": {
                    "source_file": str(json_file.name),
                    "parse_error": "Failed to parse JSON file",
                    "retained": True
                }
            })
            file_id += 1
            continue
        
        try:
            # Extract file locations from the JSON content itself
            file_locations = extract_file_locations_from_json(issue_data)
            
            # If no files found in JSON, use instance_id as identifier
            if not file_locations:
                instance_id = issue_data.get("instance_id", json_file.stem)
                file_locations = [f"issues/{instance_id}"]
            
            # Create violation
            violation = create_violation_from_issue(
                issue_data, 
                policies,
                str(json_file.name)
            )
            
            # Create ONE entry per JSON file (not per modified file)
            instance_id = issue_data.get("instance_id", json_file.stem)
            
            # Use the first file as the main file, or use instance_id
            main_file = file_locations[0] if file_locations else f"issues/{instance_id}"
            
            # Count by severity (just 1 violation per JSON file)
            error_count = 1 if violation["severity"] == "ERROR" else 0
            warn_count = 1 if violation["severity"] == "WARN" else 0
            info_count = 1 if violation["severity"] == "INFO" else 0
            
            file_report = {
                "id": file_id,
                "file": main_file,
                "summary": {
                    "ERROR": error_count,
                    "WARN": warn_count,
                    "INFO": info_count,
                    "total": 1
                },
                "violations": [violation],  # Just ONE violation per JSON
                "original_data": issue_data  # Retain original JSON data
            }
            
            report.append(file_report)
            file_id += 1
        
        except Exception as e:
            # If analysis fails, retain original data without violations
            print(f"  Warning: Analysis failed for {json_file.name}: {e}")
            report.append({
                "id": file_id,
                "file": str(json_file.name),
                "summary": {
                    "ERROR": 0,
                    "WARN": 0,
                    "INFO": 0,
                    "total": 0
                },
                "violations": [],
                "original_data": issue_data,  # Retain original JSON data
                "analysis_error": str(e)
            })
            file_id += 1
    
    return report


def main():
    # Load policies
    policies_path = Path(policies_file)
    policies = load_policies(policies_path)
    print(f"Loaded {len(policies)} policies from {policies_path}")
    
    # Find all JSON files from configured input_files
    print(f"\nSearching for JSON files in: {', '.join(input_files)}")
    json_files = find_json_files(input_files)
    print(f"Found {len(json_files)} JSON file(s)")
    
    if not json_files:
        print("No JSON files found to analyze")
        return 0
    
    # Generate report
    print("\nAnalyzing issues...")
    report = generate_report(json_files, policies)
    
    # Write output
    output_path = Path(output_file)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\nAnalysis complete! Report written to: {output_path}")
    
    # Print summary
    total_entries = len(report)
    total_violations = sum(f["summary"]["total"] for f in report)
    total_errors = sum(f["summary"]["ERROR"] for f in report)
    total_warns = sum(f["summary"]["WARN"] for f in report)
    failed_analyses = sum(1 for f in report if "analysis_error" in f or f["summary"]["total"] == 0)
    
    print(f"\nSummary:")
    print(f"  Total entries: {total_entries}")
    print(f"  Total violations: {total_violations}")
    print(f"  Errors: {total_errors}")
    print(f"  Warnings: {total_warns}")
    print(f"  Failed/Retained: {failed_analyses}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
