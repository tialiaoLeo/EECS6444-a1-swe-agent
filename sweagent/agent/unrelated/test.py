#!/usr/bin/env python3
# pip install datasets
import argparse, json, os, re
from datasets import load_dataset

VARIANTS = {
    "oracle": "princeton-nlp/SWE-bench_Lite_oracle",
    "bm25_13K": "princeton-nlp/SWE-bench_Lite_bm25_13K",
    "bm25_27K": "princeton-nlp/SWE-bench_Lite_bm25_27K",
}

ISSUE_RE = re.compile(r"<issue>(.*?)</issue>", re.S)
FILE_RE  = re.compile(r"\[start of ([^\]]+)\]\s*(.*?)(?=\n\[start of |\Z)", re.S)

META_KEYS = [
    "instance_id", "repo", "base_commit", "patch", "test_patch",
    "created_at", "version", "FAIL_TO_PASS", "PASS_TO_PASS"
]

def find_row(instance_id: str, variant_key: str):
    ds_name = VARIANTS[variant_key]
    for split in ("dev", "test"):
        ds = load_dataset(ds_name, split=split)
        for r in ds:
            if r.get("instance_id") == instance_id:
                r["_split"] = split
                return r
    raise SystemExit(f"[not found] {instance_id} in {ds_name} dev/test")

def parse_prompt(text: str):
    # Extract <issue>…</issue> and the embedded files
    m = ISSUE_RE.search(text)
    issue = m.group(1).strip() if m else ""
    files = [{"path": p.strip(), "content": c} for p, c in FILE_RE.findall(text)]
    return {"issue": issue, "files": files}

def dump_one(row: dict, out_dir: str, variant_key: str, mode: str):
    os.makedirs(out_dir, exist_ok=True)
    meta = {k: row.get(k) for k in META_KEYS if k in row}
    base = {
        "instance_id": row["instance_id"],
        "variant": variant_key,
        "split": row["_split"],
        "meta": meta,
    }

    if mode in ("raw", "both"):
        obj = {**base, "text": row["text"]}
        with open(os.path.join(out_dir, f"{row['instance_id']}.raw.json"), "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)

    if mode in ("parsed", "both"):
        parsed = parse_prompt(row["text"])
        obj = {**base, **parsed}
        with open(os.path.join(out_dir, f"{row['instance_id']}.parsed.json"), "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)

def main():
    ap = argparse.ArgumentParser(description="Dump SWE-bench Lite prompts to JSON")
    ap.add_argument("instance_ids", nargs="+", help="e.g. astropy__astropy-12907")
    ap.add_argument("--variant", choices=VARIANTS.keys(), default="oracle",
                    help="oracle | bm25_13K | bm25_27K")
    ap.add_argument("--mode", choices=["raw", "parsed", "both"], default="raw",
                    help="raw=text blob; parsed=issue+files; both=write both JSONs")
    ap.add_argument("--out", default="lite_json", help="output directory")
    args = ap.parse_args()

    for iid in args.instance_ids:
        row = find_row(iid, args.variant)
        dump_one(row, args.out, args.variant, args.mode)
        print(f"[ok] {iid} -> {args.out}")

if __name__ == "__main__":
    main()
