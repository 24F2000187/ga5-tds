import glob
import json
import os

def main():
    for d in glob.glob("captured*"):
        if not os.path.isdir(d):
            continue
        counts = {}
        for path in glob.glob(d + "/**/*.json", recursive=True):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    rec = json.load(fh)
            except Exception:
                continue
            req = rec.get("request", {})
            if req.get("operation") == "commit":
                for r in req.get("receipts", []):
                    if r.get("accepted"):
                        counts[r["action"]] = counts.get(r["action"], 0) + 1
        if counts:
            print(f"Directory {d}: {counts}")
        else:
            print(f"Directory {d}: no accepted receipts found")

if __name__ == "__main__":
    main()
