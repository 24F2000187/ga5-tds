import glob
import json

def main():
    by_call = {}
    for path in glob.glob("captured2/q9_*.json"):
        with open(path, encoding="utf-8") as fh:
            rec = json.load(fh)
        resp = rec.get("response", {})
        if isinstance(resp, dict) and resp.get("proposals"):
            for p in resp["proposals"]:
                by_call[p["callId"]] = p

    for path in glob.glob("captured2/q9_*.json"):
        with open(path, encoding="utf-8") as fh:
            rec = json.load(fh)
        req = rec.get("request", {})
        if req.get("operation") == "commit" and str(rec.get("client", "")).startswith("2a06"):
            for r in req.get("receipts", []):
                call = r["callId"]
                proposal = by_call.get(call)
                accepted = r.get("accepted")
                if proposal:
                    print(f"Dossier: {proposal['dossierId']} | Action: {proposal['action']} | Accepted: {accepted}")
                    print(f"  Target: {proposal.get('target')}")
                    print(f"  Payload: {proposal.get('payload')}")
                    print(f"  Evidence: {proposal.get('evidence')}")
                    print("-" * 50)

if __name__ == "__main__":
    main()
