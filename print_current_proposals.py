import json
import glob
from q9_mailroom import deterministic_decision, fingerprint_of, build_proposal

def main():
    # Load corpus from captured2
    caps = []
    for path in sorted(glob.glob("captured2/q9_*.json")):
        with open(path, encoding="utf-8") as fh:
            try:
                rec = json.load(fh)
            except Exception:
                continue
            if rec.get("request", {}).get("operation") == "propose":
                caps.append(rec)
    
    # Load corpus using pick_corpus logic
    # Wait, let's just write the pick_corpus logic directly to avoid import issues
    def pick_corpus(caps):
        best = None
        for rec in caps:
            req = rec["request"]
            if req.get("operation") != "propose":
                continue
            dossiers = req.get("dossiers") or []
            import collections
            parts = collections.Counter(d.get("partition") for d in dossiers)
            if parts.get("stable_core") != 64 or parts.get("fresh_audit") != 3:
                continue
            if best is None or rec.get("ts", 0) > best.get("ts", 0):
                best = rec
        return best

    corpus = pick_corpus(caps)
    if not corpus:
        print("No complete 67-dossier propose capture found.")
        return
    req = corpus["request"]
    dossiers = req["dossiers"]
    
    for d in dossiers:
        did = d["dossierId"]
        fp = fingerprint_of(d)
        fixed = deterministic_decision(d)
        if fixed:
            proposal = build_proposal(did, d, fp, fixed)
            print(f"Dossier: {did} | Action: {proposal['action']}")
            print(f"  Target: {proposal.get('target')}")
            print(f"  Payload: {proposal.get('payload')}")
            print(f"  Evidence: {proposal.get('evidence')}")
            print("-" * 50)
        else:
            print(f"Dossier: {did} | NO DETERMINISTIC DECISION")
            print("-" * 50)

if __name__ == "__main__":
    main()
