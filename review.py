"""CLI / CI gate: python review.py file.c [--fail-above 0.6]  (splits top-level functions naively by braces)."""
import argparse, json, re, sys
import joblib
from vulnlens.rules import review

FUNC = re.compile(r"^[A-Za-z_][\w\s\*]*\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{", re.M)


def functions(src: str):
    for m in FUNC.finditer(src):
        depth, i = 0, m.end() - 1
        while i < len(src):
            depth += {"{": 1, "}": -1}.get(src[i], 0)
            if depth == 0:
                yield m.group(1), src.count("\n", 0, m.start()) + 1, src[m.start():i + 1]
                break
            i += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path"); ap.add_argument("--fail-above", type=float, default=None); ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    model = joblib.load("models/vulnlens.joblib")
    src = open(a.path, encoding="utf-8", errors="replace").read()
    rows = []
    for name, line, body in functions(src):
        p = float(model.predict_proba([body])[0])
        rows.append({"function": name, "line": line, "risk": round(p, 3),
                     "findings": [dict(f.to_dict(), line=f.line + line - 1) for f in review(body)]})
    rows.sort(key=lambda r: -r["risk"])
    if a.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            print(f"{r['risk']:.2f}  {r['function']} (line {r['line']})")
            for f in r["findings"]:
                print(f"      L{f['line']} {f['cwe']} {f['title']}")
    if a.fail_above is not None and any(r["risk"] > a.fail_above for r in rows):
        sys.exit(1)


if __name__ == "__main__":
    main()
