"""Run web/vulnlens.js in Node on real test functions and compare with the Python scorer."""
import json, os, shutil, subprocess
import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
MODEL = os.path.join(ROOT, "web/model.json")


@pytest.mark.skipif(not (shutil.which("node") and os.path.exists(MODEL)), reason="needs node + trained web model")
def test_js_scores_match_python():
    import pandas as pd
    from vulnlens.model import web_score
    from vulnlens.rules import review
    te = pd.read_parquet(os.path.join(ROOT, "data/test.parquet")).sample(200, random_state=1)
    codes = te.func.tolist()
    js = r"""
const V=require(process.argv[1]);const fs=require('fs');
const M=JSON.parse(fs.readFileSync(process.argv[2]));const codes=JSON.parse(fs.readFileSync(0,'utf8'));
console.log(JSON.stringify(codes.map(c=>[V.score(M,c).p,V.review(c).length])));"""
    out = subprocess.run(["node", "-e", js, os.path.join(ROOT, "web/vulnlens.js"), MODEL],
                         input=json.dumps(codes), capture_output=True, text=True, check=True).stdout
    res = json.loads(out)
    M = json.load(open(MODEL))
    bad = [i for i, c in enumerate(codes) if abs(res[i][0] - web_score(M, c)) > 1e-6]
    assert len(bad) <= 2, f"{len(bad)} mismatches"
    rule_bad = [i for i, c in enumerate(codes) if res[i][1] != len(review(c))]
    assert len(rule_bad) <= 2
