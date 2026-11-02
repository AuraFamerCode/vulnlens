import json, os, math
import pytest
from vulnlens.model import VulnLensModel, web_score

ROOT = os.path.dirname(os.path.dirname(__file__))

TOY = [("int f(char*d,char*s){strcpy(d,s);return 0;}", 1), ("int g(int a,int b){return a+b;}", 0)] * 20


def test_fit_predict_explain_roundtrip():
    codes, y = zip(*TOY)
    m = VulnLensModel.fit(list(codes), list(y), max_features=100)
    p = m.predict_proba(list(codes[:2]))
    assert p[0] > p[1]
    ex = m.explain(codes[0])
    assert ex and "term" in ex[0]


def test_web_json_matches_sklearn():
    codes, y = zip(*TOY)
    m = VulnLensModel.fit(list(codes), list(y), max_features=100)
    j = json.loads(json.dumps(m.to_web_json()))
    for c in codes[:2] + ("void h(){ while(1){ x->y[i+1]=0; } }",):
        assert abs(web_score(j, c) - m.predict_proba([c])[0]) < 1e-3


@pytest.mark.skipif(not os.path.exists(os.path.join(ROOT, "results/metrics.json")), reason="run train.py first")
def test_reported_metrics_are_sane():
    r = json.load(open(os.path.join(ROOT, "results/metrics.json")))
    a = r["test_accuracy_mode"]
    assert a["accuracy"] > r["majority_baseline_accuracy"] + 0.05
    assert 0 < a["f1"] < 1 and a["roc_auc"] > 0.6
    assert r["latency_ms"]["p50"] < 100
