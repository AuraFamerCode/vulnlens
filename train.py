"""Train + evaluate VulnLens on CodeXGLUE Defect Detection (Devign). Writes models/ and results/."""
import json, os, platform, sys, time
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score, confusion_matrix

from vulnlens.model import VulnLensModel, save_web
from vulnlens.tokenize import normalize

RNG = np.random.default_rng(0)
os.makedirs("models", exist_ok=True); os.makedirs("results", exist_ok=True)
tr, va, te = [pd.read_parquet(f"data/{s}.parquet") for s in ("train", "validation", "test")]

def metrics(y, p, thr):
    yhat = (p >= thr).astype(int)
    return {"accuracy": accuracy_score(y, yhat), "precision": precision_score(y, yhat), "recall": recall_score(y, yhat),
            "f1": f1_score(y, yhat), "roc_auc": roc_auc_score(y, p), "confusion": confusion_matrix(y, yhat).tolist()}

def boot_ci(y, p, thr, fn, n=1000):
    y, yhat = np.asarray(y), (p >= thr).astype(int); s = []
    for _ in range(n):
        i = RNG.integers(0, len(y), len(y)); s.append(fn(y[i], yhat[i]))
    return [float(np.percentile(s, 2.5)), float(np.percentile(s, 97.5))]

# 1) model selection on the validation split only
grid = []
for mf in (10000, 30000, 100000):
    for C in (0.5, 1.0, 2.0):
        m = VulnLensModel.fit(tr.func.tolist(), tr.target.values, max_features=mf, C=C)
        acc = accuracy_score(va.target, m.predict(va.func.tolist()))
        grid.append({"max_features": mf, "C": C, "val_accuracy": acc}); print(grid[-1], flush=True)
# prefer the smallest vocabulary within 0.5 pt of the best (keeps the browser model small)
best_acc = max(g["val_accuracy"] for g in grid)
pick = sorted([g for g in grid if g["val_accuracy"] >= best_acc - 0.005], key=lambda g: (g["max_features"], -g["val_accuracy"]))[0]
print("picked", pick)
m = VulnLensModel.fit(tr.func.tolist(), tr.target.values, max_features=pick["max_features"], C=pick["C"])

# 2) two operating points chosen on validation: max accuracy and max F1 ("review mode", higher recall)
pv = m.predict_proba(va.func.tolist())
ths = np.round(np.arange(0.30, 0.71, 0.01), 2)
thr_acc = float(max(ths, key=lambda t: accuracy_score(va.target, pv >= t)))
thr_f1 = float(max(ths, key=lambda t: f1_score(va.target, pv >= t)))
m.threshold = thr_acc

# 3) held-out test, touched once
pt = m.predict_proba(te.func.tolist())
res = {"dataset": "CodeXGLUE Defect Detection (Devign), google/code_x_glue_cc_defect_detection",
       "splits": {"train": len(tr), "validation": len(va), "test": len(te)},
       "grid": grid, "picked": pick, "thr_accuracy_mode": thr_acc, "thr_review_mode": thr_f1,
       "test_accuracy_mode": metrics(te.target, pt, thr_acc), "test_review_mode": metrics(te.target, pt, thr_f1)}
res["test_accuracy_mode"]["accuracy_ci95"] = boot_ci(te.target, pt, thr_acc, accuracy_score)
res["test_accuracy_mode"]["f1_ci95"] = boot_ci(te.target, pt, thr_acc, f1_score)
res["test_review_mode"]["f1_ci95"] = boot_ci(te.target, pt, thr_f1, f1_score)

# 4) leakage check: test functions whose normalised text also appears in train
key = lambda s: " ".join(normalize(s).split())
trk = set(map(key, tr.func)); dup = te.func.map(key).isin(trk).values
res["test_exact_dupes_of_train"] = int(dup.sum())
if (~dup).sum():
    res["test_dedup_accuracy"] = accuracy_score(te.target[~dup], pt[~dup] >= thr_acc)

# 5) majority-class baseline + per-project breakdown
res["majority_baseline_accuracy"] = float(max(te.target.mean(), 1 - te.target.mean()))
res["per_project"] = {p: {"n": int((te.project == p).sum()), "accuracy": accuracy_score(te.target[te.project == p], pt[(te.project == p).values] >= thr_acc)} for p in te.project.unique()}

# 6) latency: single-function inference, end to end (tokenise + features + predict), CPU
codes = te.func.sample(300, random_state=0).tolist(); lat = []
for c in codes:
    t0 = time.perf_counter(); m.predict_proba([c]); lat.append((time.perf_counter() - t0) * 1000)
t0 = time.perf_counter(); m.predict_proba(te.func.tolist()); batch = time.perf_counter() - t0
res["latency_ms"] = {"p50": float(np.percentile(lat, 50)), "p95": float(np.percentile(lat, 95)),
                     "batch_throughput_funcs_per_s": len(te) / batch, "cpu": platform.processor() or platform.machine(), "cores": os.cpu_count()}

joblib.dump(m, "models/vulnlens.joblib"); save_web(m, "web/model.json")
res["web_model_bytes"] = os.path.getsize("web/model.json")
json.dump(res, open("results/metrics.json", "w"), indent=2, default=float)
print(json.dumps({k: v for k, v in res.items() if k not in ("grid", "per_project")}, indent=1, default=float))
