"""VulnLens risk model: TF-IDF over normalised code tokens + scaled hand-crafted features -> logistic regression."""
from __future__ import annotations
import json
import math
from dataclasses import dataclass

import numpy as np
import scipy.sparse as sp
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from .features import FEATURE_NAMES, vector
from .tokenize import tokens

FEAT_WEIGHT = 0.3  # scale of the dense block relative to the TF-IDF block


@dataclass
class VulnLensModel:
    vectorizer: TfidfVectorizer
    mean: np.ndarray
    std: np.ndarray
    clf: LogisticRegression
    threshold: float = 0.5

    @classmethod
    def fit(cls, codes, labels, max_features=30000, C=1.0) -> "VulnLensModel":
        vec = TfidfVectorizer(tokenizer=tokens, lowercase=False, token_pattern=None,
                              max_features=max_features, sublinear_tf=True, min_df=2)
        X = vec.fit_transform(codes)
        F = np.array([vector(c) for c in codes])
        mean, std = F.mean(0), F.std(0)
        std[std < 1e-6] = 1.0  # constant features
        clf = LogisticRegression(C=C, max_iter=3000)
        m = cls(vec, mean, std, clf)
        clf.fit(m._stack(X, F), labels)
        return m

    def _stack(self, X, F):
        return sp.hstack([X, (F - self.mean) / self.std * FEAT_WEIGHT]).tocsr()

    def predict_proba(self, codes) -> np.ndarray:
        X = self.vectorizer.transform(codes)
        F = np.array([vector(c) for c in codes])
        return self.clf.predict_proba(self._stack(X, F))[:, 1]

    def predict(self, codes) -> np.ndarray:
        return (self.predict_proba(codes) >= self.threshold).astype(int)

    def explain(self, code: str, k: int = 8) -> list[dict]:
        """Top contributing tokens/features (weight x value) for one function."""
        X = self.vectorizer.transform([code])
        F = np.array([vector(code)])
        z = self._stack(X, F).toarray()[0]
        w = self.clf.coef_[0]
        names = list(self.vectorizer.get_feature_names_out()) + ["feat:" + n for n in FEATURE_NAMES]
        contrib = z * w
        idx = np.argsort(-np.abs(contrib))[:k]
        return [{"term": names[i], "contribution": round(float(contrib[i]), 4)} for i in idx if contrib[i] != 0]

    def to_web_json(self) -> dict:
        vocab = self.vectorizer.vocabulary_
        terms = sorted(vocab, key=vocab.get)
        w = self.clf.coef_[0]
        n = len(terms)
        return {
            "version": 1,
            "terms": {t: [round(float(self.vectorizer.idf_[vocab[t]]), 5), round(float(w[vocab[t]]), 5)] for t in terms},
            "feature_names": FEATURE_NAMES,
            "feat_mean": [round(float(x), 6) for x in self.mean],
            "feat_std": [round(float(x), 6) for x in self.std],
            "feat_w": [round(float(x), 6) for x in w[n:]],
            "feat_weight": FEAT_WEIGHT,
            "bias": float(self.clf.intercept_[0]),
            "threshold": self.threshold,
        }


def web_score(model_json: dict, code: str) -> float:
    """Pure-Python re-implementation of the browser scorer (used to test parity)."""
    toks = tokens(code)
    tf: dict[str, int] = {}
    for t in toks:
        if t in model_json["terms"]:
            tf[t] = tf.get(t, 0) + 1
    vals = {t: (1 + math.log(c)) * model_json["terms"][t][0] for t, c in tf.items()}
    norm = math.sqrt(sum(v * v for v in vals.values())) or 1.0
    z = model_json["bias"] + sum(v / norm * model_json["terms"][t][1] for t, v in vals.items())
    f = vector(code)
    for i, x in enumerate(f):
        z += (x - model_json["feat_mean"][i]) / model_json["feat_std"][i] * model_json["feat_weight"] * model_json["feat_w"][i]
    return 1 / (1 + math.exp(-z))


def save_web(model: VulnLensModel, path: str) -> None:
    with open(path, "w") as fh:
        json.dump(model.to_web_json(), fh, separators=(",", ":"))
