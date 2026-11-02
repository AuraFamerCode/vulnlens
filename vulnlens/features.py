"""Hand-crafted, explainable code-risk features (mirrored in web/vulnlens.js)."""
import re
from .tokenize import normalize, tokens

RISKY_CALLS = {
    "unsafe_copy": ["strcpy", "strcat", "sprintf", "vsprintf", "gets", "strncpy", "strncat"],
    "memory_copy": ["memcpy", "memmove", "memset"],
    "alloc": ["malloc", "calloc", "realloc", "av_malloc", "av_mallocz", "g_malloc", "g_new", "kmalloc"],
    "free": ["free", "av_free", "av_freep", "g_free", "kfree"],
    "format_io": ["printf", "fprintf", "snprintf", "scanf", "sscanf"],
}

FEATURE_NAMES = [
    "log_tokens", "log_lines", "max_nesting", "n_if", "n_loops", "n_goto", "n_return",
    "n_ptr_arrow", "n_index", "n_arith_assign", "n_casts", "n_sizeof", "n_null_checks",
    "n_unsafe_copy", "n_memory_copy", "n_alloc", "n_free", "n_format_io", "n_params",
]

_CAST = re.compile(r"\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long|size_t|uint\d+_t|int\d+_t|void)\s*\**\s*\)")


def _log1p(x: float) -> float:
    import math
    return math.log1p(x)


def extract(code: str) -> dict:
    norm = normalize(code)
    t = tokens(code)
    counts: dict[str, int] = {}
    for tok in t:
        counts[tok] = counts.get(tok, 0) + 1
    depth = maxd = 0
    for tok in t:
        if tok == "{":
            depth += 1
            maxd = max(maxd, depth)
        elif tok == "}":
            depth = max(0, depth - 1)
    head = norm.split("{", 1)[0]
    n_params = 0 if "(" not in head else len([p for p in head[head.find("(") + 1:head.rfind(")")].split(",") if p.strip() and p.strip() != "void"])
    f = {
        "log_tokens": _log1p(len(t)),
        "log_lines": _log1p(code.count("\n") + 1),
        "max_nesting": float(maxd),
        "n_if": counts.get("if", 0),
        "n_loops": counts.get("for", 0) + counts.get("while", 0),
        "n_goto": counts.get("goto", 0),
        "n_return": counts.get("return", 0),
        "n_ptr_arrow": counts.get("->", 0),
        "n_index": counts.get("[", 0),
        "n_arith_assign": sum(counts.get(o, 0) for o in ["+=", "-=", "*=", "<<=", "++", "--"]),
        "n_casts": len(_CAST.findall(norm)),
        "n_sizeof": counts.get("sizeof", 0),
        "n_null_checks": len(re.findall(r"!\s*[A-Za-z_]\w*\s*\)|==\s*NULL|!=\s*NULL", norm)),
        "n_params": n_params,
    }
    for k, names in RISKY_CALLS.items():
        f["n_" + k] = sum(counts.get(n, 0) for n in names)
    return {k: float(f[k]) for k in FEATURE_NAMES}


def vector(code: str) -> list[float]:
    d = extract(code)
    return [d[k] for k in FEATURE_NAMES]
