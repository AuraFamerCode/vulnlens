"""Line-level review hints mapped to CWE ids. Rules explain; the ML model scores."""
import re
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    line: int
    cwe: str
    title: str
    advice: str
    snippet: str

    def to_dict(self) -> dict:
        return asdict(self)


RULES = [
    (re.compile(r"\b(strcpy|strcat|gets|sprintf|vsprintf)\s*\("), "CWE-120", "Unbounded string copy",
     "Use a length-bounded call (snprintf / strlcpy) and check the destination size."),
    (re.compile(r"\b(memcpy|memmove)\s*\([^;]*\b(len|size|length|n|count)\w*"), "CWE-787", "Copy length from a variable",
     "Validate the length against the destination buffer before copying."),
    (re.compile(r"\b(malloc|av_malloc|g_malloc|kmalloc)\s*\([^;]*\*"), "CWE-190", "Multiplication inside allocation size",
     "Check for integer overflow (or use calloc / av_malloc_array) before allocating."),
    (re.compile(r"\b(free|av_free|g_free|kfree)\s*\(\s*([A-Za-z_][\w>\-\.]*)\s*\)\s*;"), "CWE-416", "Pointer not cleared after free",
     "Set the pointer to NULL (or use av_freep) to avoid use-after-free / double free."),
    (re.compile(r"\b(printf|fprintf|syslog)\s*\(\s*(?:[A-Za-z_]\w*\s*,\s*)?[A-Za-z_]\w*\s*\)"), "CWE-134", "Non-literal format string",
     "Pass a literal format string, e.g. printf(\"%s\", msg)."),
    (re.compile(r"\[\s*[A-Za-z_]\w*\s*(?:\+|-)\s*\w+\s*\]"), "CWE-125", "Computed array index",
     "Bounds-check computed indices before reading or writing the array."),
    (re.compile(r"\b(scanf|sscanf|fscanf)\s*\([^;]*%s"), "CWE-120", "Unbounded %s in scanf",
     "Give %s a width, e.g. %63s."),
    (re.compile(r"\balloca\s*\("), "CWE-770", "Stack allocation of variable size",
     "Prefer heap allocation with an explicit size limit."),
]


def review(code: str) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        for rx, cwe, title, advice in RULES:
            if rx.search(line):
                out.append(Finding(i, cwe, title, advice, stripped[:160]))
    return out
