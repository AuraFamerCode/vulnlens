"""Code normalisation + tokenisation. Mirrored exactly in web/vulnlens.js."""
import re

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_STRING = re.compile(r'"(?:\\.|[^"\\\n])*"')
_CHAR = re.compile(r"'(?:\\.|[^'\\\n])*'")
_HEX = re.compile(r"\b0[xX][0-9a-fA-F]+[uUlL]*\b")
_NUM = re.compile(r"\b\d+(?:\.\d+)?[uUlLfF]*\b")
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|->|\+\+|--|<<=|>>=|<<|>>|<=|>=|==|!=|&&|\|\||[+\-*/%&|^]=|[{}()\[\];,<>=+\-*/%&|^!~?:.]")


def normalize(code: str) -> str:
    code = _BLOCK_COMMENT.sub(" ", code)
    code = _LINE_COMMENT.sub(" ", code)
    code = _STRING.sub(" STR ", code)
    code = _CHAR.sub(" CHR ", code)
    code = _HEX.sub(" NUM ", code)
    code = _NUM.sub(" NUM ", code)
    return code


def tokens(code: str) -> list[str]:
    return _TOKEN.findall(normalize(code))


def ngrams(code: str, n_max: int = 3) -> list[str]:
    t = tokens(code)
    out = list(t)
    for n in range(2, n_max + 1):
        out += [" ".join(t[i:i + n]) for i in range(len(t) - n + 1)]
    return out
