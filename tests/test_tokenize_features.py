from vulnlens.tokenize import normalize, tokens
from vulnlens.features import extract, FEATURE_NAMES
from vulnlens.rules import review

SRC = '''int copy(char *dst, const char *src, int len) {
    /* comment with strcpy( */
    char buf[64]; // strcpy(
    if (!src) return -1;
    strcpy(buf, src);
    memcpy(dst, buf, len);
    for (int i = 0; i < 0x10; i++) { dst[i + 1] = 'a'; }
    printf(src);
    free(dst);
    return 0;
}'''


def test_comments_strings_numbers_normalised():
    n = normalize('x = "hi"; /* c */ y = 0x1F + 3.5; // z')
    assert "hi" not in n and "c" not in n.split() and "STR" in n and n.count("NUM") == 2


def test_tokens_keep_operators():
    assert tokens("a->b += c[i++];") == ["a", "->", "b", "+=", "c", "[", "i", "++", "]", ";"]


def test_features_counts():
    f = extract(SRC)
    assert set(f) == set(FEATURE_NAMES)
    assert f["n_unsafe_copy"] == 1  # the commented-out strcpy calls must not count
    assert f["n_memory_copy"] == 1 and f["n_free"] == 1 and f["n_loops"] == 1
    assert f["n_params"] == 3 and f["max_nesting"] == 2 and f["n_null_checks"] == 1


def test_rules_find_expected_cwes():
    cwes = {x.cwe for x in review(SRC)}
    assert {"CWE-120", "CWE-787", "CWE-134", "CWE-416", "CWE-125"} <= cwes


def test_rules_skip_comment_lines_and_safe_code():
    assert review("// strcpy(a, b);\nint add(int a, int b) { return a + b; }") == []
