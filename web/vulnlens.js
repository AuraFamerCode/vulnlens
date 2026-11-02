// Browser port of vulnlens/tokenize.py, features.py, rules.py and model.web_score.
// Parity with the Python scorer is checked by tests/test_web_parity.py (runs this file in Node).
(function (root) {
  const BLOCK = /\/\*[\s\S]*?\*\//g, LINE = /\/\/[^\n]*/g;
  const STR = /"(?:\\.|[^"\\\n])*"/g, CHR = /'(?:\\.|[^'\\\n])*'/g;
  const HEX = /\b0[xX][0-9a-fA-F]+[uUlL]*\b/g, NUM = /\b\d+(?:\.\d+)?[uUlLfF]*\b/g;
  const TOKEN = /[A-Za-z_][A-Za-z0-9_]*|->|\+\+|--|<<=|>>=|<<|>>|<=|>=|==|!=|&&|\|\||[+\-*/%&|^]=|[{}()\[\];,<>=+\-*/%&|^!~?:.]/g;
  function normalize(c) {
    return c.replace(BLOCK, " ").replace(LINE, " ").replace(STR, " STR ").replace(CHR, " CHR ").replace(HEX, " NUM ").replace(NUM, " NUM ");
  }
  function tokens(c) { return normalize(c).match(TOKEN) || []; }
  const RISKY = {
    unsafe_copy: ["strcpy", "strcat", "sprintf", "vsprintf", "gets", "strncpy", "strncat"],
    memory_copy: ["memcpy", "memmove", "memset"],
    alloc: ["malloc", "calloc", "realloc", "av_malloc", "av_mallocz", "g_malloc", "g_new", "kmalloc"],
    free: ["free", "av_free", "av_freep", "g_free", "kfree"],
    format_io: ["printf", "fprintf", "snprintf", "scanf", "sscanf"],
  };
  const CAST = /\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long|size_t|uint\d+_t|int\d+_t|void)\s*\**\s*\)/g;
  const NULLCHK = /!\s*[A-Za-z_]\w*\s*\)|==\s*NULL|!=\s*NULL/g;
  function features(code) {
    const norm = normalize(code), t = tokens(code), cnt = {};
    for (const x of t) cnt[x] = (cnt[x] || 0) + 1;
    const g = (k) => cnt[k] || 0;
    let d = 0, maxd = 0;
    for (const x of t) { if (x === "{") { d++; if (d > maxd) maxd = d; } else if (x === "}") d = Math.max(0, d - 1); }
    const head = norm.split("{")[0];
    let nParams = 0;
    if (head.includes("(")) {
      nParams = head.slice(head.indexOf("(") + 1, head.lastIndexOf(")")).split(",").filter((p) => p.trim() && p.trim() !== "void").length;
    }
    const f = {
      log_tokens: Math.log1p(t.length), log_lines: Math.log1p(code.split("\n").length), max_nesting: maxd,
      n_if: g("if"), n_loops: g("for") + g("while"), n_goto: g("goto"), n_return: g("return"),
      n_ptr_arrow: g("->"), n_index: g("["), n_arith_assign: ["+=", "-=", "*=", "<<=", "++", "--"].reduce((a, o) => a + g(o), 0),
      n_casts: (norm.match(CAST) || []).length, n_sizeof: g("sizeof"), n_null_checks: (norm.match(NULLCHK) || []).length, n_params: nParams,
    };
    for (const k in RISKY) f["n_" + k] = RISKY[k].reduce((a, n) => a + g(n), 0);
    return f;
  }
  function score(M, code) {
    const tf = {};
    for (const t of tokens(code)) if (M.terms[t]) tf[t] = (tf[t] || 0) + 1;
    const vals = {}; let ss = 0;
    for (const t in tf) { const v = (1 + Math.log(tf[t])) * M.terms[t][0]; vals[t] = v; ss += v * v; }
    const norm = Math.sqrt(ss) || 1;
    let z = M.bias; const contrib = [];
    for (const t in vals) { const c = (vals[t] / norm) * M.terms[t][1]; z += c; contrib.push({ term: t, c }); }
    const f = features(code);
    M.feature_names.forEach((n, i) => {
      const c = ((f[n] - M.feat_mean[i]) / M.feat_std[i]) * M.feat_weight * M.feat_w[i]; z += c; contrib.push({ term: "feat:" + n, c });
    });
    contrib.sort((a, b) => Math.abs(b.c) - Math.abs(a.c));
    return { p: 1 / (1 + Math.exp(-z)), top: contrib.slice(0, 8), features: f };
  }
  const RULES = [
    [/\b(strcpy|strcat|gets|sprintf|vsprintf)\s*\(/, "CWE-120", "Unbounded string copy", "Use a length-bounded call (snprintf / strlcpy) and check the destination size."],
    [/\b(memcpy|memmove)\s*\([^;]*\b(len|size|length|n|count)\w*/, "CWE-787", "Copy length from a variable", "Validate the length against the destination buffer before copying."],
    [/\b(malloc|av_malloc|g_malloc|kmalloc)\s*\([^;]*\*/, "CWE-190", "Multiplication inside allocation size", "Check for integer overflow (or use calloc / av_malloc_array) before allocating."],
    [/\b(free|av_free|g_free|kfree)\s*\(\s*([A-Za-z_][\w>\-\.]*)\s*\)\s*;/, "CWE-416", "Pointer not cleared after free", "Set the pointer to NULL (or use av_freep) to avoid use-after-free / double free."],
    [/\b(printf|fprintf|syslog)\s*\(\s*(?:[A-Za-z_]\w*\s*,\s*)?[A-Za-z_]\w*\s*\)/, "CWE-134", "Non-literal format string", "Pass a literal format string, e.g. printf(\"%s\", msg)."],
    [/\[\s*[A-Za-z_]\w*\s*(?:\+|-)\s*\w+\s*\]/, "CWE-125", "Computed array index", "Bounds-check computed indices before reading or writing the array."],
    [/\b(scanf|sscanf|fscanf)\s*\([^;]*%s/, "CWE-120", "Unbounded %s in scanf", "Give %s a width, e.g. %63s."],
    [/\balloca\s*\(/, "CWE-770", "Stack allocation of variable size", "Prefer heap allocation with an explicit size limit."],
  ];
  function review(code) {
    const out = [];
    code.split("\n").forEach((line, i) => {
      const s = line.trim();
      if (s.startsWith("//") || s.startsWith("*")) return;
      for (const [rx, cwe, title, advice] of RULES) if (rx.test(line)) out.push({ line: i + 1, cwe, title, advice, snippet: s.slice(0, 160) });
    });
    return out;
  }
  const api = { normalize, tokens, features, score, review };
  if (typeof module !== "undefined") module.exports = api; else root.VulnLens = api;
})(this);
