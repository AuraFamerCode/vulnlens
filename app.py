"""Local Gradio demo: python app.py  ->  http://127.0.0.1:7860"""
import json
import joblib
import gradio as gr
from vulnlens.rules import review

model = joblib.load("models/vulnlens.joblib")
EXAMPLES = [[e["code"]] for e in json.load(open("web/examples.json"))]


def analyse(code: str):
    p = float(model.predict_proba([code])[0])
    label = "HIGH" if p >= model.threshold else "MEDIUM" if p >= 0.4 else "LOW"
    findings = [[f.line, f.cwe, f.title, f.advice] for f in review(code)]
    why = [[e["term"], e["contribution"]] for e in model.explain(code)]
    return f"## Risk {p*100:.0f}/100 — {label}", findings, why


with gr.Blocks(title="VulnLens") as demo:
    gr.Markdown("# VulnLens — AI security review for C/C++ functions (Neural Storm FT-05)")
    code = gr.Code(language="c", label="Function", lines=22)
    btn = gr.Button("Review", variant="primary")
    risk = gr.Markdown()
    fnd = gr.Dataframe(headers=["line", "CWE", "finding", "advice"], label="Line findings")
    why = gr.Dataframe(headers=["term", "contribution"], label="Why (top model contributions)")
    gr.Examples(EXAMPLES, inputs=code)
    btn.click(analyse, code, [risk, fnd, why])

if __name__ == "__main__":
    demo.launch()
