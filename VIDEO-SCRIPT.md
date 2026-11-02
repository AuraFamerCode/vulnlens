# VulnLens: 1-minute demo video script

Record the screen with OBS or the Windows Game Bar (Win+G) at 1080p, with the live site open. Speak at a normal pace; this is ≈150 words.

| Time | On screen | Say |
|---|---|---|
| 0:00–0:08 | Title of the site | "Memory-safety bugs like buffer overflows are still the number-one source of exploited vulnerabilities in C code, and they slip through code review. This is VulnLens, for Neural Storm track FT-05." |
| 0:08–0:22 | Example "classic overflow + UAF" selected, click Review | "Paste a function and it scores the risk in milliseconds, in the browser. Here: 84 out of 100. On the right, six line findings mapped to CWEs: the unbounded strcpy, the unchecked memcpy length, the allocation overflow, the format string, and a use-after-free." |
| 0:22–0:32 | Scroll to "Why the model thinks so" | "The model is explainable: these are the exact tokens and features that pushed the score up or down." |
| 0:32–0:42 | Pick the real QEMU "VULNERABLE" example, then the real "safe" one | "It's trained on 21,000 real functions from FFmpeg and QEMU. Real vulnerable QEMU code scores high, and real safe code scores 4." |
| 0:42–0:52 | Metrics card | "On the held-out Devign test set: 63.7% accuracy and 0.70 ROC-AUC, on par with fine-tuned CodeBERT, at one millisecond per function on a CPU. In review mode it catches 93% of vulnerable functions." |
| 0:52–1:00 | Terminal: `python review.py samples/demo.c --fail-above 0.7` | "And it drops into CI as a gate that fails risky pull requests. VulnLens: faster, focused code review." |
