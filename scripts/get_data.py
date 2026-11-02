"""Download the CodeXGLUE Defect Detection (Devign) splits into data/."""
import os, shutil
from huggingface_hub import hf_hub_download

os.makedirs("data", exist_ok=True)
for s in ("train", "validation", "test"):
    p = hf_hub_download("google/code_x_glue_cc_defect_detection", f"data/{s}-00000-of-00001.parquet", repo_type="dataset")
    shutil.copy(p, f"data/{s}.parquet"); print("saved", f"data/{s}.parquet")
