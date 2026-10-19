# Analyst fine-tuning runbook

This directory packages candidate supervision for a local analyst model. It is
not evidence of a completed or independently evaluated fine-tuning run. The
2026-09-23 recheck found two corpus entries: one `reallab` entry and one synthetic
`demo` entry. See the measured evidence in [HANDOFF.md](../docs/HANDOFF.md).

## Available inputs

- `corpus/sft.jsonl` — frozen prompt/response examples, including synthetic
  data. Existing rows predate the current guards and must be reviewed and
  revalidated before training; they are not current model-quality measurements.
- `assessments/*.json` — supervision assessments per case, authored by a human
  or a stronger reviewer. The builder refuses any assessment citing a finding
  or evidence id that is not in the case (`exit 2`). The current builder also
  rejects unsupported CVEs/numbers. These checks do not verify semantic truth,
  reviewer identity, safe remediation, or independent evaluation.
- `build_corpus.py` — builder/validator. Grow the corpus by scanning more real
  targets, then running:

  ```
  python finetune/build_corpus.py --run <run> --host <ip> \
      --assessment finetune/assessments/<run>-<ip>.json \
      --out finetune/corpus/sft.jsonl
  ```

## Training recipe (not run by the agent)

NOT RUN: this illustrative recipe requires human-reviewed local dependencies,
model artifacts, hardware and supervision provenance. Nothing is provisioned by
the agent. Do not upload scan cases to cloud training services without the
required policy approval. Resource use and model quality have not been measured.

```python
# train_sft.py — run where a GPU exists
import json, torch
from datasets import Dataset
from peft import LoraConfig
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer

rows = [json.loads(l) for l in open("sft.jsonl")]
ds = Dataset.from_list([{"text": r["prompt"] + r["response"] + "<|eot_id|>"} for r in rows])

bnb = BitsAndBytesConfig(
    load_in_4bit=True, bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_quant_type="nf4"
)
tok = AutoTokenizer.from_pretrained("meta-llama/Llama-3.2-3B-Instruct")
model = AutoModelForCausalLM.from_pretrained(
    "meta-llama/Llama-3.2-3B-Instruct", quantization_config=bnb, device_map="auto"
)
cfg = LoraConfig(
    r=16,
    lora_alpha=32,
    lora_dropout=0.05,
    task_type="CAUSAL_LM",
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
)
trainer = SFTTrainer(
    model=model,
    train_dataset=ds,
    peft_config=cfg,
    args=SFTConfig(
        num_train_epochs=3,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,
        learning_rate=2e-4,
        logging_steps=1,
        output_dir="analyst-lora",
    ),
)
trainer.train()
trainer.save_model("analyst-lora")
```

Then merge, convert and quantize with llama.cpp:

```
python convert_hf_to_gguf.py merged/ --outfile analyst-f16.gguf
llama-quantize analyst-f16.gguf analyst-q4.gguf q4_K_M
```

## Bring the trained model into the product

```
ollama create vulnassess-analyst -f Modelfile        # FROM ./analyst-q4.gguf
python -m vulnassess ui --model vulnassess-analyst --db data/vulnassess.db --run reallab
```

The UI's Analyze action uses whatever `--model` names, so the trained model
replaces the vanilla baseline with one flag. Everything stays local.

## Honest limits

- VERIFIED: the recheck inspected two stored rows, one `reallab` and one
  synthetic `demo`. This is a corpus inventory, not verified real supervision
  or a trained analyst. Reviewer provenance and held-out evaluation are missing.
- Supervision provenance must be recorded per example in the assessment file's
  sibling provenance note; keep assessments reviewable like any other evidence.
- Scoring stays deterministic. The current analyst boundary rejects unsupported
  CVEs/numbers and never writes canonical scores; those guards do not prove
  semantic correctness or useful reasoning.
