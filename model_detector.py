"""Local detector adapter for the AI Firewall."""

import torch
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
)

MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"
MAX_CHARACTERS = 12000


class LocalDetector:
    def __init__(self):
        # Use files already downloaded on this computer.
        self.tokenizer = AutoTokenizer.from_pretrained(
            MODEL_ID,
            local_files_only=True,
            trust_remote_code=False,
        )

        self.model = AutoModelForSequenceClassification.from_pretrained(
            MODEL_ID,
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
        )

        self.model.to("cpu")
        self.model.eval()

        # Count all tokens, including the model's special tokens.
        self.max_tokens = min(
            512,
            int(self.model.config.max_position_embeddings),
        )

        expected_labels = {0: "SAFE", 1: "INJECTION"}
        if self.model.config.id2label != expected_labels:
            raise ValueError("Unexpected model labels; loading stopped.")

    def __call__(self, text):
        # Invalid or oversized input must not receive a SAFE verdict.
        if not isinstance(text, str):
            return "UNKNOWN"

        if not text.strip() or len(text) > MAX_CHARACTERS:
            return "UNKNOWN"

        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=False,
        )

        # Never silently cut off the end of a message.
        if inputs["input_ids"].shape[1] > self.max_tokens:
            return "UNKNOWN"

        with torch.inference_mode():
            logits = self.model(**inputs).logits

        if logits.shape != (1, 2):
            return "UNKNOWN"

        if not torch.isfinite(logits).all().item():
            return "UNKNOWN"

        label_id = int(logits.argmax(dim=-1).item())
        return self.model.config.id2label[label_id]