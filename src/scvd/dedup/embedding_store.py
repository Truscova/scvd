# Lightweight *optional* on-disk embedding cache (sidecar files, not in JSON)
# Keyed by (model_id, content_sha256). You can disable caching completely.

from __future__ import annotations
import hashlib, json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
import torch
from transformers import AutoModel, AutoTokenizer

@dataclass
class EmbedModel:
    model_id: str
    tokenizer: AutoTokenizer
    model: AutoModel
    max_tokens: int
    dim: int

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def content_sha256(text: str) -> str:
    # Stable hash over canonicalized text
    return _sha256_bytes(text.encode("utf-8"))

def load_embed_model(model_id: str = "snowflake-arctic-embed-l-v2.0",
                     device: Optional[str] = None) -> EmbedModel:
    """
    Loads a local embedding model (Hugging Face). Works on a single A5000.
    Switch model_id to 'nvidia/NV-Embed-v2' if you want heavier SOTA.
    """
    tok = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    mdl = AutoModel.from_pretrained(
        model_id,
        trust_remote_code=True,
        torch_dtype=torch.float16,
        device_map=("auto" if device is None else None)
    )
    dim = getattr(mdl, "embed_dim", None) or getattr(mdl.config, "hidden_size", None) or 1024
    max_tokens = getattr(mdl.config, "max_position_embeddings", 8192)
    return EmbedModel(model_id=model_id, tokenizer=tok, model=mdl, max_tokens=int(max_tokens), dim=int(dim))

class EmbeddingStore:
    """
    Sidecar storage (optional):
      <root>/embeddings/<model_id>/<sha>.npy
      <root>/embeddings/<model_id>/manifest.jsonl
    """
    def __init__(self, root: Path, cache_mode: str = "none"):
        assert cache_mode in {"none","disk"}
        self.root = Path(root)
        self.cache_mode = cache_mode
        self.emb_root = self.root / "embeddings"
        if cache_mode == "disk":
            self.emb_root.mkdir(parents=True, exist_ok=True)

    def _model_dir(self, model_id: str) -> Path:
        d = self.emb_root / model_id.replace("/", "__")
        if self.cache_mode == "disk":
            d.mkdir(parents=True, exist_ok=True)
        return d

    def vector_path(self, model_id: str, sha: str) -> Path:
        return self._model_dir(model_id) / f"{sha}.npy"

    def has(self, model_id: str, sha: str) -> bool:
        if self.cache_mode != "disk":
            return False
        return self.vector_path(model_id, sha).exists()

    def save(self, model_id: str, sha: str, vec: np.ndarray) -> Optional[Path]:
        if self.cache_mode != "disk":
            return None
        p = self.vector_path(model_id, sha)
        np.save(p, vec.astype(np.float32))
        manifest = {
            "sha256": sha,
            "model_id": model_id,
            "path": str(p),
            "dim": int(vec.shape[-1]),
            "created_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        }
        with (self._model_dir(model_id) / "manifest.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(manifest) + "\n")
        return p

    @torch.inference_mode()
    def embed(self, model: EmbedModel, text: str) -> np.ndarray:
        """
        Mean-pool last hidden state (robust across most HF embedding checkpoints).
        """
        toks = model.tokenizer(
            text, truncation=True, max_length=model.max_tokens, return_tensors="pt"
        )
        toks = {k: v.to(model.model.device) for k, v in toks.items()}
        out = model.model(**toks)
        last = getattr(out, "last_hidden_state", None) or out[0]
        attn = toks.get("attention_mask", torch.ones_like(last[:, :, 0]))
        mask = attn.unsqueeze(-1).type_as(last)
        vec = (last * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-6)
        vec = torch.nn.functional.normalize(vec, p=2, dim=-1)[0]
        return vec.detach().float().cpu().numpy()

    def get_or_compute(self, model: EmbedModel, text: str) -> tuple[str, np.ndarray]:
        sha = content_sha256(text)
        if self.cache_mode == "disk" and self.has(model.model_id, sha):
            return sha, np.load(self.vector_path(model.model_id, sha))
        vec = self.embed(model, text)
        self.save(model.model_id, sha, vec)  # no-op if cache_mode="none"
        return sha, vec
