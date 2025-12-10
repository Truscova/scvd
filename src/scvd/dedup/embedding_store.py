# scvd/dedup/embedding_store.py

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, List, Tuple

import json
import hashlib

import numpy as np
import torch
from sentence_transformers import SentenceTransformer


def load_embed_model(model_name: str, device: Optional[str] = None) -> SentenceTransformer:
    """
    Load a sentence-transformers model for embedding.

    Uses CUDA if available unless `device` is explicitly provided.
    """
    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"

    print(f"[dedup] Loading embedding model '{model_name}' on device '{device}'")
    model = SentenceTransformer(model_name, device=device)
    return model


def encode_texts(
    model: SentenceTransformer,
    texts: List[str],
    batch_size: int = 32,
) -> np.ndarray:
    """
    Encode a list of texts into L2-normalized embeddings (numpy array).
    """
    if not texts:
        return np.zeros((0, model.get_sentence_embedding_dimension()), dtype=np.float32)

    embeddings = model.encode(
        texts,
        batch_size=batch_size,
        convert_to_numpy=True,
        show_progress_bar=True,
        normalize_embeddings=True,  # cosine similarity = dot product
    )
    # Ensure float32
    return embeddings.astype(np.float32)


@dataclass
class EmbeddingStore:
    """
    Tiny disk-backed cache for embeddings, keyed by a stable hash of the text.

    cache_mode:
      - "none": no caching
      - "disk": store under emb_root/emb_cache/<model_name>/...
    """
    model: SentenceTransformer
    model_name: str
    emb_root: Path
    cache_mode: str = "none"   # "none" or "disk"

    def __post_init__(self) -> None:
        self._mem_cache: Dict[str, np.ndarray] = {}
        if self.cache_mode == "disk":
            self.cache_dir = self.emb_root / "emb_cache" / self._safe_model_name()
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.cache_dir = None

    def _safe_model_name(self) -> str:
        return self.model_name.replace("/", "__")

    @staticmethod
    def _hash_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _disk_path(self, key: str) -> Path:
        assert self.cache_dir is not None
        return self.cache_dir / f"{key}.json"

    # --- core API ---

    def get(self, text: str) -> np.ndarray:
        """
        Get (or compute) the embedding for a single text.
        """
        embs = self.get_many([text])
        return embs[0]

    def get_many(self, texts: List[str]) -> np.ndarray:
        """
        Get (or compute) embeddings for many texts in one go.

        Uses in-memory and optional disk cache; only missing texts are
        passed to the model in a batch.
        """
        if not texts:
            return np.zeros((0, self.model.get_sentence_embedding_dimension()), dtype=np.float32)

        keys = [self._hash_text(t) for t in texts]
        embs: List[Optional[np.ndarray]] = [None] * len(texts)

        missing_indices: List[int] = []
        missing_texts: List[str] = []

        # 1) try memory / disk caches
        for i, (t, k) in enumerate(zip(texts, keys)):
            # mem cache
            if k in self._mem_cache:
                embs[i] = self._mem_cache[k]
                continue

            # disk cache
            if self.cache_mode == "disk" and self.cache_dir is not None:
                path = self._disk_path(k)
                if path.exists():
                    data = json.loads(path.read_text(encoding="utf-8"))
                    e = np.array(data["embedding"], dtype=np.float32)
                    self._mem_cache[k] = e
                    embs[i] = e
                    continue

            # missing
            missing_indices.append(i)
            missing_texts.append(t)

        # 2) compute embeddings for missing texts
        if missing_texts:
            new_embs = encode_texts(self.model, missing_texts)
            for idx, e in zip(missing_indices, new_embs):
                k = keys[idx]
                self._mem_cache[k] = e
                if self.cache_mode == "disk" and self.cache_dir is not None:
                    path = self._disk_path(k)
                    payload = {"embedding": e.tolist()}
                    path.write_text(json.dumps(payload), encoding="utf-8")
                embs[idx] = e

        # 3) stack into a single array
        assert all(e is not None for e in embs)
        arr = np.stack([e for e in embs if e is not None], axis=0)
        return arr

    # Backwards-compat with older code I gave you earlier
    def get_or_compute(self, _model: SentenceTransformer, text: str) -> Tuple[str, np.ndarray]:
        """
        Compat wrapper for older code that expected (key, embedding).

        We just compute the hash key and call get().
        """
        key = self._hash_text(text)
        emb = self.get(text)
        return key, emb
