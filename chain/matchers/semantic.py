"""Tier 2: semantic similarity to clusters of known-bad behavior.

Clusters are YAML files of example texts (attacks, malicious commands,
malware capability descriptions). New content is scored by cosine
similarity to the closest example, so paraphrases still match.

The default embedder is an offline hashed n-gram model so the scaffold runs
with zero dependencies. Swap in a real embedding model for production:

    CHAIN_EMBEDDER=sentence-transformers:intfloat/multilingual-e5-small
"""
from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import yaml

from .base import MatchContext, MatchResult

WORD_RE = re.compile(r"[a-z0-9_]+")


class Embedder(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]: ...


class HashingEmbedder:
    """Dependency-free embedder: hashed word unigrams/bigrams + char trigrams."""

    def __init__(self, dim: int = 2048) -> None:
        self.dim = dim

    def _features(self, text: str) -> list[str]:
        text = text.lower()
        words = WORD_RE.findall(text)
        feats = [f"w:{w}" for w in words]
        feats += [f"b:{a}_{b}" for a, b in zip(words, words[1:])]
        joined = " ".join(words)
        feats += [f"c:{joined[i:i + 3]}" for i in range(max(len(joined) - 2, 0))]
        return feats

    def embed(self, texts: list[str]) -> list[list[float]]:
        out = []
        for t in texts:
            vec = [0.0] * self.dim
            for f in self._features(t):
                h = int.from_bytes(hashlib.blake2b(f.encode(), digest_size=8).digest(), "little")
                weight = 2.0 if f[0] == "b" else (1.0 if f[0] == "w" else 0.3)
                vec[h % self.dim] += weight if (h >> 63) & 1 else -weight
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            out.append([v / norm for v in vec])
        return out


class SentenceTransformerEmbedder:
    def __init__(self, model_name: str) -> None:
        from sentence_transformers import SentenceTransformer  # optional dependency

        self.model = SentenceTransformer(model_name)

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self.model.encode(texts, normalize_embeddings=True).tolist()


def default_embedder() -> Embedder:
    spec = os.environ.get("CHAIN_EMBEDDER", "")
    if spec.startswith("sentence-transformers:"):
        return SentenceTransformerEmbedder(spec.split(":", 1)[1])
    return HashingEmbedder()


def _cos(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


class SemanticIndex:
    """In-memory cluster index. Replace with FAISS / a vector DB at scale."""

    def __init__(self, embedder: Embedder | None = None) -> None:
        self.embedder = embedder or default_embedder()
        self.clusters: dict[str, list[tuple[str, list[float]]]] = {}

    def add_cluster(self, name: str, examples: list[str]) -> None:
        vecs = self.embedder.embed(examples)
        self.clusters.setdefault(name, []).extend(zip(examples, vecs))

    def load_dir(self, path: str | Path) -> "SemanticIndex":
        for f in sorted(Path(path).glob("*.y*ml")):
            data = yaml.safe_load(f.read_text())
            self.add_cluster(data["name"], data["examples"])
        return self

    def score(self, cluster: str, text: str) -> tuple[float, str]:
        if cluster not in self.clusters:
            raise KeyError(f"unknown semantic cluster {cluster!r}")
        # Score each line/sentence separately so a short injection hidden in a
        # long document is not diluted by the surrounding benign text.
        chunks = [c for c in re.split(r"[\n.!?]+", text) if len(c.strip()) > 8] or [text]
        chunks = chunks[:64]
        vecs = self.embedder.embed(chunks)
        best, best_ex = 0.0, ""
        for v in vecs:
            for ex, ev in self.clusters[cluster]:
                s = _cos(v, ev)
                if s > best:
                    best, best_ex = s, ex
        return best, best_ex


@dataclass
class SemanticMatcher:
    cluster: str
    threshold: float = 0.6
    gray_band: float = 0.15          # scores in [threshold-gray_band, threshold) are "uncertain"
    tier: str = "semantic"
    name: str = "semantic"

    def match(self, text: str, ctx: MatchContext) -> MatchResult:
        if ctx.semantic_index is None:
            return MatchResult(False, 0.0, self.tier, self.name, detail="no semantic index loaded")
        score, example = ctx.semantic_index.score(self.cluster, text)
        hit = score >= self.threshold
        uncertain = not hit and score >= self.threshold - self.gray_band
        return MatchResult(
            hit, score, self.tier, f"{self.name}:{self.cluster}",
            detail=f"similarity {score:.2f} to {example[:60]!r}",
            uncertain=uncertain,
        )
