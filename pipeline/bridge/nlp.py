"""NLP text-similarity fallback for findings the authoritative chain missed (O5).

Embeds the weakness text and every ATT&CK technique description with a
sentence-transformer and maps by cosine similarity. Deterministic: pinned model,
eval mode, sorted outputs.
"""

from __future__ import annotations

import torch
from sentence_transformers import SentenceTransformer, util

from pipeline.bridge.confidence import nlp_confidence
from pipeline.data.loaders import Catalogues
from pipeline.schema import Detection, Finding, Mapping

DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


class NlpMapper:
    """Text-similarity mapper. Build once (loads model + embeds corpus), reuse."""

    def __init__(
        self,
        catalogues: Catalogues,
        model_name: str = DEFAULT_MODEL,
        top_k: int = 3,
        threshold: float = 0.40,
    ) -> None:
        self.catalogues = catalogues
        self.model_name = model_name
        self.top_k = top_k
        self.threshold = threshold
        self.model = SentenceTransformer(model_name)
        self.model.eval()

        techniques = catalogues.attack.techniques()
        self.technique_ids = [t.technique_id for t in techniques]
        corpus = [f"{t.name}. {t.description}" for t in techniques]
        self.corpus_embeddings = self.model.encode(
            corpus, convert_to_tensor=True, normalize_embeddings=True
        )

    def _query(self, finding: Finding) -> str:
        parts: list[str] = []
        for cwe in finding.cwe_ids:
            entry = self.catalogues.cwe.get(cwe)
            if entry:
                parts.append(f"{entry.name}. {entry.description}")
        parts.append(finding.message)
        return " ".join(p for p in parts if p).strip()

    def map_finding(self, finding: Finding) -> list[Mapping]:
        """Map a finding to ATT&CK technique(s) by text similarity."""
        query = self._query(finding)
        if not query:
            return []

        query_embedding = self.model.encode(
            query, convert_to_tensor=True, normalize_embeddings=True
        )
        scores = util.cos_sim(query_embedding, self.corpus_embeddings)[0]
        k = min(self.top_k, len(self.technique_ids))
        top = torch.topk(scores, k=k)
        matches = [
            (self.technique_ids[i], float(scores[i])) for i in top.indices.tolist()
        ]
        matches.sort(key=lambda m: (-m[1], m[0]))
        top_matches = [
            {"technique_id": tid, "score": round(score, 4)} for tid, score in matches
        ]

        source_cwe = finding.cwe_ids[0] if finding.cwe_ids else ""
        mappings: list[Mapping] = []
        for tid, score in matches:
            if score < self.threshold:
                continue
            mappings.append(
                Mapping(
                    finding_id=finding.finding_id,
                    cwe=source_cwe,
                    capec_ids=[],
                    technique_ids=[tid],
                    method="nlp",
                    chain_evidence={
                        "query": query,
                        "model": self.model_name,
                        "score": round(score, 4),
                        "threshold": self.threshold,
                        "top_matches": top_matches,
                    },
                    confidence=nlp_confidence(score),
                    detection=Detection(),
                )
            )
        return mappings
