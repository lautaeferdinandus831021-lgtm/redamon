"""Hybrid recall: BM25 keyword + entity/graph fusion.

`search` is the `memory_recall` path (keyword, works with zero configuration).
`smart_search` is `memory_smart_search`: it fuses the keyword ranking with
structural evidence - shared entities, and memories one graph hop away from a
keyword match - which is how a question worded differently from the stored
memory still finds it without needing embeddings.

No embedding model is pulled in: adding a vector dependency would mean a new
package in a baked image (and a model download at runtime). BM25 + the entity
graph is the keyless mode agentmemory itself falls back to.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

from .models import STATE_ACTIVE, MemoryRecord

_TOKEN = re.compile(r"[a-z0-9_]{2,}")

# Words that carry no discriminating power in this domain: every memory is
# about a target, a scan or a tool, so those tokens must not drive ranking.
_STOPWORDS = frozenset({
    "the", "and", "for", "with", "that", "this", "from", "was", "were", "are",
    "has", "have", "had", "not", "but", "you", "your", "its", "it's", "into",
    "out", "on", "in", "of", "to", "is", "at", "as", "be", "by", "or", "an",
    "tool", "target", "scan", "found", "using", "used", "run", "ran", "get",
})

K1 = 1.5
B = 0.75


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall((text or "").lower()) if t not in _STOPWORDS]


@dataclass
class ScoredMemory:
    record: MemoryRecord
    score: float
    keyword: float = 0.0
    graph: float = 0.0
    why: str = ""


def bm25(
    query_tokens: Sequence[str],
    docs: dict[str, list[str]],
) -> dict[str, float]:
    """Okapi BM25 over an in-process corpus keyed by memory id.

    Returns 0.0-scored entries omitted; the caller merges with other signals.
    """
    q = [t for t in query_tokens if t]
    if not q or not docs:
        return {}
    n_docs = len(docs)
    lengths = {k: max(1, len(v)) for k, v in docs.items()}
    avgdl = sum(lengths.values()) / n_docs

    df: dict[str, int] = {}
    for tokens in docs.values():
        for term in set(tokens):
            df[term] = df.get(term, 0) + 1

    scores: dict[str, float] = {}
    for doc_id, tokens in docs.items():
        if not tokens:
            continue
        tf: dict[str, int] = {}
        for term in tokens:
            tf[term] = tf.get(term, 0) + 1
        score = 0.0
        for term in q:
            f = tf.get(term, 0)
            if not f:
                continue
            idf = math.log(1.0 + (n_docs - df.get(term, 0) + 0.5) / (df.get(term, 0) + 0.5))
            denom = f + K1 * (1.0 - B + B * (lengths[doc_id] / avgdl))
            score += idf * (f * (K1 + 1.0)) / denom if denom else 0.0
        if score > 0:
            scores[doc_id] = score
    return scores


def _normalize(scores: dict[str, float]) -> dict[str, float]:
    if not scores:
        return {}
    top = max(scores.values())
    if top <= 0:
        return {}
    return {k: v / top for k, v in scores.items()}


def _entity_overlap(query_entities: Iterable[str], record: MemoryRecord) -> float:
    want = {e.lower() for e in query_entities if e}
    if not want:
        return 0.0
    have = {e.lower() for e in record.entities}
    if not have:
        return 0.0
    return len(want & have) / len(want)


def search(
    records: Iterable[MemoryRecord],
    query: str = "",
    *,
    limit: int = 8,
    entities: Optional[Sequence[str]] = None,
    kinds: Optional[Sequence[str]] = None,
    min_confidence: float = 0.0,
    include_archived: bool = False,
) -> list[ScoredMemory]:
    """Keyword recall, ranked by BM25 x confidence.

    Confidence multiplies the text score rather than adding to it, so a
    high-confidence memory that does not match the query still does not outrank
    a matching one.
    """
    pool = [
        r for r in records
        if (include_archived or r.state != "archived")
        and (not kinds or r.kind in kinds)
        and r.confidence >= min_confidence
    ]
    if not pool:
        return []

    if not (query or "").strip():
        # No query = "what do you know?", answered by confidence, but only
        # memories that ever earned a place (active) or are fresh.
        ordered = sorted(pool, key=lambda r: (-r.confidence, -r.updated_at))
        return [
            ScoredMemory(record=r, score=r.confidence, why="ranked by confidence")
            for r in ordered[:limit]
        ]

    docs = {r.memory_id: tokenize(r.text) + tokenize(" ".join(r.tags)) for r in pool}
    raw = bm25(tokenize(query), docs)
    if not raw:
        return []
    norm = _normalize(raw)
    by_id = {r.memory_id: r for r in pool}

    out: list[ScoredMemory] = []
    for mem_id, kw in norm.items():
        record = by_id[mem_id]
        score = kw * (0.35 + 0.65 * record.confidence)
        out.append(ScoredMemory(
            record=record,
            score=score,
            keyword=kw,
            why=f"keyword {kw:.2f} x conf {record.confidence:.2f}",
        ))
    out.sort(key=lambda s: (-s.score, -s.record.confidence))
    return out[:limit]


def smart_search(
    records: Iterable[MemoryRecord],
    query: str = "",
    *,
    limit: int = 8,
    entities: Optional[Sequence[str]] = None,
    neighbors: Optional[dict[str, list[tuple[str, float]]]] = None,
    kinds: Optional[Sequence[str]] = None,
    min_confidence: float = 0.0,
    graph_weight: float = 0.3,
    entity_weight: float = 0.25,
    include_archived: bool = False,
) -> list[ScoredMemory]:
    """Fused recall: keyword + entity overlap + one-hop graph expansion.

    A memory reachable through the knowledge graph from a keyword hit is a
    candidate even when its own text shares no token with the query - that is
    the point of keeping the edges.
    """
    pool = [
        r for r in records
        if (include_archived or r.state != "archived")
        and (not kinds or r.kind in kinds)
        and r.confidence >= min_confidence
    ]
    if not pool:
        return []
    by_id = {r.memory_id: r for r in pool}

    docs = {r.memory_id: tokenize(r.text) + tokenize(" ".join(r.tags)) for r in pool}
    kw_scores = _normalize(bm25(tokenize(query), docs)) if (query or "").strip() else {}

    # Entity-only matching: the query may name a host or an endpoint that no
    # adjacent sentence repeats.
    ent_scores = {r.memory_id: _entity_overlap(entities or (), r) for r in pool}
    ent_scores = {k: v for k, v in ent_scores.items() if v > 0}

    hops: dict[str, float] = {}
    adjacency = neighbors or {}
    for seed_id, score in kw_scores.items():
        for (other, weight) in adjacency.get(seed_id, ()):
            if other not in by_id:
                continue
            hops[other] = max(hops.get(other, 0.0), score * min(1.0, weight / 2.0))

    # Seeds start ACTIVE-state bonus-free; only the fused score decides.
    candidates = set(kw_scores) | set(ent_scores) | set(hops)
    if not candidates:
        return []
    hop_norm = _normalize(hops)

    out: list[ScoredMemory] = []
    for mem_id in candidates:
        record = by_id[mem_id]
        kw = kw_scores.get(mem_id, 0.0)
        ent = ent_scores.get(mem_id, 0.0)
        hop = hop_norm.get(mem_id, 0.0)
        score = (kw + entity_weight * ent + graph_weight * hop) * (0.35 + 0.65 * record.confidence)
        bits = []
        if kw:
            bits.append(f"keyword {kw:.2f}")
        if ent:
            bits.append(f"entity {ent:.2f}")
        if hop:
            bits.append(f"graph {hop:.2f}")
        out.append(ScoredMemory(
            record=record,
            score=score,
            keyword=kw,
            graph=hop,
            why=" + ".join(bits) + f" x conf {record.confidence:.2f}",
        ))
    # Tie-break toward active memories: same score, the promoted one wins.
    out.sort(key=lambda s: (-s.score, s.record.state != STATE_ACTIVE, -s.record.confidence))
    return out[:limit]
