"""
ThreatGraphRAG - High-Performance Semantic & Subgraph Cache Manager
Provides in-memory LRU caching with cryptographic fingerprinting,
TTL expiration, and SOC metric telemetry for sub-10ms query resolution.
"""

import time
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple, List
from collections import OrderedDict

logger = logging.getLogger(__name__)

class SemanticCache:
    def __init__(self, capacity: int = 250, default_ttl_seconds: int = 3600):
        self.capacity = capacity
        self.default_ttl = default_ttl_seconds
        self.cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self.hits: int = 0
        self.misses: int = 0
        self.tokens_saved_estimate: int = 0
        self.latency_saved_ms_estimate: float = 0.0

    def _normalize_text(self, text: str) -> str:
        """Strips punctuation, excessive whitespace, and lowercases."""
        import re
        clean = re.sub(r"[^\w\s]", " ", text.lower())
        return " ".join(clean.split())

    def generate_fingerprint(self, query: str, facts: Optional[List[str]] = None) -> str:
        """
        Creates a deterministic hash based on normalized query intent
        and sorted subgraph evidence facts.
        """
        norm_q = self._normalize_text(query)
        facts_str = "|".join(sorted(facts)) if facts else ""
        raw_payload = f"{norm_q}###{facts_str}"
        return hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

    def get(self, query: str, facts: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieves cached response if present and not expired.
        """
        fp = self.generate_fingerprint(query, facts)
        if fp not in self.cache:
            self.misses += 1
            return None

        entry = self.cache[fp]
        now = time.time()
        
        # Check TTL
        if now > entry["expires_at"]:
            del self.cache[fp]
            self.misses += 1
            return None

        # Move to end for LRU refresh
        self.cache.move_to_end(fp)
        self.hits += 1
        
        # Update savings metrics
        report_text = entry.get("report", "")
        # Estimate ~1 token per 4 characters in report + prompt
        tokens = len(report_text) // 4 + 400
        self.tokens_saved_estimate += tokens
        self.latency_saved_ms_estimate += 3200.0  # Avg saved Gemini roundtrip ~3.2s
        
        return entry

    def set(self, query: str, report: str, facts: List[str], metadata: Optional[Dict[str, Any]] = None, ttl_seconds: Optional[int] = None):
        """
        Stores synthesized report and subgraph in LRU cache with expiration.
        """
        fp = self.generate_fingerprint(query, facts)
        ttl = ttl_seconds or self.default_ttl
        now = time.time()
        
        if fp in self.cache:
            self.cache.move_to_end(fp)
        else:
            if len(self.cache) >= self.capacity:
                # Evict oldest item
                self.cache.popitem(last=False)
                
        self.cache[fp] = {
            "query": query,
            "report": report,
            "facts": facts,
            "metadata": metadata or {},
            "created_at": now,
            "expires_at": now + ttl
        }

    def get_stats(self) -> Dict[str, Any]:
        """Returns live cache health and telemetry."""
        total_requests = self.hits + self.misses
        hit_ratio = (self.hits / total_requests * 100.0) if total_requests > 0 else 0.0
        return {
            "total_entries": len(self.cache),
            "capacity": self.capacity,
            "hits": self.hits,
            "misses": self.misses,
            "hit_ratio_percent": round(hit_ratio, 1),
            "estimated_tokens_saved": self.tokens_saved_estimate,
            "estimated_latency_saved_seconds": round(self.latency_saved_ms_estimate / 1000.0, 1)
        }

    def clear(self):
        """Purges all cached entries."""
        self.cache.clear()
        self.hits = 0
        self.misses = 0

# Singleton global instance
threat_cache = SemanticCache(capacity=300, default_ttl_seconds=7200)
