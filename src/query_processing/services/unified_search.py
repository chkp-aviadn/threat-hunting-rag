"""
Unified Search Service for Threat Hunting RAG System

This service integrates the complete data flow:
CSV File (emails.csv) → VectorIndexBuilder.build_index() → ChromaDB Vector Database → Semantic Search

Provides a single interface for the RAG pipeline with proper ChromaDB integration.
"""

import logging
import time
import os  # Added missing import for environment variable access
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path
import pandas as pd

from data_preparation.schemas.email import Email
from data_preparation.embeddings.index_builder import VectorIndexBuilder

try:
    # Optional import: new unified vector backend provider (Chroma + fallback)
    from shared.vector.provider import get_vector_backend  # type: ignore
except Exception:  # pragma: no cover - provider is optional/fails gracefully
    get_vector_backend = None  # type: ignore
from query_processing.models.search import SearchQuery, SearchResults, QueryResult
from shared.enums import SearchMethod, ThreatLevel

logger = logging.getLogger(__name__)


class UnifiedSearchService:
    """
    Unified search service that handles the complete flow:
    CSV → Vector Index → ChromaDB → Semantic Search

    Features:
    - Automatic dataset loading from CSV
    - Vector index building with ChromaDB
    - Hybrid search (keyword + semantic)
    - Result formatting for RAG pipeline
    """

    def __init__(
        self,
        csv_path: str = "data/emails.csv",
        chroma_path: str = "data/chroma",
        collection_name: str = "threat_hunting_emails",
        use_provider: bool = True,
        provider_backfill: bool = False,
    ):
        """
        Initialize the unified search service.

        Args:
            csv_path: Path to the email CSV file
            csv_path: Path to ChromaDB storage
            collection_name: ChromaDB collection name
        """
        self.csv_path = Path(csv_path)
        self.chroma_path = Path(chroma_path)
        self.collection_name = collection_name

        self.vector_builder = VectorIndexBuilder(
            db_path=str(chroma_path), collection_name=collection_name
        )

        # Provider-backed collection/client (Chroma or fallback) if available
        self._vector_client = None
        self._collection = None
        self._diagnostics: Dict[str, bool] = {}
        if use_provider and get_vector_backend:
            try:
                client, collection, diagnostics = get_vector_backend(
                    collection_name=collection_name, backfill=provider_backfill
                )
                self._vector_client = client
                self._collection = collection
                self._diagnostics = diagnostics

                # If collection already has data, wire it into existing builder to reuse search logic
                existing = 0
                try:
                    existing = collection.count()
                except Exception:
                    pass
                if existing > 0:
                    self.vector_builder.client = client
                    self.vector_builder.collection = collection
                    self._index_ready = True
                    logger.info(
                        f"✅ Provider supplied existing collection with {existing} vectors; skipping rebuild"
                    )
                else:
                    logger.info(
                        "Provider collection empty; will trigger index build on first search"
                    )
            except Exception as e:  # pragma: no cover - defensive
                logger.warning(
                    f"Vector provider initialization failed, falling back to legacy builder path: {e}"
                )
        else:
            if use_provider:
                logger.info(
                    "Vector provider requested but not available; using legacy builder path."
                )

        self._emails_cache = None
        self._index_ready = False
        # Integrated QueryResultsCache (replaces legacy in-memory dict cache)
        from shared.cache.query_cache import get_query_cache

        self._results_cache = get_query_cache()
        self._last_cache_hit: bool = False

        logger.info("Initialized UnifiedSearchService")
        logger.info(f"  CSV path: {self.csv_path}")
        logger.info(f"  ChromaDB path: {self.chroma_path}")
        logger.info(f"  Collection: {self.collection_name} (canonical)")

    def ensure_index_ready(self) -> bool:
        """
        Ensure the vector index is built and ready for search.

        This implements the complete flow:
        1. Load emails from CSV
        2. Build vector index with ChromaDB
        3. Prepare for semantic search

        Returns:
            True if index is ready, False otherwise
        """
        if self._index_ready:
            return True

        try:
            # Step 1: Check if CSV exists
            if not self.csv_path.exists():
                logger.error(f"Email CSV not found at {self.csv_path}")
                return False

            # Step 2: Check if provider-sourced collection already loaded
            if self._collection is not None:
                try:
                    count = self._collection.count()
                    if count > 0:
                        logger.info(f"✅ Provider collection already populated with {count} emails")
                        self.vector_builder.client = (
                            self._vector_client or self.vector_builder.client
                        )
                        self.vector_builder.collection = self._collection
                        self._index_ready = True
                        return True
                except Exception as e:
                    logger.debug(f"Provider collection count failed: {e}")

            # Step 2b: Legacy path: check disk persistence
            if self.chroma_path.exists() and self._collection is None:
                try:
                    collection = self.vector_builder._get_collection()
                    count = collection.count()
                    if count > 0:
                        logger.info(
                            f"✅ Found existing vector index with {count} emails (legacy builder)"
                        )
                        self._index_ready = True
                        return True
                    else:
                        logger.info("Vector collection exists but is empty, rebuilding...")
                except Exception as e:
                    logger.warning(f"Vector index check failed: {e}, rebuilding...")

            # Step 3: Load emails from CSV
            logger.info("📊 Loading emails from CSV...")
            emails_df = pd.read_csv(self.csv_path)
            emails = emails_df.to_dict("records")

            logger.info(f"✅ Loaded {len(emails)} emails from CSV")

            # Step 4: Build vector index with ChromaDB
            logger.info("🔍 Building vector index via builder (Chroma or fallback)...")
            build_stats = self.vector_builder.build_index(emails)

            logger.info("✅ Vector index built successfully!")
            logger.info(f"   Total emails indexed: {build_stats['total_emails']}")
            logger.info(f"   Build time: {build_stats['build_time_seconds']:.1f}s")
            logger.info(f"   Embedding dimension: {build_stats['embedding_dimension']}")
            logger.info(f"   ChromaDB path: {build_stats['db_path']}")

            # Cache emails for quick access
            self._emails_cache = {f"email_{i}": emails[i] for i in range(len(emails))}
            self._index_ready = True

            return True

        except Exception as e:
            logger.error(f"Failed to ensure index ready: {e}")
            return False

    def search(self, query: SearchQuery) -> SearchResults:
        """
        Search emails using the complete ChromaDB pipeline.

        Args:
            query: Search query with text and parameters

        Returns:
            Search results with threat analysis
        """
        start_time = time.time()
        self._last_cache_hit = False

        # Attempt external QueryResultsCache fast path (stores serialized payloads)
        cache_payload = None
        try:
            cache_payload = self._results_cache.get(
                query.text,
                method=query.method.value,
                limit=query.limit,
                threshold=query.threat_threshold,
            )
        except Exception as e:
            logger.debug(f"QueryResultsCache get failed (non-fatal): {e}")
        if cache_payload:
            self._last_cache_hit = True
            # Rehydrate cached dict payload back into SearchResults
            try:
                results_list = []
                from threat_analysis.models.threat import ThreatFeatures

                for item in cache_payload.get("results", []):
                    email = Email(
                        id=item.get("email_id", ""),
                        sender=item.get("sender", "unknown@example.com"),
                        recipient=item.get("recipient", "unknown@example.com"),
                        subject=item.get("subject", ""),
                        body=item.get("body", ""),
                        timestamp=item.get("timestamp", datetime.utcnow().isoformat()),
                    )
                    mock_features = ThreatFeatures()
                    qr = QueryResult(
                        email=email,
                        rank=item.get("rank", 0),
                        search_score=item.get("search_score", 0.0),
                        threat_score=item.get("threat_score", 0.0),
                        threat_level=self._determine_threat_level(item.get("threat_score", 0.0)),
                        confidence=item.get("confidence", 0.0),
                        keyword_matches=item.get("keyword_matches", []),
                        semantic_similarity=item.get("semantic_similarity"),
                        features=mock_features,
                        explanation=item.get("explanation", ""),
                    )
                    results_list.append(qr)
                processing_time_ms = cache_payload.get("processing_time_ms", 0)
                return SearchResults(
                    query=query,
                    results=results_list,
                    total_found=len(results_list),
                    processing_time_ms=processing_time_ms,
                )
            except Exception as e:
                logger.debug(f"Failed to rehydrate cached results, proceeding to fresh search: {e}")

        try:
            # Ensure index is ready (may trigger build if empty)
            if not self.ensure_index_ready():
                logger.error("Search index not ready")
                return self._empty_results(query, start_time)

            n_results = query.limit or 10

            # Fast path: provider-backed collection present (Chroma or fallback) → direct query
            if self._collection is not None and (
                self.vector_builder.collection is self._collection
                or self.vector_builder.collection is None
            ):
                # Debug provider & builder collection counts
                try:
                    prov_cnt = self._collection.count()
                except Exception:
                    prov_cnt = "ERR"
                try:
                    bldr_cnt = (
                        self.vector_builder.collection.count()
                        if getattr(self.vector_builder, "collection", None)
                        else "NONE"
                    )
                except Exception:
                    bldr_cnt = "ERR"
                logger.debug(
                    f"[DEBUG SEARCH] provider_count={prov_cnt} builder_count={bldr_cnt} index_ready={self._index_ready}"
                )
                # Provider-backed fast path
                try:
                    query_embedding = self.vector_builder.embedding_generator.embed_text(query.text)
                    backend_collection = self._collection
                    chroma_results = backend_collection.query(
                        query_embeddings=[query_embedding.tolist()],
                        n_results=n_results,
                        include=["documents", "metadatas", "distances"],
                    )
                    logger.debug("Executed direct collection.query without builder wrapper")
                except Exception as e:
                    logger.warning(
                        f"Direct provider query failed ({e}); falling back to builder.search"
                    )
                    chroma_results = {}

                # Fallback if provider path returned empty payload (ids missing or empty)
                if (
                    not chroma_results
                    or not chroma_results.get("ids")
                    or not chroma_results["ids"][0]
                ):
                    logger.debug(
                        f"[DEBUG SEARCH] Provider returned empty result set (ids missing) for query='{query.text}'"
                    )
                    logger.debug(
                        "Provider fast path returned zero results; invoking builder.search fallback"
                    )
                    try:
                        search_results = self.vector_builder.search(
                            query_text=query.text, n_results=n_results
                        )
                        chroma_results = (
                            search_results.get("results", {})
                            if isinstance(search_results, dict)
                            else search_results
                        )
                    except Exception as e:
                        logger.warning(f"Builder fallback also failed: {e}")
                        chroma_results = {}
                else:
                    # If provider path gave results, optionally enrich with builder search if we want hybrid merging
                    try:
                        builder_results = self.vector_builder.search(
                            query_text=query.text, n_results=n_results
                        )
                        builder_payload = (
                            builder_results.get("results", {})
                            if isinstance(builder_results, dict)
                            else builder_results
                        )
                        # naive merge: append new ids not already present
                        if builder_payload.get("ids") and builder_payload["ids"][0]:
                            existing_ids = set(chroma_results.get("ids", [[]])[0])
                            builder_ids = builder_payload["ids"][0]
                            # Append up to remaining slots
                            for idx, bid in enumerate(builder_ids):
                                if (
                                    bid not in existing_ids
                                    and len(chroma_results["ids"][0]) < n_results
                                ):
                                    chroma_results["ids"][0].append(bid)
                                    chroma_results["documents"][0].append(
                                        builder_payload["documents"][0][idx]
                                    )
                                    chroma_results["metadatas"][0].append(
                                        builder_payload["metadatas"][0][idx]
                                    )
                                    chroma_results["distances"][0].append(
                                        builder_payload["distances"][0][idx]
                                    )
                    except Exception as e:
                        logger.debug(f"Optional builder merge skipped: {e}")
            else:
                # Legacy path: use builder wrapper
                search_results = self.vector_builder.search(
                    query_text=query.text, n_results=n_results
                )
                chroma_results = (
                    search_results.get("results", {})
                    if isinstance(search_results, dict)
                    else search_results
                )

            # Convert results
            if isinstance(chroma_results, dict):
                try:
                    ids_len = (
                        len(chroma_results.get("ids", [[]])[0]) if chroma_results.get("ids") else 0
                    )
                except Exception:
                    ids_len = "ERR"
                logger.debug(
                    f"[DEBUG SEARCH] Pre-convert ids_len={ids_len} keys={list(chroma_results.keys())}"
                )
            query_results = self._convert_chroma_results(chroma_results, query)

            # Processing time
            end_time = time.time()
            processing_time_ms = int((end_time - start_time) * 1000)

            results = SearchResults(
                query=query,
                results=query_results,
                total_found=len(query_results),
                processing_time_ms=processing_time_ms,
            )

            # Store in external cache (serialize lightweight dict payload)
            if len(query_results) > 0:
                try:
                    payload = {
                        "results": [
                            {
                                "rank": r.rank,
                                "email_id": r.email.id,
                                "sender": r.email.sender,
                                "recipient": r.email.recipient,
                                "subject": r.email.subject,
                                "body": r.email.body[:300],
                                "timestamp": (
                                    r.email.timestamp.isoformat()
                                    if hasattr(r.email.timestamp, "isoformat")
                                    else str(r.email.timestamp)
                                ),
                                "threat_score": r.threat_score,
                                "confidence": r.confidence,
                                "search_score": r.search_score,
                                "threat_level": (
                                    r.threat_level.value
                                    if hasattr(r.threat_level, "value")
                                    else r.threat_level
                                ),
                                "keyword_matches": r.keyword_matches,
                                "semantic_similarity": r.semantic_similarity,
                                "explanation": r.explanation,
                            }
                            for r in query_results
                        ],
                        "processing_time_ms": processing_time_ms,
                    }
                    self._results_cache.put(
                        query.text,
                        payload,
                        method=query.method.value,
                        limit=query.limit,
                        threshold=query.threat_threshold,
                    )
                except Exception as e:
                    logger.debug(f"QueryResultsCache put failed (non-fatal): {e}")

            logger.info(f"Search completed: {len(query_results)} results in {processing_time_ms}ms")
            return results

        except Exception as e:
            logger.error(f"Search error: {e}")
            return self._empty_results(query, start_time)

    def _convert_chroma_results(
        self, chroma_results: Dict[str, Any], query: SearchQuery
    ) -> List[QueryResult]:
        """Convert ChromaDB search results to our QueryResult format."""
        query_results = []

        # ChromaDB returns results in this format:
        # {'ids': [[...]], 'distances': [[...]], 'metadatas': [[...]], 'documents': [[...]]}

        if not chroma_results.get("ids") or not chroma_results["ids"][0]:
            return []

        ids = chroma_results["ids"][0]
        distances = chroma_results.get("distances", [None])[0] or []
        metadatas = chroma_results.get("metadatas", [None])[0] or []
        documents = chroma_results.get("documents", [None])[0] or []

        for i, email_id in enumerate(ids):
            try:
                # Get metadata
                metadata = metadatas[i] if i < len(metadatas) else {}
                document = documents[i] if i < len(documents) else ""
                distance = distances[i] if i < len(distances) else 1.0

                # Convert distance to similarity score (lower distance = higher similarity)
                similarity_score = max(0.0, 1.0 - distance)

                # Create Email object from metadata with validation fixes
                recipient = metadata.get("recipient", "")
                if not recipient or "@" not in recipient:
                    recipient = "unknown@example.com"

                sender = metadata.get("sender", "")
                if not sender or "@" not in sender:
                    sender = "unknown@example.com"

                # Parse attachments from metadata
                attachments_list = []
                attachments_str = metadata.get("attachments", "")
                if attachments_str and attachments_str.strip():
                    # Split by comma if multiple attachments
                    attachment_files = [f.strip() for f in attachments_str.split(',') if f.strip()]
                    for filename in attachment_files:
                        from data_preparation.schemas.email import EmailAttachment
                        # Create EmailAttachment object
                        attachments_list.append(EmailAttachment(
                            filename=filename,
                            size=metadata.get("attachment_size", 1024)  # Default size if not available
                        ))

                email = Email(
                    id=metadata.get("email_id", email_id),
                    sender=sender,
                    recipient=recipient,
                    subject=metadata.get("subject", ""),
                    body=self._extract_body_from_document(document, metadata.get("subject", "")),
                    timestamp=metadata.get("timestamp", ""),
                    category=metadata.get("category", "unknown"),
                    is_phishing=metadata.get("is_phishing", False),
                    confidence_score=metadata.get("confidence_score", 0.0),
                    attachments=attachments_list,
                    attachment_count=len(attachments_list)
                )

                # Calculate threat score based on similarity and metadata
                threat_score = self._calculate_threat_score(email, similarity_score)
                threat_level = self._determine_threat_level(threat_score)

                # Keyword matching (simple token overlap) if hybrid or keyword method
                keyword_matches: List[str] = []
                if query.method in (SearchMethod.HYBRID, SearchMethod.KEYWORD):
                    keyword_matches = self._extract_keyword_matches(
                        query.text, email.subject + " " + email.body
                    )
                    # Add lightweight keyword boost to threat_score (bounded)
                    if keyword_matches:
                        threat_score = min(1.0, threat_score + 0.05 * len(keyword_matches))
                        threat_level = self._determine_threat_level(threat_score)
                
                # ATTACHMENT QUERY BOOSTING: Boost emails with attachments for attachment-related queries
                attachment_query_terms = ["attachment", "exe", "scr", "js", "file", "zip", "docm", "malware"]
                query_lower = query.text.lower()
                if any(term in query_lower for term in attachment_query_terms):
                    attachment_count = metadata.get("attachment_count", 0)
                    attachments = metadata.get("attachments", "")
                    if attachment_count > 0 or attachments:
                        # Boost threat score for attachment queries when email has attachments
                        attachment_boost = 0.15
                        # Extra boost for executable attachments
                        if attachments and any(ext in attachments.lower() for ext in [".exe", ".scr", ".js", ".vbs"]):
                            attachment_boost = 0.25
                        threat_score = min(1.0, threat_score + attachment_boost)
                        threat_level = self._determine_threat_level(threat_score)
                        logger.debug(f"Attachment query boost applied: +{attachment_boost} for {email.id}")

                # Create mock ThreatFeatures for now (in production this would be real analysis)
                from threat_analysis.models.threat import ThreatFeatures

                mock_features = ThreatFeatures(
                    sender_reputation=0.5,
                    domain_reputation=0.5,
                    urgency_indicators=0.3,
                    financial_keywords=0.2,
                    suspicious_attachments=0.0,
                    phishing_signals=0.1,
                )

                # Create QueryResult
                result = QueryResult(
                    email=email,
                    rank=i + 1,  # 1-based ranking
                    search_score=similarity_score,
                    threat_score=threat_score,
                    threat_level=threat_level,
                    confidence=similarity_score,
                    keyword_matches=keyword_matches,
                    features=mock_features,
                    explanation=self._build_explanation(
                        similarity_score, keyword_matches, threat_score, threat_level, email
                    ),
                )

                query_results.append(result)

            except Exception as e:
                logger.error(f"Error converting result {i}: {e}")
                continue

        return query_results

    def _extract_keyword_matches(self, query_text: str, target_text: str) -> List[str]:
        """Return list of distinct query tokens found in target_text.

        Tokenization: lowercase, alphanumeric word boundaries, ignore stop words.
        """
        import re

        stop_words = {
            "the",
            "and",
            "or",
            "a",
            "an",
            "to",
            "for",
            "of",
            "in",
            "on",
            "at",
            "by",
            "with",
            "is",
            "be",
            "this",
            "that",
        }
        token_pattern = re.compile(r"[a-zA-Z0-9]{3,}")
        q_tokens = {
            t.lower() for t in token_pattern.findall(query_text) if t.lower() not in stop_words
        }
        if not q_tokens:
            return []
        tgt_tokens = {t.lower() for t in token_pattern.findall(target_text)}
        matches = sorted(q_tokens.intersection(tgt_tokens))
        return matches[:15]  # cap

    def _build_explanation(
        self,
        similarity: float,
        keywords: List[str],
        threat_score: float,
        level: ThreatLevel,
        email: Email,
    ) -> str:
        """Construct human-readable explanation with contributing factors."""
        parts = [
            f"Similarity={similarity:.3f}",
            f"ThreatScore={threat_score:.3f}",
            f"Level={level.value}",
        ]
        if keywords:
            parts.append(f"Keywords={'|'.join(keywords)}")
        # Simple heuristic contributions
        urgency_terms = [
            k
            for k in ["urgent", "immediate", "action", "verify", "suspend"]
            if k in (email.subject + " " + email.body).lower()
        ]
        if urgency_terms:
            parts.append(f"UrgencySignals={'|'.join(urgency_terms)}")
        if email.is_phishing:
            parts.append("Label=PhishingSample")
        return "; ".join(parts)

    def _extract_body_from_document(self, document: str, subject: str) -> str:
        """Extract email body from combined document text."""
        if not document:
            return ""

        # Remove subject from document to get body
        if subject and document.startswith(subject):
            body = document[len(subject) :].strip()
            if body.startswith("\n\n"):
                body = body[2:]
            return body

        return document

    def _calculate_threat_score(self, email: Email, similarity_score: float) -> float:
        """Calculate threat score based on email content and similarity."""
        base_score = similarity_score * 0.6  # Weight similarity

        # Add threat indicators
        threat_indicators = 0

        # Check for phishing classification
        if email.is_phishing:
            threat_indicators += 0.3

        # Check for urgent keywords
        urgent_keywords = ["urgent", "immediate", "action required", "verify", "suspend", "expire"]
        text_lower = (email.subject + " " + email.body).lower()

        for keyword in urgent_keywords:
            if keyword in text_lower:
                threat_indicators += 0.1
                break

        # Check for suspicious domains
        if "@" in email.sender:
            domain = email.sender.split("@")[1].lower()
            suspicious_domains = ["temp", "disposable", "fake", "10minute"]

            for suspicious in suspicious_domains:
                if suspicious in domain:
                    threat_indicators += 0.2
                    break

        final_score = min(1.0, base_score + threat_indicators)
        return final_score

    def _determine_threat_level(self, threat_score: float) -> ThreatLevel:
        """Determine threat level from threat score."""
        if threat_score >= 0.8:
            return ThreatLevel.CRITICAL
        elif threat_score >= 0.6:
            return ThreatLevel.HIGH
        elif threat_score >= 0.4:
            return ThreatLevel.MEDIUM
        elif threat_score >= 0.2:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.NEGLIGIBLE

    def _empty_results(self, query: SearchQuery, start_time: float) -> SearchResults:
        """Create empty search results for error cases."""
        end_time = time.time()
        processing_time_ms = int((end_time - start_time) * 1000)

        return SearchResults(
            query=query, results=[], total_found=0, processing_time_ms=processing_time_ms
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get search service statistics."""
        try:
            if not self._index_ready:
                self.ensure_index_ready()

            # Prefer provider collection if available
            if self._collection is not None:
                collection = self._collection
            else:
                collection = self.vector_builder._get_collection()
            try:
                count = collection.count()
            except Exception:
                count = 0

            # Get sample of metadata for analysis
            if count > 0:
                sample_results = collection.get(limit=min(100, count), include=["metadatas"])
                metadatas = sample_results.get("metadatas", [])

                phishing_count = sum(1 for m in metadatas if m.get("is_phishing", False))
                legitimate_count = count - phishing_count

                base = {
                    "total_emails": count,
                    "phishing_emails": phishing_count,
                    "legitimate_emails": legitimate_count,
                    "phishing_percentage": (phishing_count / count * 100) if count > 0 else 0,
                    "index_ready": self._index_ready,
                    "csv_path": str(self.csv_path),
                    "chroma_path": str(self.chroma_path),
                    "collection_name": self.collection_name,
                }
                if self._diagnostics:
                    base["vector_backend_diagnostics"] = self._diagnostics
                return base
            else:
                return {"total_emails": 0, "index_ready": False, "error": "No emails in index"}

        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            error_resp = {"total_emails": 0, "index_ready": False, "error": str(e)}
            if self._diagnostics:
                error_resp["vector_backend_diagnostics"] = self._diagnostics
            return error_resp

    def get_backend_diagnostics(self) -> Dict[str, bool]:
        """Expose vector backend diagnostics (if provider used)."""
        return self._diagnostics.copy() if self._diagnostics else {}

    # ---------------------------- Query Cache Helpers ----------------------------
    def get_query_cache_stats(self) -> Dict[str, Any]:
        """Return external QueryResultsCache statistics augmented with last hit flag."""
        try:
            stats = (
                self._results_cache.get_stats() if self._results_cache else {"cache_enabled": False}
            )
        except Exception as e:
            stats = {"cache_enabled": False, "error": str(e)}
        stats["last_cache_hit"] = self._last_cache_hit
        return stats
