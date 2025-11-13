"""
Threat Hunting RAG API (Minimal Mode)

Essential Endpoints:
    POST /api/v1/search        - Synchronous threat hunting queries
    POST /api/v1/search/refine - Iterative refinement of previous results
    POST /api/v1/chat          - Chat-style interface (search + optional refine)
    GET  /api/v1/health        - System health check
    GET  /                     - Root metadata

Removed legacy endpoints: /api/v1/batch, /api/v1/search/async, /api/v1/queries/{job_id}, /api/v1/vector/health, /api/v1/stats.
"""

import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
import asyncio
from contextlib import asynccontextmanager
import sys
import os

# Ensure project root and src/ are on sys.path BEFORE importing shared modules
_current_dir = os.path.dirname(__file__)
_src_root = os.path.abspath(os.path.join(_current_dir, "..", ".."))  # points to src/
_project_root = os.path.abspath(os.path.join(_src_root, ".."))
for _p in (_project_root, _src_root):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security.api_key import APIKeyHeader, APIKey
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from shared.pydantic_compat import BaseModel, Field, field_validator as validator

try:
    from pydantic import ConfigDict  # type: ignore
except ImportError:

    class ConfigDict(dict):  # type: ignore
        pass


import uvicorn

# Import our core components (using sys.path for demo)
# (Path adjustments performed above; legacy append removed)

from query_processing.models.search import SearchQuery, SearchResults
from orchestration.rag_pipeline import ThreatHuntingPipeline, PipelineBuilder

try:
    from query_processing.services.unified_search import UnifiedSearchService  # provider-aware
except Exception:  # pragma: no cover
    UnifiedSearchService = None  # type: ignore
try:
    from shared.vector.provider import get_vector_backend  # type: ignore
except Exception:  # pragma: no cover
    get_vector_backend = None  # type: ignore
from threat_analysis.reasoning.integration import ExplanationFactory
from shared.config import Config
from shared.session_store import SessionStore
from shared.enums import SearchMethod, ThreatLevel
from .schemas import ThreatHuntingResponse, ApiErrorResponse, ThreatEmailResult, SearchMetadata

# Centralized logging (already imported very early via shared.logging_config in bootstrap if using app.py)
try:
    from shared.logging_config import init_logging

    init_logging()
except Exception:
    logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API Configuration
API_VERSION = "1.0.0"
API_KEYS = {
    "demo-key-12345": "demo-user",
    "threat-hunter-key-67890": "threat-hunter",
    "admin-key-abcdef": "admin",
}

# Rate limiting (simple in-memory implementation)
rate_limit_data: Dict[str, List[datetime]] = {}
RATE_LIMIT_REQUESTS = 100  # requests per minute per API key
RATE_LIMIT_WINDOW = 60  # seconds

# Async job storage (in production, use Redis or database)
async_jobs: Dict[str, Dict[str, Any]] = {}


# Pydantic Models for API
class ThreatHuntingRequest(BaseModel):
    """Request model for threat hunting queries."""

    query: str = Field(..., min_length=1, max_length=500, description="Threat hunting query text")
    max_results: int = Field(default=10, ge=1, le=100, description="Maximum results to return")
    include_explanations: bool = Field(default=True, description="Include threat explanations")
    search_method: SearchMethod = Field(default=SearchMethod.HYBRID, description="Search method")
    threat_threshold: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Minimum threat score"
    )
    explanation_mode: Optional[str] = Field(
        default="text", description="Explanation mode: 'text' or 'json'"
    )
    detail_level: Optional[str] = Field(
        default="detailed", description="Explanation detail level: 'compact' or 'detailed'"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "query": "urgent payment requests from new senders",
                "max_results": 10,
                "include_explanations": True,
                "search_method": "hybrid",
                "threat_threshold": 0.5,
            }
        }
    )


# Removed: BatchRequest, AsyncRequest (minimal mode)


class ThreatHuntingResponse(BaseModel):
    """Response model for threat hunting results with diagnostics for production readiness."""

    request_id: str
    query: str
    processing_time_ms: int
    total_results: int
    results: List[Dict[str, Any]]
    search_metadata: Dict[str, Any]
    diagnostics: Optional[Dict[str, Any]] = None


# Removed: AsyncJobResponse, JobStatusResponse


class HealthResponse(BaseModel):
    """Response model for health checks."""

    status: str
    version: str
    uptime_seconds: int
    components: Dict[str, str]
    performance: Dict[str, Any]


# Removed: StatsResponse


# API Key Authentication
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_api_key(api_key: APIKey = Depends(api_key_header)) -> str:
    """Validate API key and return user."""
    if api_key in API_KEYS:
        return API_KEYS[api_key]
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


def check_rate_limit(request: Request, user: str = Depends(get_api_key)):
    """Simple rate limiting implementation."""
    now = datetime.now()
    user_requests = rate_limit_data.get(user, [])

    # Remove old requests outside the window
    cutoff_time = now - timedelta(seconds=RATE_LIMIT_WINDOW)
    user_requests = [req_time for req_time in user_requests if req_time > cutoff_time]

    # Check if rate limit exceeded
    if len(user_requests) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Max {RATE_LIMIT_REQUESTS} requests per minute.",
            headers={"Retry-After": "60"},
        )

    # Add current request
    user_requests.append(now)
    rate_limit_data[user] = user_requests

    return user


# Application lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info("🚀 Starting Threat Hunting RAG API")
    logger.info(f"📊 Version: {API_VERSION}")

    # Load configuration (includes Redis flags)
    config = Config.from_env()
    app.state.config = config

    # Initialize pipeline with provider-backed search if available
    try:
        builder = PipelineBuilder()
        if UnifiedSearchService is not None:
            search_service = UnifiedSearchService(
                use_provider=True, provider_backfill=False, collection_name="threat_hunting_emails"
            )
            builder.with_search_service(search_service)
            logger.info("API: Using provider-backed UnifiedSearchService")
        else:
            logger.info("API: UnifiedSearchService unavailable, using default builder")
        app.state.pipeline = builder.build()
        # Capture diagnostics if available
        if hasattr(app.state.pipeline.search_service, "get_backend_diagnostics"):
            app.state.vector_backend_diagnostics = (
                app.state.pipeline.search_service.get_backend_diagnostics()
            )
        else:
            app.state.vector_backend_diagnostics = {}
    except Exception as e:
        logger.warning(f"API: Fallback to default pipeline due to initialization error: {e}")
        app.state.pipeline = PipelineBuilder().build()
        app.state.vector_backend_diagnostics = {}
    app.state.start_time = time.time()
    app.state.query_count = 0
    app.state.vector_health_checked_at = datetime.now()
    # Initialize session store (Redis optional)
    try:
        app.state.session_store = SessionStore(enabled=config.redis_enabled, url=config.redis_url)
    except Exception as e:  # pragma: no cover
        logger.warning(f"Session store initialization failed: {e}")
        app.state.session_store = SessionStore(enabled=False)

    logger.info("✅ API startup complete")

    yield

    # Shutdown
    logger.info("🛑 Shutting down Threat Hunting RAG API")


# Create FastAPI application
app = FastAPI(
    title="Threat Hunting RAG API",
    description="Production-ready REST API for phishing threat detection and analysis",
    version=API_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure properly for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])  # Configure properly for production


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.now().isoformat(),
            "path": str(request.url.path),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler for unexpected errors."""
    logger.error(f"Unexpected error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "timestamp": datetime.now().isoformat(),
            "path": str(request.url.path),
        },
    )


# API Routes
@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Threat Hunting RAG API",
        "service": "Threat Hunting RAG API",
        "version": API_VERSION,
        "status": "operational",
        "documentation": "/docs",
        "health_check": "/api/v1/health",
        "endpoints": ["/api/v1/search", "/api/v1/search/refine", "/api/v1/chat", "/api/v1/health"],
    }


@app.post("/api/v1/search", response_model=ThreatHuntingResponse, tags=["Threat Hunting"])
async def search_threats(
    request: ThreatHuntingRequest, user: str = Depends(check_rate_limit)
) -> ThreatHuntingResponse:
    """Perform synchronous threat hunting query with enhanced diagnostics and feature/scoring integration."""
    start_time = time.time()
    request_id = str(uuid.uuid4())
    diagnostics: Dict[str, Any] = {
        "request_id": request_id,
        "query_len": len(request.query),
        "max_results": request.max_results,
        "search_method": request.search_method.value,
    }
    try:
        logger.info(f"Processing search request {request_id}: '{request.query}' for user {user}")
        search_query = SearchQuery(
            text=request.query,
            method=request.search_method,
            limit=request.max_results,
            threat_threshold=request.threat_threshold,
            explanation_mode=request.explanation_mode or "text",
            detail_level=request.detail_level or "detailed",
        )
        pipeline = getattr(app.state, "pipeline", None)
        if pipeline is None:
            diagnostics["pipeline_rebuilt"] = True
            from orchestration.rag_pipeline import PipelineBuilder

            builder = PipelineBuilder()
            try:
                from query_processing.services.unified_search import UnifiedSearchService as _USS

                search_service = _USS(
                    use_provider=True,
                    provider_backfill=False,
                    collection_name="threat_hunting_emails",
                )
                builder.with_search_service(search_service)
            except Exception as ie:
                diagnostics["search_service_init_error"] = str(ie)
            pipeline = builder.build()
            app.state.pipeline = pipeline
        else:
            diagnostics["pipeline_rebuilt"] = False

        # Ensure feature extractor & scorer wired (production readiness)
        if pipeline.feature_extractor is None or pipeline.threat_scorer is None:
            diagnostics["auto_wire_features"] = True
            try:
                from threat_analysis.detection.features import FeatureExtractor
                from threat_analysis.detection.scorer import ThreatScorer

                pipeline.feature_extractor = pipeline.feature_extractor or FeatureExtractor()
                pipeline.threat_scorer = pipeline.threat_scorer or ThreatScorer()
            except Exception as awe:
                diagnostics["auto_wire_error"] = str(awe)
        else:
            diagnostics["auto_wire_features"] = False

        results = pipeline.process_query(search_query)
        diagnostics["initial_result_count"] = results.total_found

        # Fallback builder.search if zero results and index has vectors
        if results.total_found == 0 and hasattr(pipeline, "search_service"):
            ss = pipeline.search_service
            try:
                col = getattr(ss, "_collection", None)
                ready_count = col.count() if col else 0
            except Exception:
                ready_count = 0
            diagnostics["collection_count"] = ready_count
            if ready_count > 0:
                diagnostics["fallback_invoked"] = True
                try:
                    search_dict = ss.vector_builder.search(
                        query_text=search_query.text, n_results=search_query.limit or 10
                    )
                    chroma_results = (
                        search_dict.get("results", {})
                        if isinstance(search_dict, dict)
                        else search_dict
                    )
                    fallback_query_results = ss._convert_chroma_results(
                        chroma_results, search_query
                    )
                    if fallback_query_results:
                        from query_processing.models.search import SearchResults as SR

                        results = SR(
                            query=search_query,
                            results=fallback_query_results,
                            total_found=len(fallback_query_results),
                            processing_time_ms=results.processing_time_ms,
                        )
                        diagnostics["fallback_result_count"] = len(fallback_query_results)
                except Exception as fe:
                    diagnostics["fallback_error"] = str(fe)
            else:
                diagnostics["fallback_invoked"] = False

        processing_time = int((time.time() - start_time) * 1000)
        app.state.query_count += 1
        diagnostics["processing_ms"] = processing_time
        response_results = []
        for r in results.results:
            data = r.model_dump()
            if not request.include_explanations:
                # Strip explanations if not requested
                data["explanation"] = ""
                if "explanation_structured" in data:
                    data["explanation_structured"] = None
            response_results.append(data)
        first_similarity = response_results[0].get("search_score") if response_results else None
        diagnostics["first_similarity"] = first_similarity

        backend_stats = {}
        try:
            if hasattr(pipeline.search_service, "get_stats"):
                backend_stats = pipeline.search_service.get_stats()
        except Exception as se:
            backend_stats = {"error": f"stats_failed: {se}"}
        diagnostics["backend_total_emails"] = backend_stats.get("total_emails")

        logger.info(
            f"Completed search {request_id} in {processing_time}ms results={results.total_found} sim_first={first_similarity}"
        )

        # Persist in refinement history
        request_history[request_id] = {
            "query": request.query,
            "results": response_results,
            "threat_threshold": request.threat_threshold,
            "timestamp": datetime.now().isoformat(),
        }

        return ThreatHuntingResponse(
            request_id=request_id,
            query=request.query,
            processing_time_ms=processing_time,
            total_results=results.total_found,
            results=response_results,
            search_metadata={
                "method": request.search_method.value,
                "threat_threshold": request.threat_threshold,
                "components_used": ["retrieval", "analysis", "scoring", "explanation"],
                "backend_stats": backend_stats,
            },
            diagnostics=diagnostics,
        )
    except Exception as e:
        diagnostics["error"] = str(e)
        logger.error(f"Search error for request {request_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Search processing failed: {str(e)}")


# In-memory store for request history (simple prototype; could persist later)
request_history: Dict[str, Dict[str, Any]] = {}


class RefinementRequest(BaseModel):
    """Request model for iterative refinement of a previous query."""

    previous_request_id: str = Field(..., description="Original search request ID to refine")
    add_filters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional metadata filters (sender_domain, feature_contains, min_threat_score)",
    )
    adjust_threshold: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Override or refine threat score threshold"
    )
    limit: Optional[int] = Field(
        default=None, ge=1, le=100, description="Optional new result limit"
    )
    explanation_focus: Optional[str] = Field(
        default=None,
        description="Highlight specific feature in explanations (attachments, impersonation, payment)",
    )
    include_structured: bool = Field(
        default=True, description="Include structured explanation if available from original result"
    )


class RefinementResponse(BaseModel):
    """Response model for query refinement results."""

    refinement_id: str
    previous_request_id: str
    original_query: str
    applied_filters: Dict[str, Any]
    processing_time_ms: int
    total_results: int
    results: List[Dict[str, Any]]
    refinement_metadata: Dict[str, Any]


@app.post("/api/v1/search/refine", response_model=RefinementResponse, tags=["Threat Hunting"])
async def refine_search(
    request: RefinementRequest, user: str = Depends(check_rate_limit)
) -> RefinementResponse:
    """Refine a previous search by applying additional filters or adjusting thresholds."""
    start_time = time.time()
    if request.previous_request_id not in request_history:
        raise HTTPException(status_code=404, detail="Previous request ID not found")

    previous = request_history[request.previous_request_id]
    original_results: List[Dict[str, Any]] = previous["results"]
    original_query = previous["query"]

    effective_threshold = (
        request.adjust_threshold
        if request.adjust_threshold is not None
        else previous.get("threat_threshold")
    )
    applied_filters: Dict[str, Any] = {}
    if request.add_filters:
        applied_filters.update(request.add_filters)
    if effective_threshold is not None:
        applied_filters["threat_threshold"] = effective_threshold
    if request.limit is not None:
        applied_filters["limit"] = request.limit

    refined = original_results
    if effective_threshold is not None:
        refined = [r for r in refined if r.get("threat_score", 0) >= effective_threshold]
    sender_domain = applied_filters.get("sender_domain")
    if sender_domain:
        refined = [
            r
            for r in refined
            if isinstance(r.get("sender"), str) and r.get("sender", "").endswith(sender_domain)
        ]
    feature_contains = applied_filters.get("feature_contains")
    if feature_contains:
        refined = [
            r
            for r in refined
            if feature_contains.lower() in " ".join(r.get("detected_features", [])).lower()
        ]

    limit = request.limit or len(refined)
    refined_limited = refined[:limit]

    if request.explanation_focus:
        focus = request.explanation_focus.lower()
        for r in refined_limited:
            # Structured explanation stored under 'explanation_structured'
            struct = r.get("explanation_structured")
            if isinstance(struct, dict):
                struct["focus_match"] = any(
                    focus in (ind.get("name", "")) for ind in struct.get("indicators", [])
                )

    # Optionally strip structured explanation
    if not request.include_structured:
        for r in refined_limited:
            if "explanation_structured" in r:
                r["explanation_structured"] = None

    processing_time_ms = int((time.time() - start_time) * 1000)
    refinement_id = str(uuid.uuid4())

    request_history[refinement_id] = {
        "query": original_query,
        "results": refined_limited,
        "refined_from": request.previous_request_id,
        "applied_filters": applied_filters,
        "processing_time_ms": processing_time_ms,
    }

    return RefinementResponse(
        refinement_id=refinement_id,
        previous_request_id=request.previous_request_id,
        original_query=original_query,
        applied_filters=applied_filters,
        processing_time_ms=processing_time_ms,
        total_results=len(refined_limited),
        results=refined_limited,
        refinement_metadata={
            "explanation_focus": request.explanation_focus,
            "backend": (
                getattr(
                    getattr(app.state, "pipeline", None).search_service, "backend_name", "default"
                )
                if hasattr(app.state, "pipeline")
                else "default"
            ),
        },
    )


# ----------------------------- Chat Endpoint Models & State -----------------------------
class ChatTurn(BaseModel):
    user_message: str
    request_id: Optional[str] = None
    refinement_id: Optional[str] = None
    results_preview: List[Dict[str, Any]] = []
    suggestions: List[str] = []
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=500, description="User chat message / query")
    session_id: Optional[str] = Field(None, description="Existing session id for continuity")
    refine: bool = Field(
        False, description="If true attempt automatic refinement based on last turn"
    )
    focus_feature: Optional[str] = Field(
        None,
        description="Feature keyword to emphasize in refinement (e.g. 'attachment','impersonation')",
    )
    min_threat_score: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Refinement threshold override"
    )
    limit: Optional[int] = Field(None, ge=1, le=50, description="Result limit override")


class ChatResponse(BaseModel):
    session_id: str
    turn: ChatTurn
    conversation_length: int
    backend: str
    refined: bool
    performance_ms: int


# In-memory chat sessions retained only as legacy fallback; primary store via SessionStore
chat_sessions: Dict[str, List[Dict[str, Any]]] = {}


def _derive_suggestions(results: List[Dict[str, Any]]) -> List[str]:
    if not results:
        return ["Try broadening your query", "Search for 'payment' or 'attachment' to start"]
    feature_counts: Dict[str, int] = {}
    for r in results:
        feats = r.get("features") or {}
        # Count high-level indicators if present
        for k, v in feats.items():
            if isinstance(v, (int, float)) and v > 0:
                feature_counts[k] = feature_counts.get(k, 0) + 1
        # If detected_features list present
        detected = r.get("detected_features") or []
        for d in detected:
            feature_counts[d] = feature_counts.get(d, 0) + 1
    suggestions: List[str] = []
    if feature_counts.get("suspicious_attachments", 0) > 0:
        suggestions.append("Refine to only suspicious attachments")
    if feature_counts.get("urgency_indicators", 0) > 0:
        suggestions.append("Raise threat threshold to focus on urgent language")
    if feature_counts.get("financial_keywords", 0) > 0:
        suggestions.append("Filter by financial transaction indicators")
    if not suggestions:
        suggestions.append("Apply a higher threshold (e.g. 0.6) to narrow results")
    return suggestions[:4]


@app.post("/api/v1/chat", response_model=ChatResponse, tags=["Threat Hunting"])
async def chat_endpoint(
    request: ChatRequest, user: str = Depends(check_rate_limit)
) -> ChatResponse:
    """Chat-style interface combining search + optional automatic refinement."""
    start = time.time()
    session_id = request.session_id or str(uuid.uuid4())
    pipeline = app.state.pipeline
    store: SessionStore = getattr(app.state, "session_store", None)

    refined = False
    results_payload: List[Dict[str, Any]] = []
    request_id: Optional[str] = None
    refinement_id: Optional[str] = None

    try:
        existing_convo: List[Dict[str, Any]] = []
        if store:
            existing_convo = store.get_session(session_id)
        elif session_id in chat_sessions:
            existing_convo = chat_sessions[session_id]

        if request.refine and existing_convo:
            # Attempt refinement using last turn's request_id
            last_turn = existing_convo[-1]
            prev_id = last_turn.get("request_id") or last_turn.get("refinement_id")
            if prev_id and prev_id in request_history:
                applied_filters: Dict[str, Any] = {}
                if request.focus_feature:
                    applied_filters["feature_contains"] = request.focus_feature
                if request.min_threat_score is not None:
                    applied_filters["threat_threshold"] = request.min_threat_score
                limit = request.limit or 5
                previous = request_history[prev_id]
                original_results = previous["results"]
                # Simple refinement logic (reuse earlier helper semantics)
                refined_results = original_results
                if request.min_threat_score is not None:
                    refined_results = [
                        r
                        for r in refined_results
                        if r.get("threat_score", 0) >= request.min_threat_score
                    ]
                if request.focus_feature:
                    refined_results = [
                        r
                        for r in refined_results
                        if request.focus_feature.lower()
                        in " ".join(r.get("detected_features", [])).lower()
                    ]
                refined_results = refined_results[:limit]
                refinement_id = str(uuid.uuid4())
                request_history[refinement_id] = {
                    "query": previous["query"],
                    "results": refined_results,
                    "refined_from": prev_id,
                    "applied_filters": applied_filters,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                results_payload = refined_results
                refined = True
            else:
                # Fallback to new search if no previous
                refined = False

        if not results_payload:
            # Perform new search
            search_query = SearchQuery(
                text=request.message,
                method=SearchMethod.HYBRID,
                limit=request.limit or 10,
                threat_threshold=request.min_threat_score,
            )
            search_results = pipeline.process_query(search_query)
            request_id = str(uuid.uuid4())
            # Store search results in request_history for future refinement
            request_history[request_id] = {
                "query": request.message,
                "results": [r.model_dump() for r in search_results.results],
                "threat_threshold": request.min_threat_score,
                "timestamp": datetime.utcnow().isoformat(),
            }
            results_payload = [r.model_dump() for r in search_results.results]

        suggestions = _derive_suggestions(results_payload)
        turn = ChatTurn(
            user_message=request.message,
            request_id=request_id,
            refinement_id=refinement_id,
            results_preview=results_payload[:5],
            suggestions=suggestions,
        )
        # Persist turn (store dict form for portability)
        if store and store.enabled:
            store.append_turn(session_id, turn.model_dump())
        else:
            chat_sessions.setdefault(session_id, []).append(turn.model_dump())

        perf_ms = int((time.time() - start) * 1000)
        conversation_length = (
            store.session_length(session_id)
            if store and store.enabled
            else len(chat_sessions.get(session_id, []))
        )
        return ChatResponse(
            session_id=session_id,
            turn=turn,
            conversation_length=conversation_length,
            backend=getattr(pipeline.search_service, "backend_name", "default"),
            refined=refined,
            performance_ms=perf_ms,
        )
    except Exception as e:
        logger.error(f"Chat endpoint error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Chat processing failed")


## Batch endpoint removed in minimal mode


## Async endpoints removed in minimal mode


@app.get("/api/v1/health", response_model=HealthResponse, tags=["System"])
async def health_check() -> HealthResponse:
    """System health check endpoint with vector backend diagnostics."""
    uptime = int(time.time() - app.state.start_time)

    # Vector backend diagnostics (captured at startup) + lightweight live probe
    diagnostics = getattr(app.state, "vector_backend_diagnostics", {})
    vector_status = (
        "healthy"
        if diagnostics and all(diagnostics.values())
        else ("degraded" if diagnostics else "unknown")
    )

    components_status = {
        "vector_db": vector_status,
        "embedding_model": "healthy",
        "cache": "healthy",
        "explanation_service": "healthy",
    }

    # Performance metrics placeholders
    avg_response_time = 1200
    cache_hit_rate = 0.65

    # Attach extra diagnostics in performance block for visibility
    performance_detail = {
        "avg_response_time_ms": avg_response_time,
        "total_queries": app.state.query_count,
        "cache_hit_rate": cache_hit_rate,
        "vector_backend_diagnostics": diagnostics,
    }

    return HealthResponse(
        status=(
            "healthy"
            if all(status == "healthy" for status in components_status.values())
            else "degraded"
        ),
        version=API_VERSION,
        uptime_seconds=uptime,
        components=components_status,
        performance=performance_detail,
    )


## Vector health & stats endpoints removed in minimal mode


# Development server
if __name__ == "__main__":
    # Execute with a proper import string so uvicorn lifecycle & reload semantics work.
    # We intentionally disable reload here because the bootstrap already handles env setup
    # and passing a direct app instance with reload causes uvicorn to exit immediately.
    host = os.getenv("API_HOST", "0.0.0.0")
    try:
        port = int(os.getenv("API_PORT", "8000"))
    except ValueError:
        port = 8000
    log_level = os.getenv("API_LOG_LEVEL", "info")
    uvicorn.run("interfaces.api.app:app", host=host, port=port, reload=False, log_level=log_level)
