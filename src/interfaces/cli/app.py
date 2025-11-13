"""
CLI Interface for Threat Hunting RAG System (Task 7.3)

Command-line interface providing interactive threat hunting capabilities
for development, testing, and manual analysis.

Features:
- Single query processing
- Interactive query mode
- Batch processing from files
- JSON and human-readable output formats
- Configuration management
- Real-time threat analysis results

Usage Examples:
    python -m interfaces.cli.app --query "urgent payment requests"
    python -m interfaces.cli.app --interactive
    python -m interfaces.cli.app --batch queries.txt --output results.json
"""

import argparse
import sys
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime
import requests  # HTTP client for server-backed chat mode

# Centralized logging (bootstrap may have initialized already; safe idempotent call)
try:
    from shared.logging_config import init_logging

    init_logging(logging.WARNING)
except Exception:
    logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

# Import core components (using sys.path for demo)
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))

from query_processing.models.search import SearchQuery, SearchResults
from orchestration.rag_pipeline import ThreatHuntingPipeline, PipelineBuilder

try:
    from shared.vector.provider import get_vector_backend  # type: ignore
except Exception:  # provider optional
    get_vector_backend = None  # type: ignore
from threat_analysis.reasoning.integration import ExplanationFactory
from shared.enums import SearchMethod, ThreatLevel


class ThreatHuntingCLI:
    """
    Command-line interface for threat hunting operations.

    Provides both single-query and interactive modes for threat analysis
    with comprehensive output formatting options.
    """

    def __init__(self, pipeline: Optional[ThreatHuntingPipeline] = None):
        """Initialize CLI with threat hunting pipeline."""
        self.pipeline = pipeline or self._build_default_pipeline()
        self.query_history: List[str] = []
        self.results_history: List[SearchResults] = []
        logger.debug("ThreatHuntingCLI initialized")

    def _log(self, message: str, level: str = "info", also_console: bool = True):
        """Unified logging helper that also optionally prints to console.

        Args:
            message: The message text
            level: One of debug/info/warning/error
            also_console: If True, echo to stdout for user visibility
        """
        log_func = {
            "debug": logger.debug,
            "info": logger.info,
            "warning": logger.warning,
            "error": logger.error,
        }.get(level.lower(), logger.info)
        log_func(message)
        if also_console:
            print(message)

    def _build_default_pipeline(self) -> ThreatHuntingPipeline:
        """Build default pipeline for CLI operations, initializing vector backend once."""
        try:
            builder = PipelineBuilder()
            # Initialize UnifiedSearchService with provider if available
            if get_vector_backend:
                from query_processing.services.unified_search import UnifiedSearchService

                # Attempt provider-backed initialization without full backfill (assumed pre-populated in startup scripts)
                search_service = UnifiedSearchService(
                    use_provider=True,
                    provider_backfill=False,
                    collection_name="threat_hunting_emails",
                )
                builder.with_search_service(search_service)
                logger.info("CLI: Using provider-backed UnifiedSearchService")
            else:
                logger.info("CLI: Provider unavailable, using default pipeline builder")
            return builder.build()
        except Exception as e:
            logger.error(f"Failed to build pipeline with provider path: {e}")
            return PipelineBuilder().build()

    def process_single_query(
        self,
        query: str,
        max_results: int = 10,
        search_method: SearchMethod = SearchMethod.HYBRID,
        threat_threshold: Optional[float] = None,
        output_format: str = "human",
    ) -> Dict[str, Any]:
        """
        Process a single threat hunting query.

        Args:
            query: The threat hunting query text
            max_results: Maximum number of results to return
            search_method: Search method to use
            threat_threshold: Minimum threat score threshold
            output_format: Output format ("human", "json", "table")

        Returns:
            Dict containing results and metadata
        """
        start_time = time.time()

        try:
            self._log(f"🔍 Processing query: '{query}'")
            self._log(f"   Method: {search_method.value}, Max results: {max_results}")
            if threat_threshold:
                self._log(f"   Threat threshold: {threat_threshold}")
            self._log("")

            # Create search query
            search_query = SearchQuery(
                text=query,
                method=search_method,
                limit=max_results,
                threat_threshold=threat_threshold,
            )

            # Process through pipeline
            results = self.pipeline.process_query(search_query)

            # Update history
            self.query_history.append(query)
            self.results_history.append(results)

            processing_time = time.time() - start_time

            # Format and display results
            if output_format == "json":
                self._display_json_results(results, processing_time)
            elif output_format == "table":
                self._display_table_results(results, processing_time)
            else:
                self._display_human_results(results, processing_time)

            # For external callers/tests, return a pure-serializable structure
            serializable_results = [
                {
                    "rank": r.rank,
                    "threat_score": r.threat_score,
                    "threat_level": (
                        r.threat_level.value if hasattr(r.threat_level, "value") else r.threat_level
                    ),
                    "confidence": r.confidence,
                    "explanation": r.explanation,
                    "keywords": r.keyword_matches,
                    "email_id": getattr(r.email, "id", None),
                    "sender": getattr(r.email, "sender", None),
                    "subject": getattr(r.email, "subject", None),
                    "timestamp": (
                        getattr(r.email, "timestamp", None).isoformat()
                        if getattr(r.email, "timestamp", None)
                        else None
                    ),
                }
                for r in results.results
            ]
            return {
                "query": query,
                "results": serializable_results,
                "processing_time_seconds": processing_time,
                "total_found": results.total_found,
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            error_msg = f"❌ Query processing failed: {str(e)}"
            self._log(error_msg, level="error")
            logger.error(f"Query processing error: {e}", exc_info=True)
            return {"query": query, "error": str(e), "processing_time": time.time() - start_time}

    def interactive_mode(self):
        """
        Run interactive threat hunting session.

        Provides a REPL-like interface for continuous threat hunting.
        """
        self._log("🛡️  THREAT HUNTING RAG SYSTEM - Interactive Mode")
        self._log("=" * 60)
        self._log("Commands:")
        self._log("  help          - Show available commands")
        self._log("  query <text>  - Run threat hunting query")
        self._log("  refine [opts] - Refine last results (threshold=, limit=, focus=)")
        self._log("  history       - Show query history")
        self._log("  stats         - Show session statistics")
        self._log("  clear         - Clear screen")
        self._log("  exit/quit     - Exit interactive mode")
        self._log("")

        session_start = time.time()

        while True:
            try:
                # Get user input
                user_input = input("🔍 threat-hunt> ").strip()

                if not user_input:
                    continue

                # Parse command
                parts = user_input.split(maxsplit=1)
                command = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ""

                if command in ["exit", "quit"]:
                    session_time = time.time() - session_start
                    self._log(
                        f"\n👋 Session complete! Total time: {session_time:.1f}s, Queries: {len(self.query_history)}"
                    )
                    break

                elif command == "help":
                    self._show_help()

                elif command == "query":
                    if not args:
                        self._log(
                            "❌ Please provide a query. Usage: query <search text>", level="warning"
                        )
                        continue
                    self.process_single_query(args, output_format="human")

                elif command == "history":
                    self._show_history()

                elif command == "stats":
                    self._show_session_stats(session_start)

                elif command == "refine":
                    self._handle_refine_command(args)

                elif command == "clear":
                    import os

                    os.system("cls" if os.name == "nt" else "clear")

                else:
                    # Treat as query if not a recognized command
                    self.process_single_query(user_input, output_format="human")

            except KeyboardInterrupt:
                self._log("\n\n👋 Goodbye!", level="info")
                break
            except Exception as e:
                self._log(f"❌ Error: {e}", level="error")
                logger.error(f"Interactive mode error: {e}", exc_info=True)

    def process_batch_file(
        self, file_path: str, output_path: Optional[str] = None, max_results: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Process queries from a batch file.

        Args:
            file_path: Path to file containing queries (one per line)
            output_path: Optional path to save results
            max_results: Maximum results per query

        Returns:
            List of results for each query
        """
        try:
            # Read queries from file
            queries_file = Path(file_path)
            if not queries_file.exists():
                raise FileNotFoundError(f"Batch file not found: {file_path}")

            queries = []
            with open(queries_file, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith("#"):  # Skip empty lines and comments
                        queries.append(line)

            if not queries:
                self._log("❌ No queries found in batch file", level="warning")
                return []

            self._log(f"📁 Processing {len(queries)} queries from {file_path}")
            self._log("")

            # Process each query
            all_results = []
            start_time = time.time()

            for i, query in enumerate(queries, 1):
                self._log(
                    f"[{i}/{len(queries)}] Processing: '{query[:50]}{'...' if len(query) > 50 else ''}'"
                )

                result = self.process_single_query(
                    query=query,
                    max_results=max_results,
                    output_format="table",  # Compact format for batch
                )
                all_results.append(result)
                self._log("")

            total_time = time.time() - start_time

            # Summary
            successful = len([r for r in all_results if "error" not in r])
            self._log(
                f"✅ Batch complete: {successful}/{len(queries)} successful in {total_time:.1f}s"
            )

            # Save results if output path provided
            if output_path:
                self._save_batch_results(all_results, output_path)

            return all_results

        except Exception as e:
            self._log(f"❌ Batch processing failed: {e}", level="error")
            logger.error(f"Batch processing error: {e}", exc_info=True)
            return []

    # ------------------------- Chat Mode (Server-backed) -------------------------
    def chat_mode(
        self,
        server_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        limit: int = 10,
        min_threat_score: Optional[float] = None,
        focus_feature: Optional[str] = None,
    ):
        """Interactive chat-style threat hunting using remote /api/v1/chat endpoint.

        Provides refinement and threshold adjustments via slash commands.
        Falls back to local pipeline processing if server unreachable.

        Commands:
          /help                 Show commands
          /threshold <value>    Set minimum threat score
          /limit <n>            Set result limit
          /focus <feature>      Emphasize feature in refinement (e.g. attachment)
          /refine               Apply refinement on next message
          /raw                  Show raw JSON of last response
          /quit or /exit        Exit chat mode
        """
        self._log("🤖 Chat Mode (server-backed) initialized. Type /help for commands.")
        server_url = server_url.rstrip("/")
        session_id: Optional[str] = None
        last_response: Optional[Dict[str, Any]] = None
        refine_next: bool = False
        history: List[Dict[str, Any]] = []

        while True:
            try:
                user_input = input("💬 chat> ").strip()
                if not user_input:
                    continue

                # Exit
                if user_input.lower() in {"/quit", "/exit", "quit", "exit"}:
                    self._log("👋 Exiting chat mode.")
                    break

                # Help
                if user_input.lower() in {"/help", "help"}:
                    print(
                        "\nCommands:\n  /threshold <value>\n  /limit <n>\n  /focus <feature>\n  /refine\n  /raw\n  /quit\n"
                    )
                    continue

                # Threshold
                if user_input.lower().startswith("/threshold"):
                    parts = user_input.split()
                    if len(parts) == 2:
                        try:
                            min_threat_score = float(parts[1])
                            self._log(f"Set min_threat_score={min_threat_score}")
                        except ValueError:
                            self._log("Invalid threshold value", level="warning")
                    else:
                        self._log("Usage: /threshold <value>", level="warning")
                    continue

                # Limit
                if user_input.lower().startswith("/limit"):
                    parts = user_input.split()
                    if len(parts) == 2 and parts[1].isdigit():
                        limit = int(parts[1])
                        self._log(f"Set limit={limit}")
                    else:
                        self._log("Usage: /limit <n>", level="warning")
                    continue

                # Focus feature
                if user_input.lower().startswith("/focus"):
                    parts = user_input.split(maxsplit=1)
                    if len(parts) == 2:
                        focus_feature = parts[1].strip()
                        self._log(f"Set focus_feature='{focus_feature}'")
                    else:
                        self._log("Usage: /focus <feature>", level="warning")
                    continue

                # Refine toggle
                if user_input.lower() == "/refine":
                    refine_next = True
                    self._log("Next message will trigger refinement.")
                    continue

                # Raw display
                if user_input.lower() == "/raw":
                    if last_response:
                        print(json.dumps(last_response, indent=2))
                    else:
                        self._log("No response yet.", level="warning")
                    continue

                # Actual message processing
                message_text = user_input
                payload = {
                    "message": message_text,
                    "session_id": session_id,
                    "refine": refine_next,
                    "min_threat_score": min_threat_score,
                    "limit": limit,
                    "focus_feature": focus_feature,
                }
                headers = {"Content-Type": "application/json"}
                if api_key:
                    headers["X-API-Key"] = api_key

                remote_success = False
                response_json: Dict[str, Any] = {}
                try:
                    resp = requests.post(
                        f"{server_url}/api/v1/chat",
                        json={k: v for k, v in payload.items() if v is not None},
                        headers=headers,
                        timeout=10,
                    )
                    if resp.status_code == 200:
                        response_json = resp.json()
                        remote_success = True
                        session_id = response_json.get("session_id", session_id)
                    else:
                        self._log(
                            f"Server responded {resp.status_code}, falling back to local search",
                            level="warning",
                        )
                except Exception as e:
                    self._log(f"Remote call failed: {e}; using local pipeline", level="warning")

                if not remote_success:
                    # Fallback local processing
                    search_query = SearchQuery(
                        text=message_text,
                        method=SearchMethod.HYBRID,
                        limit=limit,
                        threat_threshold=min_threat_score,
                    )
                    local_results = self.pipeline.process_query(search_query)
                    # Basic refinement if requested: filter & focus
                    if refine_next and min_threat_score is not None:
                        filtered = [
                            r for r in local_results.results if r.threat_score >= min_threat_score
                        ]
                    else:
                        filtered = local_results.results
                    if refine_next and focus_feature:
                        focus_lower = focus_feature.lower()
                        filtered = [
                            r
                            for r in filtered
                            if any(focus_lower in (kw.lower()) for kw in r.keyword_matches)
                        ] or filtered
                    response_json = {
                        "session_id": session_id or "local-session",
                        "turn": {
                            "user_message": message_text,
                            "results_preview": [
                                (r.model_dump() if hasattr(r, "model_dump") else r.dict())
                                for r in filtered[:5]
                            ],
                            "refinement_id": None,
                            "request_id": None,
                            "suggestions": [],
                        },
                        "conversation_length": len(history) + 1,
                        "backend": "local",
                        "refined": refine_next,
                        "performance_ms": local_results.processing_time_ms,
                    }

                last_response = response_json
                refine_next = False  # reset after use
                history.append({"message": message_text, "response": response_json})

                # Display concise summary of top results
                turn = response_json.get("turn", {})
                preview = turn.get("results_preview", [])
                if not preview:
                    self._log("No results returned.")
                    continue
                self._log(f"Top {len(preview)} results:")
                for idx, r in enumerate(preview, 1):
                    email_subject = r.get("email", {}).get("subject") or r.get("subject")
                    threat_score = r.get("threat_score")
                    threat_level = r.get("threat_level")
                    keywords = r.get("keyword_matches") or r.get("keywords") or []
                    kws = f" | 🔑 {', '.join(keywords[:4])}" if keywords else ""
                    self._log(f"  {idx}. {threat_level} {threat_score:.3f} - {email_subject}{kws}")
            except KeyboardInterrupt:
                self._log("\nInterrupted. Exiting chat mode.")
                break
            except Exception as e:
                self._log(f"Chat mode error: {e}", level="error")
                logger.error("Chat mode exception", exc_info=True)

    def _display_human_results(self, results: SearchResults, processing_time: float):
        """Display results in human-readable format."""
        self._log(f"⏱️  Processed in {processing_time:.3f}s | Found {results.total_found} results")
        self._log("=" * 80)

        if not results.results:
            self._log("🔍 No threats detected matching your query.")
            return

        for i, result in enumerate(results.results, 1):
            # Threat level emoji
            level_emoji = {
                ThreatLevel.CRITICAL: "🚨",
                ThreatLevel.HIGH: "⚠️",
                ThreatLevel.MEDIUM: "⚡",
                ThreatLevel.LOW: "ℹ️",
                ThreatLevel.NEGLIGIBLE: "✅",
            }.get(result.threat_level, "❓")

            self._log(
                f"\n{level_emoji} RESULT #{i} - {result.threat_level.value} RISK (Score: {result.threat_score:.3f})"
            )
            self._log(f"   From: {result.email.sender}")
            self._log(f"   Subject: {result.email.subject}")
            self._log(f"   Time: {result.email.timestamp}")

            if getattr(result.email, "attachment_count", 0) > 0:
                self._log(f"   📎 Attachments: {result.email.attachment_count}")

            # Show explanation (string or dict possible depending on future enhancements)
            if result.explanation:
                self._log(f"\n   💡 Analysis:")
                if isinstance(result.explanation, dict):
                    # Pretty print dict explanation structure
                    for k, v in result.explanation.items():
                        if isinstance(v, (list, tuple)):
                            self._log(f"      {k}: {', '.join(map(str, v))}")
                        else:
                            self._log(f"      {k}: {v}")
                else:
                    for line in str(result.explanation).split("\n"):
                        if line.strip():
                            self._log(f"      {line}")

            self._log(f"   🎯 Confidence: {result.confidence:.1%}")

            if result.keyword_matches:
                self._log(f"   🔑 Keywords: {', '.join(result.keyword_matches)}")

            self._log("-" * 80)

    def _display_json_results(self, results: SearchResults, processing_time: float):
        """Display results in JSON format."""
        output = {
            "query": results.query.text,
            "processing_time_seconds": processing_time,
            "total_found": results.total_found,
            "timestamp": datetime.now().isoformat(),
            "results": [],
        }

        for result in results.results:
            output["results"].append(
                {
                    "rank": result.rank,
                    "email_id": result.email.id,
                    "sender": result.email.sender,
                    "subject": result.email.subject,
                    "timestamp": result.email.timestamp.isoformat(),
                    "threat_score": result.threat_score,
                    "threat_level": result.threat_level.value,
                    "confidence": result.confidence,
                    "explanation": result.explanation,
                    "keywords": result.keyword_matches,
                }
            )

        print(json.dumps(output, indent=2))

    def _display_table_results(self, results: SearchResults, processing_time: float):
        """Display results in compact table format."""
        print(
            f"Query: {results.query.text} | Time: {processing_time:.3f}s | Found: {results.total_found}"
        )

        if not results.results:
            print("No results found.")
            return

        # Header
        print(f"{'#':<3} {'Score':<6} {'Level':<8} {'Sender':<30} {'Subject':<40}")
        print("-" * 90)

        # Results
        for result in results.results:
            sender = (
                result.email.sender[:28] + ".."
                if len(result.email.sender) > 30
                else result.email.sender
            )
            subject = (
                result.email.subject[:38] + ".."
                if len(result.email.subject) > 40
                else result.email.subject
            )

            print(
                f"{result.rank:<3} {result.threat_score:<6.3f} {result.threat_level.value:<8} {sender:<30} {subject:<40}"
            )

    def _show_help(self):
        """Show help information."""
        print("\n📚 THREAT HUNTING COMMANDS:")
        print("  query <text>      - Search for threats matching the query")
        print(
            "  refine [options]  - Refine last search results. Options: threshold=<float> limit=<int> focus=<keyword>"
        )
        print("  history           - Show previous queries in this session")
        print("  stats             - Show session statistics and performance")
        print("  clear             - Clear the screen")
        print("  help              - Show this help message")
        print("  exit/quit         - Exit interactive mode")
        print("\n💡 EXAMPLE QUERIES:")
        print("  query urgent payment requests from new senders")
        print("  query suspicious attachments")
        print("  query executive impersonation emails")
        print("\n🔧 EXAMPLE REFINEMENTS:")
        print("  refine threshold=0.6 limit=5")
        print("  refine focus=attachment")
        print("  refine threshold=0.5 focus=payment limit=3")
        print()

    def _handle_refine_command(self, args: str):
        """Parse and execute refine command on last results."""
        if not self.results_history:
            self._log("❌ No previous results to refine. Run a query first.", level="warning")
            return
        # Default parameters
        threshold: Optional[float] = None
        limit: Optional[int] = None
        focus: Optional[str] = None
        if args:
            for token in args.split():
                if "=" in token:
                    key, val = token.split("=", 1)
                    key = key.strip().lower()
                    val = val.strip()
                    if key in {"threshold", "t"}:
                        try:
                            threshold = float(val)
                        except ValueError:
                            self._log(f"⚠️ Invalid threshold value: {val}", level="warning")
                    elif key in {"limit", "n"}:
                        if val.isdigit():
                            limit = int(val)
                        else:
                            self._log(f"⚠️ Invalid limit value: {val}", level="warning")
                    elif key in {"focus", "f"}:
                        focus = val
        refined = self._refine_last_results(threshold=threshold, limit=limit, focus=focus)
        if refined:
            self._display_human_results(refined, 0.0)
        else:
            self._log("🔍 Refinement produced no results.")

    def _refine_last_results(
        self, threshold: Optional[float], limit: Optional[int], focus: Optional[str]
    ) -> Optional[SearchResults]:
        """Refine last SearchResults using optional threshold, limit, and focus keyword.

        Focus keyword matches against keyword_matches and explanation text.
        """
        original = self.results_history[-1]
        working = list(original.results)
        # Threshold filter
        if threshold is not None:
            working = [r for r in working if r.threat_score >= threshold]
        # Focus filter
        if focus:
            fl = focus.lower()
            filtered = []
            for r in working:
                in_keywords = any(fl in kw.lower() for kw in (r.keyword_matches or []))
                in_expl = fl in str(r.explanation).lower()
                if in_keywords or in_expl:
                    filtered.append(r)
            working = filtered or working  # if no matches keep original to avoid empty surprise
        # Apply limit
        if limit is not None and limit > 0:
            working = working[:limit]
        # Re-rank
        for idx, r in enumerate(working, 1):
            r.rank = idx
        # Build new SearchResults object
        try:
            refined = SearchResults(
                query=original.query,
                results=working,
                total_found=len(working),
                processing_time_ms=0,
            )
            # Append to history for chainable refinement
            self.results_history.append(refined)
            self.query_history.append(f"REFINE({threshold},{limit},{focus})")
            self._log(
                f"🔁 Refined results: {len(working)} items (threshold={threshold}, limit={limit}, focus={focus})"
            )
            return refined
        except Exception as e:
            self._log(f"❌ Refinement failed: {e}", level="error")
            logger.error("Refinement construction error", exc_info=True)
            return None

    def _show_history(self):
        """Show query history."""
        if not self.query_history:
            print("📝 No queries in history yet.")
            return

        print(f"\n📝 QUERY HISTORY ({len(self.query_history)} queries):")
        for i, query in enumerate(self.query_history, 1):
            result_count = (
                self.results_history[i - 1].total_found if i <= len(self.results_history) else 0
            )
            print(f"  {i:2d}. {query} -> {result_count} results")
        print()

    def _show_session_stats(self, session_start: float):
        """Show session statistics."""
        session_time = time.time() - session_start
        total_results = sum(r.total_found for r in self.results_history)

        print(f"\n📊 SESSION STATISTICS:")
        print(f"  Session time: {session_time:.1f} seconds")
        print(f"  Queries executed: {len(self.query_history)}")
        print(f"  Total results found: {total_results}")
        if self.query_history:
            avg_time = session_time / len(self.query_history)
            print(f"  Average query time: {avg_time:.2f} seconds")

        # Threat level breakdown
        if self.results_history:
            threat_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "CRITICAL": 0}
            for results in self.results_history:
                for result in results.results:
                    threat_counts[result.threat_level.value] = (
                        threat_counts.get(result.threat_level.value, 0) + 1
                    )

            print(f"  Threat breakdown: {threat_counts}")
        print()

    def _save_batch_results(self, results: List[Dict[str, Any]], output_path: str):
        """Save batch results to file."""
        try:
            output_file = Path(output_path)

            # Prepare output data
            output_data = {
                "batch_timestamp": datetime.now().isoformat(),
                "total_queries": len(results),
                "successful_queries": len([r for r in results if "error" not in r]),
                "results": results,
            }

            # Save as JSON
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, default=str)

            print(f"💾 Results saved to {output_path}")

        except Exception as e:
            print(f"❌ Failed to save results: {e}")


def create_cli_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Threat Hunting RAG System CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m interfaces.cli.app --query "urgent payment requests"
  python -m interfaces.cli.app --interactive
  python -m interfaces.cli.app --batch queries.txt --output results.json
    python -m interfaces.cli.app --chat --server-url http://localhost:8000 --api-key DEMO_KEY
        """,
    )

    # Mode selection (mutually exclusive)
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--query", "-q", type=str, help="Single threat hunting query to process"
    )
    mode_group.add_argument(
        "--interactive", "-i", action="store_true", help="Start interactive threat hunting session"
    )
    mode_group.add_argument(
        "--batch", "-b", type=str, help="Process queries from batch file (one query per line)"
    )
    mode_group.add_argument(
        "--chat", action="store_true", help="Start server-backed chat mode (/api/v1/chat)"
    )

    # Query options
    parser.add_argument(
        "--max-results",
        "-n",
        type=int,
        default=10,
        help="Maximum number of results to return (default: 10)",
    )
    parser.add_argument(
        "--search-method",
        "-m",
        choices=["keyword", "semantic", "hybrid"],
        default="hybrid",
        help="Search method to use (default: hybrid)",
    )
    parser.add_argument(
        "--threat-threshold", "-t", type=float, help="Minimum threat score threshold (0.0-1.0)"
    )

    # Output options
    parser.add_argument(
        "--output-format",
        "-f",
        choices=["human", "json", "table"],
        default="human",
        help="Output format (default: human)",
    )
    parser.add_argument("--output", "-o", type=str, help="Output file path (for batch mode)")
    # Chat mode options
    parser.add_argument(
        "--server-url",
        type=str,
        default="http://localhost:8000",
        help="Server base URL for chat mode (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        help="API key for authenticated chat/API calls (env THREAT_RAG_API_KEY fallback)",
    )
    parser.add_argument(
        "--chat-limit",
        type=int,
        default=10,
        help="Default result limit for chat messages (default: 10)",
    )
    parser.add_argument(
        "--chat-threshold",
        type=float,
        help="Default minimum threat score for chat messages (optional)",
    )
    parser.add_argument(
        "--chat-focus",
        type=str,
        help="Initial focus feature for refinement (e.g. attachment, impersonation)",
    )

    # Verbosity
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    return parser


def main():
    """Main CLI entry point."""
    parser = create_cli_parser()
    args = parser.parse_args()

    # Configure logging based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    try:
        # Initialize CLI (provider-backed search if available)
        cli = ThreatHuntingCLI()
        # Expose vector backend diagnostics if available
        diagnostics = {}
        if hasattr(cli.pipeline.search_service, "get_backend_diagnostics"):
            diagnostics = cli.pipeline.search_service.get_backend_diagnostics()
            if diagnostics:
                logger.info(f"Vector backend diagnostics: {diagnostics}")

        # Convert search method string to enum
        search_method = {
            "keyword": SearchMethod.KEYWORD,
            "semantic": SearchMethod.SEMANTIC,
            "hybrid": SearchMethod.HYBRID,
        }[args.search_method]

        # Execute based on mode
        if args.interactive:
            cli.interactive_mode()

        elif args.query:
            cli.process_single_query(
                query=args.query,
                max_results=args.max_results,
                search_method=search_method,
                threat_threshold=args.threat_threshold,
                output_format=args.output_format,
            )

        elif args.batch:
            cli.process_batch_file(
                file_path=args.batch, output_path=args.output, max_results=args.max_results
            )

        elif args.chat:
            # Resolve API key precedence: CLI flag > env var
            api_key = args.api_key or os.environ.get("THREAT_RAG_API_KEY")
            if not api_key:
                logger.warning(
                    "No API key provided for chat mode; attempting unauthenticated calls."
                )
            cli.chat_mode(
                server_url=args.server_url,
                api_key=api_key,
                limit=args.chat_limit,
                min_threat_score=args.chat_threshold,
                focus_feature=args.chat_focus,
            )

    except KeyboardInterrupt:
        print("\n👋 Operation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        if args.verbose:
            logger.error("Fatal error details:", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
