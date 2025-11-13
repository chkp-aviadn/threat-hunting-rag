"""Automate interactive CLI queries and save results.

Runs the interactive mode of the Threat Hunting RAG CLI and feeds a
predefined set of natural language threat hunting queries. Captures the
entire session output and produces both a raw log and a parsed JSON summary
of detected results per query under the examples/ directory.

Usage:
  python examples/run_interactive_queries.py

Artifacts produced:
  examples/interactive_session_<timestamp>.log          Raw console output
  examples/interactive_queries_summary_<timestamp>.json Parsed summary
  examples/interactive_queries_latest.log               Latest raw log symlink/overwrite
  examples/interactive_queries_latest.json              Latest summary overwrite

Parsing heuristic:
  - Each query start identified by line beginning with "🔍 Processing query:".
  - Result blocks identified by lines containing "RESULT #<n> - <LEVEL> RISK (Score: <float>)".
  - Subject and sender extracted from subsequent lines starting with "   Subject:" and "   From:".
  - Confidence extracted from line starting with "   🎯 Confidence:".
  - Keywords (optional) from line starting with "   🔑 Keywords:".

If parsing fails, the raw log still contains full detail for manual review.
"""

from __future__ import annotations

import subprocess
import sys
import time
import re
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any


QUERIES: List[str] = [
    "Show me emails asking for confidential information from unknown senders.",
    "Find emails that mention wire transfers or urgent money transfers.",
    "List emails with links to unfamiliar or misspelled domains.",
    "Identify emails pretending to be from IT support asking for password resets.",
    "Show me emails where the sender’s address doesn’t match the display name.",
    "Find emails containing invoices or payment instructions from first-time contacts.",
    "Highlight emails with suspicious-looking PDF or ZIP attachments.",
    "Locate emails referencing overdue payments or account suspension warnings.",
    "Show me messages claiming to be from well-known vendors but using personal email addresses.",
    "Find emails sent outside business hours requesting urgent approval or action.",
]


def run_interactive_session(queries: List[str]) -> str:
    """Launch interactive CLI and feed queries, returning full stdout text."""
    # Command as requested by user
    cmd = [sys.executable, "-m", "src.interfaces.cli.app", "--interactive"]
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    # Feed each query as a raw line (unprefixed so CLI treats as query)
    for q in queries:
        line = q.strip() + "\n"
        assert process.stdin is not None
        process.stdin.write(line)
        process.stdin.flush()
        # Short pause to let processing happen before next query
        time.sleep(0.25)

    # Send exit command to terminate interactive loop
    assert process.stdin is not None
    process.stdin.write("exit\n")
    process.stdin.flush()

    # Collect all output
    stdout, _ = process.communicate(timeout=120)
    return stdout


RESULT_LINE_RE = re.compile(r"RESULT #(?P<rank>\d+) - (?P<level>[A-Z]+) RISK \(Score: (?P<score>[0-9.]+)\)")


def parse_session_output(raw: str) -> Dict[str, Any]:
    """Parse raw interactive session output into structured summary.

    Returns dict with keys:
      queries: list of query texts
      results: mapping query_text -> list of result dicts
      parsing_warnings: list of non-fatal issues
    """
    lines = raw.splitlines()
    current_query: str | None = None
    data: Dict[str, List[Dict[str, Any]]] = {}
    warnings: List[str] = []
    current_result: Dict[str, Any] | None = None

    def commit_result():
        nonlocal current_result, current_query
        if current_query and current_result:
            data.setdefault(current_query, []).append(current_result)
        current_result = None

    for i, line in enumerate(lines):
        # Detect start of a new query (may be preceded by prompt '🔍 threat-hunt> ')
        if "Processing query:" in line:
            # New query begins; commit previous result
            commit_result()
            # Extract quoted query text
            m = re.search(r"'(.+)'", line)
            if m:
                current_query = m.group(1)
                data.setdefault(current_query, [])
            else:
                warnings.append(f"Line {i}: could not extract query text")
                current_query = f"<unknown-{i}>"
        else:
            # Try to parse result lines
            rl = RESULT_LINE_RE.search(line)
            if rl and current_query:
                commit_result()
                current_result = {
                    "rank": int(rl.group("rank")),
                    "threat_level": rl.group("level"),
                    "threat_score": float(rl.group("score")),
                }
            elif current_result is not None:
                # Supplementary lines for current result
                if line.strip().startswith("From:"):
                    current_result["sender"] = line.split("From:", 1)[1].strip()
                elif line.strip().startswith("Subject:"):
                    current_result["subject"] = line.split("Subject:", 1)[1].strip()
                elif "Confidence:" in line:
                    # Format: 🎯 Confidence: 45.3%
                    conf_match = re.search(r"Confidence: ([0-9.]+)%", line)
                    if conf_match:
                        current_result["confidence_pct"] = float(conf_match.group(1))
                elif line.strip().startswith("🔑 Keywords:"):
                    kws = line.split("Keywords:", 1)[1].strip()
                    current_result["keywords"] = [k.strip() for k in kws.split(',') if k.strip()]
                # Explanation lines are multi-line; we won't attempt full capture for brevity.

    # Commit any trailing result
    commit_result()

    return {
        "queries": list(data.keys()),
        "results": data,
        "parsing_warnings": warnings,
    }


def write_outputs(raw: str, parsed: Dict[str, Any]) -> None:
    examples_dir = Path(__file__).parent
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    log_path = examples_dir / f"interactive_session_{timestamp}.log"
    summary_path = examples_dir / f"interactive_queries_summary_{timestamp}.json"
    latest_log = examples_dir / "interactive_queries_latest.log"
    latest_json = examples_dir / "interactive_queries_latest.json"

    log_path.write_text(raw, encoding="utf-8")
    summary_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
    latest_log.write_text(raw, encoding="utf-8")
    latest_json.write_text(json.dumps(parsed, indent=2), encoding="utf-8")

    print(f"✅ Raw log saved to {log_path}")
    print(f"✅ Summary saved to {summary_path}")
    if parsed.get("parsing_warnings"):
        print(f"⚠️ Parsing warnings: {len(parsed['parsing_warnings'])}")


def main():
    raw = run_interactive_session(QUERIES)
    parsed = parse_session_output(raw)
    write_outputs(raw, parsed)

    # Compact overview
    for q in QUERIES:
        res = parsed["results"].get(q, [])
        print(f"\nQuery: {q}\n  Results captured: {len(res)}")
        for r in res[:3]:  # show top 3 for quick glance
            print(f"    #{r['rank']} {r['threat_level']} {r['threat_score']:.3f} - {r.get('subject','<no subject>')}")


if __name__ == "__main__":
    main()
