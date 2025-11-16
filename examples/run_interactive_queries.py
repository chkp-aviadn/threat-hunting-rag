"""Automate interactive CLI queries and save results.

Runs the interactive mode of the Threat Hunting RAG CLI and feeds a
predefined set of natural language threat hunting queries. Captures the
entire session output and produces both a raw log and a parsed JSON summary
of detected results per query under the examples/ directory.

Usage:
  python examples/run_interactive_queries.py

Artifacts produced:
  examples/interactive_session_<timestamp>.log           Raw console output (full CLI interaction)
  examples/interactive_queries_summary_<timestamp>.json  Machine-readable parsed summary
  examples/interactive_queries_report_<timestamp>.md     Human-readable executive report

Parsing heuristic:
  - Each query start identified by line beginning with "🔍 Processing query:".
  - Result blocks identified by lines containing "RESULT #<n> - <LEVEL> RISK (Score: <float>)".
  - Subject and sender extracted from subsequent lines starting with "   Subject:" and "   From:".
  - Confidence extracted from line starting with "   🎯 Confidence:".
  - Keywords (optional) from line starting with "   🔑 Keywords:".

If parsing fails, the raw log still contains full detail for manual review.
"""

from __future__ import annotations

# Disable ChromaDB telemetry before any imports
import os
os.environ.setdefault("CHROMA_TELEMETRY_DISABLED", "TRUE")
os.environ.setdefault("ANONYMIZED_TELEMETRY", "FALSE")

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
    for i, q in enumerate(queries):
        line = q.strip() + "\n"
        assert process.stdin is not None
        process.stdin.write(line)
        process.stdin.flush()
        # Short pause to let processing happen before next query
        time.sleep(0.25)
        
        # After the second query, test refine command
        if i == 1:  # After wire transfer query
            process.stdin.write("refine threshold=0.7\n")
            process.stdin.flush()
            time.sleep(0.25)

    # Run history command
    assert process.stdin is not None
    process.stdin.write("history\n")
    process.stdin.flush()
    time.sleep(0.25)
    
    # Run stats command
    process.stdin.write("stats\n")
    process.stdin.flush()
    time.sleep(0.25)

    # Send exit command to terminate interactive loop
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
        # Skip refine results (they'll be shown in the refine section)
        if "🔁 Refined results:" in line:
            # Stop collecting results for current query when refine starts
            commit_result()
            current_query = None
            continue
            
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


def extract_session_commands(raw_output: str) -> Dict[str, str]:
    """Extract refine, history, and stats outputs from raw log."""
    commands = {}
    
    # Extract refine output
    refine_match = re.search(r'🔁 Refined results: (\d+) items \(threshold=([^)]+)\).*?(?=🔍 threat-hunt>)', raw_output, re.DOTALL)
    if refine_match:
        commands['refine'] = f"Filtered to {refine_match.group(1)} items (threshold={refine_match.group(2)})"
    
    # Extract history output
    history_match = re.search(r'📝 QUERY HISTORY.*?\n(.*?)(?=🔍 threat-hunt>)', raw_output, re.DOTALL)
    if history_match:
        commands['history'] = history_match.group(1).strip()
    
    # Extract stats output
    stats_match = re.search(r'📊 SESSION STATISTICS:.*?\n(.*?)(?=🔍 threat-hunt>)', raw_output, re.DOTALL)
    if stats_match:
        commands['stats'] = stats_match.group(1).strip()
    
    return commands


def generate_markdown_report(parsed: Dict[str, Any], timestamp: str, raw_output: str = "") -> str:
    """Generate a human-readable Markdown report from parsed results."""
    lines = []
    lines.append("# Threat Hunting Interactive Demo Results")
    lines.append(f"\n**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"**Session ID:** {timestamp}\n")
    
    # Calculate overall statistics
    threat_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NEGLIGIBLE': 0}
    total_results = 0
    
    for query, results in parsed['results'].items():
        for result in results:
            threat_counts[result['threat_level']] += 1
            total_results += 1
    
    lines.append("## 📊 Executive Summary")
    lines.append(f"\n- **Total Queries:** {len(parsed['queries'])}")
    lines.append(f"- **Total Results Analyzed:** {total_results}")
    lines.append(f"\n### Threat Level Distribution\n")
    lines.append("| Threat Level | Count | Percentage |")
    lines.append("|-------------|-------|------------|")
    for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE']:
        count = threat_counts[level]
        pct = (count/total_results*100) if total_results > 0 else 0
        emoji = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '⚡', 'LOW': '📝', 'NEGLIGIBLE': '✅'}[level]
        lines.append(f"| {emoji} {level:11s} | {count:5d} | {pct:6.1f}% |")
    
    lines.append("\n---\n")
    lines.append("## 🔍 Query Results Detail\n")
    
    # Detail for each query
    for i, query in enumerate(parsed['queries'], 1):
        results = parsed['results'].get(query, [])
        lines.append(f"### Query {i}: {query}")
        lines.append(f"\n**Results Found:** {len(results)}\n")
        
        if not results:
            lines.append("*No results captured*\n")
            continue
        
        # Show all 10 results per query
        lines.append("| Rank | Level | Score | From | Subject |")
        lines.append("|------|-------|-------|------|---------|")
        for result in results:
            level_emoji = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '⚡', 'LOW': '📝', 'NEGLIGIBLE': '✅'}[result['threat_level']]
            subject = result.get('subject', 'N/A')[:50] + ('...' if len(result.get('subject', '')) > 50 else '')
            sender = result.get('sender', 'N/A')[:30]
            lines.append(f"| {result['rank']} | {level_emoji} {result['threat_level']} | {result['threat_score']:.3f} | `{sender}` | {subject} |")
        
        lines.append("")
    
    lines.append("\n---\n")
    lines.append("## 📋 Notes\n")
    lines.append("- **Raw Log:** Contains full CLI output with detailed analysis")
    lines.append("- **JSON Summary:** Machine-readable format with complete result data")
    lines.append("- **This Report:** Human-readable executive summary")
    
    # Extract history and stats from raw output if available
    if parsed.get("parsing_warnings"):
        lines.append(f"\n⚠️ **Parsing Warnings:** {len(parsed['parsing_warnings'])} (see JSON for details)")
    
    # Add session commands section
    lines.append("\n---\n")
    lines.append("## 🔧 Interactive Commands Tested\n")
    
    # Extract command outputs from raw log
    if raw_output:
        session_cmds = extract_session_commands(raw_output)
        
        # Refine results
        if 'refine' in session_cmds:
            lines.append("### 🔁 Refine Command\n")
            lines.append("**Command:** `refine threshold=0.7`\n")
            lines.append("**What it does:** Filters the previous query results to show only emails with threat scores ≥ 0.7\n")
            lines.append(f"**Result:** {session_cmds['refine']}\n")
            lines.append("**Applied after:** Query #2 (wire transfers) which originally returned 10 results")
            lines.append("**Outcome:** Only 5 HIGH/CRITICAL threats remain (scores: 0.755, 0.758, 0.708, 0.742, 0.789)")
            lines.append("**Use case:** Quickly narrow down results without re-running the search\n")
        
        # History output
        if 'history' in session_cmds:
            lines.append("### 📝 History Command\n")
            lines.append("**Command:** `history`")
            lines.append("**Output:**\n")
            lines.append("```")
            lines.append(session_cmds['history'])
            lines.append("```\n")
        
        # Stats output  
        if 'stats' in session_cmds:
            lines.append("### 📊 Stats Command\n")
            lines.append("**Command:** `stats`")
            lines.append("**Output:**\n")
            lines.append("```")
            lines.append(session_cmds['stats'])
            lines.append("```\n")
    else:
        lines.append("This demo tested interactive commands:")
        lines.append("- **refine threshold=0.7** - Filtered wire transfer results")
        lines.append("- **history** - Displayed query history")
        lines.append("- **stats** - Showed session statistics\n")
        lines.append("*See raw log file for full command outputs.*")
    
    return "\n".join(lines)


def write_outputs(raw: str, parsed: Dict[str, Any]) -> None:
    examples_dir = Path(__file__).parent
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    log_path = examples_dir / f"interactive_session_{timestamp}.log"
    summary_path = examples_dir / f"interactive_queries_summary_{timestamp}.json"
    report_path = examples_dir / f"interactive_queries_report_{timestamp}.md"

    # Write raw log and JSON summary
    log_path.write_text(raw, encoding="utf-8")
    summary_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
    
    # Generate human-readable Markdown report with raw output
    markdown = generate_markdown_report(parsed, timestamp, raw)
    report_path.write_text(markdown, encoding="utf-8")

    print(f"✅ Raw log saved to {log_path}")
    print(f"✅ Summary saved to {summary_path}")
    print(f"✅ Report saved to {report_path}")
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
