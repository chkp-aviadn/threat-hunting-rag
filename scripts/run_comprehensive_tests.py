#!/usr/bin/env python3
"""Comprehensive query testing suite."""

import subprocess
import sys
from pathlib import Path
from datetime import datetime

# Get project root (parent of scripts directory)
PROJECT_ROOT = Path(__file__).parent.parent

queries = [
    ("Find emails with .exe attachments", "Should show HIGH/CRITICAL for executable files"),
    ("Show emails with wire_details.exe", "Should show CRITICAL score for specific .exe"),
    ("Find emails asking for confidential information from unknown senders", "Should show MEDIUM+ for BEC patterns"),
    ("List emails with links to unfamiliar domains", "Should identify suspicious domains"),
    ("Show emails from misspelled corporate domains", "Should catch typosquatting"),
    ("Find urgent payment requests sent after hours", "Should combine urgency + timing signals"),
    ("Emails with suspicious .js or .scr attachments", "Should escalate to CRITICAL"),
]

# Create output file path
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = PROJECT_ROOT / "scripts" / f"comprehensive_test_results_{timestamp}.log"

print("="*100)
print("COMPREHENSIVE THREAT HUNTING QUERY TESTS")
print(f"Output will be saved to: {output_file}")
print("="*100)

print("="*100)
print("COMPREHENSIVE THREAT HUNTING QUERY TESTS")
print(f"Output will be saved to: {output_file}")
print("="*100)

# Open output file for writing
with open(output_file, 'w') as f:
    f.write("="*100 + "\n")
    f.write("COMPREHENSIVE THREAT HUNTING QUERY TESTS\n")
    f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write("="*100 + "\n\n")

    for i, (query, expected) in enumerate(queries, 1):
        test_header = f"\n{'='*100}\nTEST #{i}: {query}\nExpected: {expected}\n{'='*100}\n"
        print(test_header)
        f.write(test_header)
        
        result = subprocess.run(
            ["python", "app.py", "--query", query],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT)
        )
        
        # Extract key metrics from output
        output_lines = result.stdout.split('\n')
        
        # Find results section
        found_results = False
        result_count = 0
        threat_levels = []
        
        for line in output_lines:
            if "Found" in line and "results" in line:
                found_results = True
                parts = line.split()
                for j, part in enumerate(parts):
                    if part == "Found":
                        result_count = parts[j+1]
            elif "RESULT #" in line and ("RISK" in line or "Score:" in line):
                # Extract threat level
                if "CRITICAL" in line:
                    threat_levels.append("CRITICAL")
                elif "HIGH" in line:
                    threat_levels.append("HIGH")
                elif "MEDIUM" in line:
                    threat_levels.append("MEDIUM")
                elif "LOW" in line:
                    threat_levels.append("LOW")
                elif "NEGLIGIBLE" in line:
                    threat_levels.append("NEGLIGIBLE")
        
        summary = f"\n📊 Results Summary:\n   Total Results: {result_count}\n   Threat Levels: {', '.join(threat_levels[:5]) if threat_levels else 'None detected'}\n"
        print(summary)
        f.write(summary + "\n")
        
        # Show first result for verification
        in_result = False
        line_count = 0
        first_result = []
        for line in output_lines:
            if "RESULT #1" in line:
                in_result = True
            if in_result:
                print(line)
                first_result.append(line)
                line_count += 1
                if line_count > 15 or (line.startswith("---") and line_count > 5):
                    break
        
        f.write("\n".join(first_result) + "\n\n")

    final_msg = f"\n{'='*100}\nTEST SUITE COMPLETE\n{'='*100}\n"
    print(final_msg)
    f.write(final_msg)

print(f"\n✅ Results saved to: {output_file}")
