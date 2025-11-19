#!/usr/bin/env python3
"""
Quick check if ChromaDB index is populated.
Exits with 0 if index has documents, 1 if empty or missing.
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from shared.vector.provider import get_vector_backend

def main():
    try:
        _, collection, _ = get_vector_backend()
        count = collection.count()
        
        if count > 0:
            # Index is populated
            sys.exit(0)
        else:
            # Index is empty
            sys.exit(1)
    except Exception:
        # Collection doesn't exist or other error
        sys.exit(1)

if __name__ == "__main__":
    main()
