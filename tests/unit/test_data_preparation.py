"""Tests for Data Preparation requirements.

Validates:
- Synthetic dataset exists and >=100 emails
- Mix of legitimate vs phishing emails (not all one class)
- Required metadata columns present
- Embeddings can be generated (dimension > 0) for a sample
"""

import sys, pathlib

root = pathlib.Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(root))

import pandas as pd
from data_preparation.embeddings.index_builder import VectorIndexBuilder

DATA_CSV = pathlib.Path("data/emails.csv")

REQUIRED_COLUMNS = {"id", "sender", "subject", "body", "timestamp", "is_phishing"}


def test_dataset_exists_and_size():
    assert DATA_CSV.exists(), f"Dataset file missing at {DATA_CSV}"
    df = pd.read_csv(DATA_CSV)
    assert len(df) >= 100, f"Dataset size {len(df)} < 100"


def test_dataset_mixed_classes():
    df = pd.read_csv(DATA_CSV)
    phishing = df[df["is_phishing"] == True]
    legit = df[df["is_phishing"] == False]
    assert not phishing.empty, "No phishing samples present"
    assert not legit.empty, "No legitimate samples present"
    # Rough balance sanity: at least 20% phishing and <= 80% phishing
    ratio = len(phishing) / len(df)
    assert 0.2 <= ratio <= 0.8, f"Phishing ratio {ratio:.2f} outside expected bounds"


def test_dataset_metadata_columns():
    df = pd.read_csv(DATA_CSV, nrows=5)
    # Adapt to actual schema: optional columns like category/recipient may be derived later
    missing = REQUIRED_COLUMNS - set(df.columns)
    assert (
        not missing
    ), f"Missing required core columns: {missing}. Present columns: {df.columns.tolist()}"


def test_embedding_generation_sample():
    # Build vector index builder and generate embeddings for a small sample without full index rebuild
    builder = VectorIndexBuilder(db_path="data/chroma", collection_name="threat_hunting_emails")
    df = pd.read_csv(DATA_CSV)
    sample_text = df.iloc[0]["subject"] + "\n" + df.iloc[0]["body"]
    emb = builder.embedding_generator.embed_text(sample_text)
    assert emb is not None and len(emb) > 0, "Embedding generation failed or empty vector"
