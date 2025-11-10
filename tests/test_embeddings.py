"""
Test suite for embeddings functionality - Phase 3, Task 3.1

Tests the sentence-transformers embedding generator implementation.
"""

import pytest
import numpy as np
import tempfile
import shutil
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).parent.parent / "src"))

from infrastructure.ml.embeddings import EmbeddingGenerator


class TestEmbeddingGenerator:
    """Test cases for the EmbeddingGenerator class."""
    
    @pytest.fixture
    def temp_cache_dir(self):
        """Create temporary cache directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def embedding_generator(self, temp_cache_dir):
        """Create EmbeddingGenerator instance for testing."""
        return EmbeddingGenerator(cache_dir=temp_cache_dir)
    
    def test_initialization(self, embedding_generator):
        """Test that EmbeddingGenerator initializes correctly."""
        assert embedding_generator.model_name == "sentence-transformers/all-MiniLM-L6-v2"
        assert embedding_generator.model is None  # Lazy loading
        assert isinstance(embedding_generator._memory_cache, dict)
        assert len(embedding_generator._memory_cache) == 0
    
    def test_model_loading(self, embedding_generator):
        """Test that the sentence-transformers model loads correctly."""
        model = embedding_generator._load_model()
        
        assert model is not None
        assert embedding_generator.model is not None
        assert embedding_generator.get_embedding_dimension() == 384
    
    def test_embed_text_basic(self, embedding_generator):
        """Test basic text embedding functionality."""
        text = "This is a test email about urgent payment."
        embedding = embedding_generator.embed_text(text)
        
        assert isinstance(embedding, np.ndarray)
        assert embedding.shape == (384,)
        assert not np.all(embedding == 0)  # Should not be all zeros
    
    def test_embed_text_empty(self, embedding_generator):
        """Test embedding empty text returns zero vector."""
        embedding = embedding_generator.embed_text("")
        
        assert isinstance(embedding, np.ndarray)
        assert embedding.shape == (384,)
        assert np.all(embedding == 0)  # Should be all zeros for empty text
    
    def test_embed_email(self, embedding_generator):
        """Test email embedding with subject and body."""
        email = {
            'subject': 'Urgent payment required',
            'body': 'Please pay your invoice immediately to avoid suspension.'
        }
        
        embedding = embedding_generator.embed_email(email)
        
        assert isinstance(embedding, np.ndarray)
        assert embedding.shape == (384,)
        assert not np.all(embedding == 0)
    
    def test_embed_email_missing_fields(self, embedding_generator):
        """Test email embedding with missing subject or body."""
        # Missing body
        email1 = {'subject': 'Test subject'}
        embedding1 = embedding_generator.embed_email(email1)
        assert embedding1.shape == (384,)
        
        # Missing subject
        email2 = {'body': 'Test body content'}
        embedding2 = embedding_generator.embed_email(email2)
        assert embedding2.shape == (384,)
        
        # Empty email
        email3 = {}
        embedding3 = embedding_generator.embed_email(email3)
        assert np.all(embedding3 == 0)  # Should be zero vector
    
    def test_caching_functionality(self, embedding_generator):
        """Test that caching works correctly."""
        text = "Test text for caching"
        
        # First call should generate and cache
        embedding1 = embedding_generator.embed_text(text)
        assert len(embedding_generator._memory_cache) == 1
        
        # Second call should use cache
        embedding2 = embedding_generator.embed_text(text)
        assert np.array_equal(embedding1, embedding2)
    
    def test_similarity_calculation(self, embedding_generator):
        """Test similarity calculation between embeddings."""
        # Similar texts
        embedding1 = embedding_generator.embed_text("urgent payment required")
        embedding2 = embedding_generator.embed_text("payment needed urgently")
        similarity_high = embedding_generator.similarity(embedding1, embedding2)
        
        # Different texts
        embedding3 = embedding_generator.embed_text("team meeting tomorrow")
        similarity_low = embedding_generator.similarity(embedding1, embedding3)
        
        assert 0 <= similarity_high <= 1
        assert 0 <= similarity_low <= 1
        assert similarity_high > similarity_low  # Similar texts should have higher similarity
    
    def test_batch_embedding(self, embedding_generator):
        """Test batch embedding functionality."""
        texts = [
            "Urgent payment required",
            "Team meeting tomorrow",
            "Security alert notification"
        ]
        
        embeddings = embedding_generator.embed_batch(texts, batch_size=2)
        
        assert len(embeddings) == 3
        assert all(isinstance(emb, np.ndarray) for emb in embeddings)
        assert all(emb.shape == (384,) for emb in embeddings)
    
    def test_cache_stats(self, embedding_generator):
        """Test cache statistics functionality."""
        # Generate some embeddings to populate cache
        embedding_generator.embed_text("test text 1")
        embedding_generator.embed_text("test text 2")
        
        stats = embedding_generator.get_cache_stats()
        
        assert 'memory_cache_size' in stats
        assert 'disk_cache_size' in stats
        assert 'cache_directory' in stats
        assert 'model_name' in stats
        assert stats['memory_cache_size'] == 2
        assert stats['model_name'] == "sentence-transformers/all-MiniLM-L6-v2"
    
    def test_clear_cache(self, embedding_generator):
        """Test cache clearing functionality."""
        # Populate cache
        embedding_generator.embed_text("test text")
        assert len(embedding_generator._memory_cache) > 0
        
        # Clear cache
        embedding_generator.clear_memory_cache()
        assert len(embedding_generator._memory_cache) == 0


class TestEmbeddingIntegration:
    """Integration tests for embedding functionality."""
    
    def test_threat_hunting_similarity(self):
        """Test that embeddings work well for threat hunting scenarios."""
        generator = EmbeddingGenerator()
        
        # Phishing email patterns
        phishing1 = generator.embed_text("Urgent: Your account will be suspended")
        phishing2 = generator.embed_text("Immediate action required for your account")
        
        # Legitimate email patterns  
        legitimate1 = generator.embed_text("Weekly team meeting reminder")
        legitimate2 = generator.embed_text("Project status update report")
        
        # Test that similar threat types have higher similarity
        phishing_similarity = generator.similarity(phishing1, phishing2)
        legitimate_similarity = generator.similarity(legitimate1, legitimate2)
        cross_similarity = generator.similarity(phishing1, legitimate1)
        
        # Phishing emails should be more similar to each other than to legitimate emails
        assert phishing_similarity > cross_similarity
        assert legitimate_similarity > cross_similarity
    
    def test_performance_requirements(self):
        """Test that embedding generation meets performance requirements."""
        import time
        
        generator = EmbeddingGenerator()
        
        # Test single embedding performance
        start_time = time.time()
        generator.embed_text("Test email content for performance testing")
        single_time = time.time() - start_time
        
        assert single_time < 2.0  # Should be under 2 seconds per embedding
        
        # Test batch performance
        texts = [f"Test email {i}" for i in range(10)]
        start_time = time.time()
        embeddings = generator.embed_batch(texts)
        batch_time = time.time() - start_time
        
        assert len(embeddings) == 10
        assert batch_time < 10.0  # Should handle 10 embeddings in under 10 seconds


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__])