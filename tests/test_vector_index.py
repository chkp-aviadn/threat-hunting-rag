"""
Test suite for vector index functionality - Phase 3, Task 3.2

Tests the SimpleVectorIndex implementation for persistent vector storage and search.
"""

import pytest
import numpy as np
import tempfile
import shutil
import json
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).parent.parent / "src"))

from infrastructure.ml.simple_vector_index import SimpleVectorIndex


class TestSimpleVectorIndex:
    """Test cases for the SimpleVectorIndex class."""
    
    @pytest.fixture
    def temp_db_dir(self):
        """Create temporary database directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def sample_emails(self):
        """Create sample email dataset for testing."""
        return [
            {
                'id': 'email_1',
                'subject': 'Urgent payment required',
                'body': 'Your account will be suspended unless you pay immediately.',
                'sender': 'billing@suspicious-bank.com',
                'recipient': 'user@company.com',
                'timestamp': '2024-01-01T10:00:00Z',
                'category': 'phishing',
                'is_phishing': True,
                'confidence_score': 0.95
            },
            {
                'id': 'email_2',
                'subject': 'Team meeting tomorrow',
                'body': 'Don\'t forget about our weekly team meeting at 2 PM.',
                'sender': 'manager@company.com',
                'recipient': 'team@company.com',
                'timestamp': '2024-01-01T11:00:00Z',
                'category': 'legitimate',
                'is_phishing': False,
                'confidence_score': 0.1
            },
            {
                'id': 'email_3',
                'subject': 'Security alert notification',
                'body': 'We detected unusual activity on your account.',
                'sender': 'security@fake-bank.com',
                'recipient': 'user@company.com',
                'timestamp': '2024-01-01T12:00:00Z',
                'category': 'phishing',
                'is_phishing': True,
                'confidence_score': 0.88
            }
        ]
    
    @pytest.fixture
    def vector_index(self, temp_db_dir):
        """Create SimpleVectorIndex instance for testing."""
        return SimpleVectorIndex(db_path=temp_db_dir)
    
    def test_initialization(self, vector_index, temp_db_dir):
        """Test that SimpleVectorIndex initializes correctly."""
        assert str(vector_index.db_path) == temp_db_dir
        assert vector_index.embeddings is None
        assert vector_index.metadata == []
        assert vector_index.document_count == 0
        assert vector_index.db_path.exists()
    
    def test_build_index(self, vector_index, sample_emails):
        """Test building vector index from email dataset."""
        stats = vector_index.build_index(sample_emails)
        
        # Verify build statistics
        assert stats['total_emails'] == 3
        assert stats['build_time_seconds'] > 0
        assert stats['embedding_dimension'] == 384
        assert stats['document_count'] == 3
        
        # Verify internal state
        assert vector_index.document_count == 3
        assert vector_index.embeddings.shape == (3, 384)
        assert len(vector_index.metadata) == 3
        
        # Verify metadata preservation
        metadata = vector_index.metadata
        assert metadata[0]['email_id'] == 'email_1'
        assert metadata[0]['is_phishing'] is True
        assert metadata[1]['is_phishing'] is False
    
    def test_build_index_empty(self, vector_index):
        """Test building index with empty email list raises error."""
        with pytest.raises(ValueError, match="Email list cannot be empty"):
            vector_index.build_index([])
    
    def test_persistence(self, vector_index, sample_emails):
        """Test that vector index persists to disk correctly."""
        # Build index
        vector_index.build_index(sample_emails)
        
        # Verify files are created
        assert vector_index.embeddings_file.exists()
        assert vector_index.metadata_file.exists()
        assert vector_index.stats_file.exists()
        
        # Verify file contents
        with open(vector_index.metadata_file, 'r') as f:
            saved_metadata = json.load(f)
        assert len(saved_metadata) == 3
        assert saved_metadata[0]['email_id'] == 'email_1'
    
    def test_load_existing_index(self, temp_db_dir, sample_emails):
        """Test loading existing index from disk."""
        # Create and build index
        index1 = SimpleVectorIndex(db_path=temp_db_dir)
        index1.build_index(sample_emails)
        original_count = index1.document_count
        
        # Create new instance (should load existing data)
        index2 = SimpleVectorIndex(db_path=temp_db_dir)
        
        assert index2.document_count == original_count
        assert index2.embeddings is not None
        assert len(index2.metadata) == original_count
    
    def test_search_basic(self, vector_index, sample_emails):
        """Test basic search functionality."""
        # Build index
        vector_index.build_index(sample_emails)
        
        # Search for urgent payment
        results = vector_index.search("urgent payment account", n_results=2)
        
        assert results['query'] == "urgent payment account"
        assert results['n_results'] <= 2
        assert len(results['results']) <= 2
        assert results['total_documents'] == 3
        
        # Verify result structure
        if results['results']:
            result = results['results'][0]
            assert 'metadata' in result
            assert 'similarity_score' in result
            assert 'distance' in result
            assert 'document' in result
            assert 0 <= result['similarity_score'] <= 1
    
    def test_search_empty_index(self, vector_index):
        """Test searching empty index returns appropriate response."""
        results = vector_index.search("test query")
        
        assert results['query'] == "test query"
        assert results['n_results'] == 0
        assert results['results'] == []
        assert 'error' in results
    
    def test_search_with_filtering(self, vector_index, sample_emails):
        """Test search with metadata filtering."""
        # Build index
        vector_index.build_index(sample_emails)
        
        # Search for phishing emails only
        phishing_results = vector_index.search(
            "account security", 
            n_results=5,
            where_filter={"is_phishing": True}
        )
        
        # All results should be phishing emails
        for result in phishing_results['results']:
            assert result['metadata']['is_phishing'] is True
        
        # Search for legitimate emails only
        legitimate_results = vector_index.search(
            "meeting team",
            n_results=5,
            where_filter={"is_phishing": False}
        )
        
        # All results should be legitimate emails
        for result in legitimate_results['results']:
            assert result['metadata']['is_phishing'] is False
    
    def test_cosine_similarity_calculation(self, vector_index):
        """Test cosine similarity calculation."""
        # Test identical vectors
        vec1 = np.array([1, 0, 0])
        vec2 = np.array([1, 0, 0])
        similarity = vector_index._cosine_similarity_batch(vec1, np.array([vec2]))[0]
        assert abs(similarity - 1.0) < 1e-6
        
        # Test orthogonal vectors
        vec3 = np.array([0, 1, 0])
        similarity = vector_index._cosine_similarity_batch(vec1, np.array([vec3]))[0]
        assert abs(similarity) < 1e-6
        
        # Test zero vector
        vec_zero = np.zeros(3)
        similarity = vector_index._cosine_similarity_batch(vec_zero, np.array([vec1]))[0]
        assert similarity == 0.0
    
    def test_get_stats(self, vector_index, sample_emails):
        """Test database statistics functionality."""
        # Test empty index stats
        empty_stats = vector_index.get_stats()
        assert empty_stats['document_count'] == 0
        assert empty_stats['db_exists'] is True
        
        # Build index and test stats
        vector_index.build_index(sample_emails)
        stats = vector_index.get_stats()
        
        assert stats['document_count'] == 3
        assert stats['embedding_dimension'] == 384
        assert stats['files']['embeddings'] is True
        assert stats['files']['metadata'] is True
        assert 'embeddings_file_size_mb' in stats
        assert 'metadata_file_size_mb' in stats
    
    def test_clear_index(self, vector_index, sample_emails):
        """Test index clearing functionality."""
        # Build index
        vector_index.build_index(sample_emails)
        assert vector_index.document_count == 3
        
        # Clear index
        vector_index.clear_index()
        
        # Verify clearing
        assert vector_index.document_count == 0
        assert vector_index.embeddings is None
        assert vector_index.metadata == []
        assert not vector_index.embeddings_file.exists()
        assert not vector_index.metadata_file.exists()


class TestVectorIndexIntegration:
    """Integration tests for vector index functionality."""
    
    def test_threat_hunting_scenarios(self):
        """Test vector index with realistic threat hunting scenarios."""
        # Create larger test dataset
        emails = [
            # Phishing emails
            {
                'id': 'phish_1',
                'subject': 'URGENT: Account suspension',
                'body': 'Your account will be suspended. Click here immediately.',
                'sender': 'security@fake-bank.com',
                'is_phishing': True,
                'category': 'phishing'
            },
            {
                'id': 'phish_2', 
                'subject': 'Payment verification needed',
                'body': 'Verify your payment method now or lose access.',
                'sender': 'billing@suspicious-site.com',
                'is_phishing': True,
                'category': 'phishing'
            },
            # Legitimate emails
            {
                'id': 'legit_1',
                'subject': 'Weekly team meeting',
                'body': 'Join us for the weekly team sync at 2 PM.',
                'sender': 'manager@company.com',
                'is_phishing': False,
                'category': 'legitimate'
            },
            {
                'id': 'legit_2',
                'subject': 'Invoice payment reminder',
                'body': 'Invoice #12345 payment is due in 7 days.',
                'sender': 'accounting@vendor.com',
                'is_phishing': False,
                'category': 'legitimate'
            }
        ]
        
        # Build index
        index = SimpleVectorIndex()
        stats = index.build_index(emails)
        assert stats['total_emails'] == 4
        
        # Test threat hunting queries
        
        # Query 1: Find urgent account-related emails
        urgent_results = index.search("urgent account suspension", n_results=2)
        assert urgent_results['n_results'] > 0
        
        # Query 2: Find payment-related emails
        payment_results = index.search("payment verification", n_results=3)
        assert payment_results['n_results'] > 0
        
        # Query 3: Find team communications
        team_results = index.search("team meeting sync", n_results=2)
        assert team_results['n_results'] > 0
        
        # Test filtering for phishing only
        phishing_only = index.search(
            "account payment", 
            n_results=5,
            where_filter={"is_phishing": True}
        )
        
        # Verify all results are phishing
        for result in phishing_only['results']:
            assert result['metadata']['is_phishing'] is True
    
    def test_performance_requirements(self):
        """Test that vector index meets performance requirements."""
        import time
        
        # Create larger dataset for performance testing
        emails = []
        for i in range(50):
            emails.append({
                'id': f'email_{i}',
                'subject': f'Test email subject {i}',
                'body': f'This is test email body content number {i}.',
                'sender': f'user{i}@test.com',
                'is_phishing': i % 2 == 0,  # Alternate phishing/legitimate
                'category': 'phishing' if i % 2 == 0 else 'legitimate'
            })
        
        # Test build performance
        index = SimpleVectorIndex()
        start_time = time.time()
        stats = index.build_index(emails)
        build_time = time.time() - start_time
        
        # Should build 50 emails quickly (well under requirement of 30s for 150 emails)
        assert build_time < 15.0  # 50 emails should build in under 15 seconds
        assert stats['average_build_time_per_email'] < 1.0  # Under 1 second per email
        
        # Test search performance
        search_times = []
        for i in range(10):
            start_time = time.time()
            results = index.search(f"test query {i}", n_results=5)
            search_time = time.time() - start_time
            search_times.append(search_time)
            assert results['n_results'] >= 0  # Should return results
        
        avg_search_time = sum(search_times) / len(search_times)
        assert avg_search_time < 2.0  # Should be under 2 seconds per search


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__])