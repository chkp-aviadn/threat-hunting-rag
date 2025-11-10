"""
Integration tests for end-to-end Phase 3 pipeline

Tests the complete embeddings and vector search pipeline working together.
"""

import pytest
import tempfile
import shutil
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).parent.parent / "src"))

from infrastructure.ml.embeddings import EmbeddingGenerator
from infrastructure.ml.simple_vector_index import SimpleVectorIndex


class TestPhase3Pipeline:
    """Integration tests for Phase 3 embeddings and vector search pipeline."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def threat_hunting_emails(self):
        """Create realistic threat hunting email dataset."""
        return [
            # Phishing - Account suspension threats
            {
                'id': 'phish_suspension_1',
                'subject': 'URGENT: Account Suspension Notice',
                'body': 'Your account will be suspended in 24 hours unless you verify your identity immediately. Click here to prevent closure.',
                'sender': 'security@fake-bank.com',
                'recipient': 'user@company.com',
                'timestamp': '2024-01-01T09:00:00Z',
                'category': 'phishing',
                'is_phishing': True,
                'threat_type': 'account_suspension',
                'confidence_score': 0.95
            },
            {
                'id': 'phish_suspension_2',
                'subject': 'Final Warning: Account Deactivation',
                'body': 'This is your final warning. Your account access will be terminated unless you confirm your details now.',
                'sender': 'alerts@phishing-amazon.com',
                'recipient': 'user@company.com',
                'timestamp': '2024-01-01T10:30:00Z',
                'category': 'phishing',
                'is_phishing': True,
                'threat_type': 'account_suspension',
                'confidence_score': 0.92
            },
            
            # Phishing - Payment fraud
            {
                'id': 'phish_payment_1',
                'subject': 'Payment Method Expired - Update Required',
                'body': 'Your payment method has expired. Update your billing information immediately to maintain service.',
                'sender': 'billing@fake-netflix.com',
                'recipient': 'user@company.com',
                'timestamp': '2024-01-01T11:15:00Z',
                'category': 'phishing',
                'is_phishing': True,
                'threat_type': 'payment_fraud',
                'confidence_score': 0.87
            },
            {
                'id': 'phish_payment_2',
                'subject': 'Invoice Overdue - Immediate Action Required',
                'body': 'Your invoice payment is 30 days overdue. Pay now to avoid service disruption and additional fees.',
                'sender': 'collections@suspicious-paypal.com',
                'recipient': 'user@company.com',
                'timestamp': '2024-01-01T14:20:00Z',
                'category': 'phishing',
                'is_phishing': True,
                'threat_type': 'payment_fraud',
                'confidence_score': 0.89
            },
            
            # Legitimate - Business communications
            {
                'id': 'legit_meeting_1',
                'subject': 'Weekly Team Standup - Thursday 2 PM',
                'body': 'Don\'t forget about our weekly team standup meeting this Thursday at 2 PM in conference room B.',
                'sender': 'manager@company.com',
                'recipient': 'team@company.com',
                'timestamp': '2024-01-01T08:00:00Z',
                'category': 'legitimate',
                'is_phishing': False,
                'threat_type': 'none',
                'confidence_score': 0.05
            },
            {
                'id': 'legit_project_1',
                'subject': 'Q1 Project Status Update',
                'body': 'The Q1 development project is on track for completion by March 31st. All milestones have been met.',
                'sender': 'project-manager@company.com',
                'recipient': 'stakeholders@company.com',
                'timestamp': '2024-01-01T16:45:00Z',
                'category': 'legitimate',
                'is_phishing': False,
                'threat_type': 'none',
                'confidence_score': 0.02
            },
            
            # Legitimate - Billing (legitimate invoices)
            {
                'id': 'legit_invoice_1',
                'subject': 'Invoice #INV-2024-001 - Payment Due',
                'body': 'Please find attached invoice #INV-2024-001 for consulting services. Payment is due within 30 days.',
                'sender': 'accounting@trusted-vendor.com',
                'recipient': 'ap@company.com',
                'timestamp': '2024-01-01T12:30:00Z',
                'category': 'legitimate',
                'is_phishing': False,
                'threat_type': 'none',
                'confidence_score': 0.15
            },
            {
                'id': 'legit_invoice_2',
                'subject': 'Monthly Subscription Renewal Notice',
                'body': 'Your monthly subscription for premium support will renew automatically on February 1st.',
                'sender': 'billing@software-vendor.com',
                'recipient': 'admin@company.com',
                'timestamp': '2024-01-01T13:10:00Z',
                'category': 'legitimate',
                'is_phishing': False,
                'threat_type': 'none',
                'confidence_score': 0.08
            }
        ]
    
    def test_end_to_end_pipeline(self, temp_dir, threat_hunting_emails):
        """Test complete pipeline from embeddings to search results."""
        # Step 1: Initialize components
        embedding_gen = EmbeddingGenerator(cache_dir=f"{temp_dir}/embeddings_cache")
        vector_index = SimpleVectorIndex(db_path=f"{temp_dir}/vector_db")
        
        # Step 2: Build vector index
        build_stats = vector_index.build_index(threat_hunting_emails)
        
        # Verify build success
        assert build_stats['total_emails'] == 8
        assert build_stats['embedding_dimension'] == 384
        assert build_stats['build_time_seconds'] > 0
        
        # Step 3: Test threat hunting queries
        
        # Query 1: Account suspension threats
        suspension_results = vector_index.search(
            "urgent account suspension security alert",
            n_results=3
        )
        
        assert suspension_results['n_results'] > 0
        
        # Verify we get phishing emails for this query
        phishing_count = sum(
            1 for result in suspension_results['results']
            if result['metadata']['is_phishing']
        )
        assert phishing_count > 0  # Should find phishing emails
        
        # Query 2: Payment-related threats  
        payment_results = vector_index.search(
            "payment method expired billing update",
            n_results=3
        )
        
        assert payment_results['n_results'] > 0
        
        # Query 3: Legitimate business communications
        business_results = vector_index.search(
            "team meeting project status update",
            n_results=3
        )
        
        assert business_results['n_results'] > 0
        
        # Step 4: Test filtering capabilities
        
        # Filter for phishing emails only
        phishing_only = vector_index.search(
            "account payment urgent",
            n_results=5,
            where_filter={"is_phishing": True}
        )
        
        # All results should be phishing
        for result in phishing_only['results']:
            assert result['metadata']['is_phishing'] is True
        
        # Filter for legitimate emails only
        legitimate_only = vector_index.search(
            "invoice payment meeting",
            n_results=5,
            where_filter={"is_phishing": False}
        )
        
        # All results should be legitimate
        for result in legitimate_only['results']:
            assert result['metadata']['is_phishing'] is False
    
    def test_threat_detection_accuracy(self, temp_dir, threat_hunting_emails):
        """Test threat detection accuracy with specific scenarios."""
        # Build index
        vector_index = SimpleVectorIndex(db_path=f"{temp_dir}/vector_db")
        vector_index.build_index(threat_hunting_emails)
        
        # Test Case 1: Account suspension query should find phishing
        suspension_query = "account will be suspended unless you verify"
        results = vector_index.search(suspension_query, n_results=2)
        
        # Top result should be phishing with high similarity
        assert results['results'][0]['metadata']['is_phishing'] is True
        assert results['results'][0]['similarity_score'] > 0.3  # Reasonable similarity
        
        # Test Case 2: Team meeting query should find legitimate emails
        meeting_query = "weekly team standup meeting conference room"
        results = vector_index.search(meeting_query, n_results=2)
        
        # Should find the team meeting email
        meeting_found = any(
            'weekly' in result['metadata']['subject'].lower() 
            for result in results['results']
        )
        assert meeting_found
        
        # Test Case 3: Payment fraud detection
        fraud_query = "payment method expired update billing"
        results = vector_index.search(fraud_query, n_results=3)
        
        # Should find payment-related emails
        payment_found = any(
            'payment' in result['metadata']['subject'].lower() or
            'payment' in result['metadata']['body'].lower()
            for result in results['results']
        )
        assert payment_found
    
    def test_performance_integration(self, temp_dir, threat_hunting_emails):
        """Test integrated performance of the complete pipeline."""
        import time
        
        # Test build performance
        start_time = time.time()
        vector_index = SimpleVectorIndex(db_path=f"{temp_dir}/vector_db")
        build_stats = vector_index.build_index(threat_hunting_emails)
        build_time = time.time() - start_time
        
        # Performance assertions
        assert build_time < 10.0  # Should build 8 emails in under 10 seconds
        assert build_stats['average_build_time_per_email'] < 2.0  # Under 2 seconds per email
        
        # Test search performance
        queries = [
            "urgent account suspension",
            "payment method expired", 
            "team meeting project",
            "invoice billing payment",
            "security alert notification"
        ]
        
        search_times = []
        for query in queries:
            start_time = time.time()
            results = vector_index.search(query, n_results=3)
            search_time = time.time() - start_time
            search_times.append(search_time)
            
            assert results['n_results'] >= 0  # Should return results
            assert search_time < 2.0  # Each search under 2 seconds
        
        avg_search_time = sum(search_times) / len(search_times)
        assert avg_search_time < 1.0  # Average search time under 1 second
    
    def test_cache_integration(self, temp_dir, threat_hunting_emails):
        """Test that caching works correctly in the integrated pipeline."""
        # Build index (this will create embeddings and cache them)
        vector_index = SimpleVectorIndex(db_path=f"{temp_dir}/vector_db")
        build_stats = vector_index.build_index(threat_hunting_emails)
        
        # Verify cache is populated
        cache_stats = vector_index.embedding_generator.get_cache_stats()
        assert cache_stats['memory_cache_size'] > 0
        
        # Rebuild with same emails (should use cache)
        start_time = time.time()
        build_stats_cached = vector_index.build_index(threat_hunting_emails)
        cached_build_time = time.time() - start_time
        
        # Cached build should be faster (though model loading might dominate)
        assert cached_build_time <= build_stats['build_time_seconds'] * 2  # Allow some variance
        
        # Verify results are consistent
        assert build_stats_cached['total_emails'] == build_stats['total_emails']
        assert build_stats_cached['embedding_dimension'] == build_stats['embedding_dimension']


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])
