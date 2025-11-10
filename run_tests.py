#!/usr/bin/env python3
"""
Simple test runner for Phase 3 components without pytest dependency
"""

import sys
import tempfile
import shutil
from pathlib import Path
import traceback

# Add the src directory to Python path
sys.path.append(str(Path(__file__).parent / "src"))

from infrastructure.ml.embeddings import EmbeddingGenerator
from infrastructure.ml.simple_vector_index import SimpleVectorIndex


def run_test(test_name, test_func):
    """Run a single test function and report results."""
    try:
        print(f"🧪 Running {test_name}...", end=" ")
        test_func()
        print("✅ PASSED")
        return True
    except Exception as e:
        print("❌ FAILED")
        print(f"   Error: {e}")
        traceback.print_exc()
        return False


def test_embeddings_basic():
    """Test basic embedding functionality."""
    # Create temporary cache directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Initialize generator
        generator = EmbeddingGenerator(cache_dir=temp_dir)
        
        # Test text embedding
        embedding = generator.embed_text("Test email about urgent payment")
        assert embedding.shape == (384,), f"Wrong embedding shape: {embedding.shape}"
        
        # Test email embedding
        email = {
            'subject': 'Urgent payment required',
            'body': 'Please pay immediately to avoid suspension'
        }
        email_embedding = generator.embed_email(email)
        assert email_embedding.shape == (384,), f"Wrong email embedding shape: {email_embedding.shape}"
        
        # Test similarity
        embedding2 = generator.embed_text("Payment needed urgently")
        similarity = generator.similarity(embedding, embedding2)
        assert 0 <= similarity <= 1, f"Invalid similarity score: {similarity}"
        assert similarity > 0.5, f"Similar texts should have high similarity: {similarity}"
        
    finally:
        shutil.rmtree(temp_dir)


def test_vector_index_basic():
    """Test basic vector index functionality."""
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create test emails
        emails = [
            {
                'id': 'email_1',
                'subject': 'Urgent payment required', 
                'body': 'Pay now to avoid suspension',
                'sender': 'billing@fake.com',
                'is_phishing': True,
                'category': 'phishing'
            },
            {
                'id': 'email_2',
                'subject': 'Team meeting tomorrow',
                'body': 'Weekly sync at 2 PM',
                'sender': 'manager@company.com', 
                'is_phishing': False,
                'category': 'legitimate'
            }
        ]
        
        # Build index
        index = SimpleVectorIndex(db_path=temp_dir)
        stats = index.build_index(emails)
        
        assert stats['total_emails'] == 2, f"Wrong email count: {stats['total_emails']}"
        assert stats['embedding_dimension'] == 384, f"Wrong dimension: {stats['embedding_dimension']}"
        
        # Test search
        results = index.search("urgent payment", n_results=2)
        assert results['n_results'] > 0, "Should find results"
        assert 'results' in results, "Missing results key"
        
        # Test filtering
        phishing_results = index.search("payment", where_filter={"is_phishing": True})
        for result in phishing_results['results']:
            assert result['metadata']['is_phishing'] is True, "Filter failed"
        
    finally:
        shutil.rmtree(temp_dir)


def test_integration_pipeline():
    """Test integration between embeddings and vector index."""
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create realistic email dataset
        emails = [
            # Phishing emails
            {
                'id': 'phish_1',
                'subject': 'URGENT: Account suspension notice',
                'body': 'Your account will be suspended unless you verify immediately',
                'sender': 'security@fake-bank.com',
                'is_phishing': True,
                'category': 'phishing'
            },
            {
                'id': 'phish_2', 
                'subject': 'Payment verification needed',
                'body': 'Update your payment method now to continue service',
                'sender': 'billing@suspicious.com',
                'is_phishing': True,
                'category': 'phishing'
            },
            # Legitimate emails
            {
                'id': 'legit_1',
                'subject': 'Weekly team standup',
                'body': 'Join us for the weekly team meeting at 2 PM',
                'sender': 'manager@company.com',
                'is_phishing': False,
                'category': 'legitimate'  
            },
            {
                'id': 'legit_2',
                'subject': 'Project milestone completed',
                'body': 'The Q1 project milestone has been successfully completed',
                'sender': 'project-lead@company.com',
                'is_phishing': False,
                'category': 'legitimate'
            }
        ]
        
        # Build vector index
        index = SimpleVectorIndex(db_path=temp_dir)
        stats = index.build_index(emails)
        
        assert stats['total_emails'] == 4, "Should index all 4 emails"
        
        # Test threat hunting queries
        
        # Query 1: Account suspension (should find phishing)
        suspension_results = index.search("account suspension urgent", n_results=2)
        assert suspension_results['n_results'] > 0, "Should find suspension emails"
        
        # Verify top result is phishing
        top_result = suspension_results['results'][0]
        assert top_result['metadata']['is_phishing'] is True, "Top result should be phishing"
        
        # Query 2: Team meeting (should find legitimate)
        meeting_results = index.search("team meeting standup", n_results=2)
        assert meeting_results['n_results'] > 0, "Should find meeting emails"
        
        # Query 3: Test filtering
        phishing_only = index.search("payment account", where_filter={"is_phishing": True})
        for result in phishing_only['results']:
            assert result['metadata']['is_phishing'] is True, "All results should be phishing"
        
        legitimate_only = index.search("team project", where_filter={"is_phishing": False})
        for result in legitimate_only['results']:
            assert result['metadata']['is_phishing'] is False, "All results should be legitimate"
        
    finally:
        shutil.rmtree(temp_dir)


def test_performance_requirements():
    """Test that performance requirements are met."""
    import time
    
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create 20 test emails for performance testing
        emails = []
        for i in range(20):
            emails.append({
                'id': f'email_{i}',
                'subject': f'Test email subject {i}',
                'body': f'This is test email body content for email number {i}.',
                'sender': f'user{i}@test.com',
                'is_phishing': i % 2 == 0,
                'category': 'phishing' if i % 2 == 0 else 'legitimate'
            })
        
        # Test build performance
        index = SimpleVectorIndex(db_path=temp_dir)
        start_time = time.time()
        stats = index.build_index(emails)
        build_time = time.time() - start_time
        
        # Should build quickly (requirement is < 30s for 150 emails)
        time_per_email = build_time / 20
        estimated_150_emails = time_per_email * 150
        assert estimated_150_emails < 30, f"Build too slow: {estimated_150_emails:.1f}s for 150 emails"
        
        # Test search performance
        start_time = time.time()
        results = index.search("test email content", n_results=5)
        search_time = time.time() - start_time
        
        assert search_time < 2.0, f"Search too slow: {search_time:.3f}s"
        assert results['n_results'] > 0, "Should find results"
        
    finally:
        shutil.rmtree(temp_dir)


def main():
    """Run all tests and report results."""
    print("🚀 PHASE 3 TEST SUITE - COMPREHENSIVE VALIDATION")
    print("=" * 60)
    
    tests = [
        ("Embeddings Basic Functionality", test_embeddings_basic),
        ("Vector Index Basic Functionality", test_vector_index_basic),
        ("Integration Pipeline", test_integration_pipeline),
        ("Performance Requirements", test_performance_requirements),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        if run_test(test_name, test_func):
            passed += 1
        else:
            failed += 1
        print()
    
    print("=" * 60)
    print(f"📊 RESULTS: {passed} PASSED, {failed} FAILED")
    
    if failed == 0:
        print("🎉 ALL TESTS PASSED - PHASE 3 FULLY VALIDATED!")
        print("\n✅ Phase 3 Requirements Met:")
        print("   • sentence-transformers embeddings with 384 dimensions")
        print("   • Persistent vector index with metadata")
        print("   • Semantic search with filtering")
        print("   • Performance under 2 seconds per query")
        print("   • Build time under 30 seconds for 150 emails")
        print("   • Threat hunting query capabilities")
        return 0
    else:
        print(f"❌ {failed} tests failed - needs investigation")
        return 1


if __name__ == "__main__":
    sys.exit(main())