"""
Main application entry point for the Threat Hunting RAG System.

This module provides the central configuration and logging setup for the entire application.
Use this as the entry point for all major application components.
"""

import os
import sys
import logging
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from shared.config import get_config

# Module logger
logger = logging.getLogger(__name__)


def setup_application() -> None:
    """
    Initialize the application with proper configuration and logging.
    
    This function should be called at the start of any main application component.
    """
    try:
        # Load and validate configuration
        config = get_config()
        
        # Create required directories
        directories_to_create = [
            config.model_cache_dir,
            config.embedding_cache_dir, 
            config.query_cache_dir,
            Path(config.vector_db_path).parent,
            Path(config.email_dataset_path).parent,
            "logs"  # For log files
        ]
        
        for directory in directories_to_create:
            Path(directory).mkdir(parents=True, exist_ok=True)
            logger.debug(f"Created/verified directory: {directory}")
        
        logger.info("🚀 Threat Hunting RAG System initialized successfully")
        logger.info(f"📊 Configuration: debug={config.debug}, log_level={config.log_level}")
        logger.info(f"📁 Data path: {config.email_dataset_path}")
        logger.info(f"🔧 Model: {config.embedding_model}")
        
        return config
        
    except Exception as e:
        # Use basic logging if config setup fails
        logging.basicConfig(level=logging.ERROR)
        logging.error(f"❌ Application setup failed: {e}")
        raise


def main():
    """Main application entry point for testing."""
    config = setup_application()
    
    logger.info("🧪 Running application setup test...")
    
    # Test configuration access
    logger.debug(f"Email dataset path: {config.email_dataset_path}")
    logger.debug(f"Vector DB path: {config.vector_db_path}")
    logger.debug(f"Embedding model: {config.embedding_model}")
    
    # Test logging levels
    logger.debug("🐛 Debug message - detailed diagnostics")
    logger.info("ℹ️  Info message - general information")
    logger.warning("⚠️  Warning message - potential issues") 
    logger.error("❌ Error message - operation failures")
    
    logger.info("✅ Application setup test completed successfully!")


if __name__ == "__main__":
    main()
