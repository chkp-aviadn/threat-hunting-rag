#!/usr/bin/env python3
"""
Threat Hunting RAG System - Application Bootstrap

This is the main entry point that ensures all prerequisites are met before starting
any component of the system. It provides automated setup and validation.

Usage:
    python app.py --cli                    # Start CLI interface
    python app.py --api                    # Start REST API server
    python app.py --setup                  # Setup system only
    python app.py --reset                  # Wipe dataset + vector index + caches then re-setup
    python app.py --validate               # Validate system status
    python app.py --query "threat query"   # Quick query execution
"""

import os
import sys
import time
import logging
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List

# Add src to Python path for imports
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "src"))

logger = logging.getLogger(__name__)


class SystemBootstrap:
    """
    Comprehensive system bootstrap that ensures all prerequisites are met.
    """
    
    def __init__(self):
        """Initialize bootstrap with system requirements."""
        self.project_root = Path(__file__).parent
        self.data_dir = self.project_root / "data"
        self.cache_dir = self.project_root / "cache"
        self.logs_dir = self.project_root / "logs"
        self.vector_dir = self.data_dir / "chroma"
        self.simple_vector_dir = self.data_dir / "simple_vector_db"
        
        # Required files and their generators
        self.requirements = {
            'email_dataset': {
                'path': self.data_dir / 'emails.csv',
                'generator': self._generate_dataset,
                'description': 'Email dataset (150+ synthetic emails)'
            },
            'vector_index': {
                'path': self.data_dir / 'chroma',
                'generator': self._build_vector_index,
                'description': 'ChromaDB vector index for semantic search'
            },
            'config_file': {
                'path': self.project_root / '.env',
                'generator': self._create_config,
                'description': 'Environment configuration file'
            }
        }
        
        # Setup centralized logging early (before any other imports that may emit logs)
        self._setup_central_logging()
    
    def _setup_central_logging(self):
        """Initialize centralized logging using shared logging configuration.

        Falls back to simple bootstrap file logging if centralized config import fails.
        """
        self.logs_dir.mkdir(exist_ok=True)
        try:
            # Import after path adjustments; ensures single rotating file + console
            from src.shared.logging_config import init_logging  # type: ignore
            init_logging(logging.INFO)
        except Exception:
            # Fallback minimal logging (should rarely trigger)
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s | %(levelname)s | %(name)s | %(message)s',
                handlers=[
                    logging.StreamHandler(),
                    logging.FileHandler(self.logs_dir / 'bootstrap_fallback.log')
                ]
            )
        logger.info("🚀 Starting Threat Hunting RAG System Bootstrap")
    
    def check_prerequisites(self) -> Dict[str, Any]:
        """
        Check all system prerequisites and return status.
        
        Returns:
            Dict containing status of each requirement
        """
        logger.info("🔍 Checking system prerequisites...")
        
        status = {
            'all_ready': True,
            'requirements': {},
            'missing': [],
            'ready': []
        }
        
        for req_name, req_info in self.requirements.items():
            path = req_info['path']
            
            # Special handling for vector_index (ChromaDB or SimpleVectorStore)
            if req_name == 'vector_index':
                # Check ChromaDB directory or SimpleVectorStore fallback
                chroma_exists = path.exists() and any(path.iterdir()) if path.is_dir() else False
                simple_db_path = self.data_dir / 'simple_vector_db' 
                simple_exists = simple_db_path.exists() and any(simple_db_path.iterdir()) if simple_db_path.is_dir() else False
                exists = chroma_exists or simple_exists
            else:
                exists = path.exists()
            
            status['requirements'][req_name] = {
                'exists': exists,
                'path': str(path),
                'description': req_info['description']
            }
            
            if exists:
                status['ready'].append(req_name)
                logger.info(f"  ✅ {req_info['description']}: Found at {path}")
            else:
                status['missing'].append(req_name)
                status['all_ready'] = False
                logger.warning(f"  ❌ {req_info['description']}: Missing at {path}")
        
        # Check Python dependencies
        deps_status = self._check_python_dependencies()
        if not deps_status:
            status['all_ready'] = False
            status['missing'].append('python_dependencies')
        
        return status
    
    def _check_python_dependencies(self) -> bool:
        """Check if required Python packages are installed."""
        try:
            import pandas
            import numpy
            import sentence_transformers
            import fastapi
            import pydantic
            logger.info("  ✅ Python dependencies: All required packages available")
            return True
        except ImportError as e:
            logger.error(f"  ❌ Python dependencies: Missing package - {e}")
            return False
    
    def setup_system(self, force: bool = False) -> bool:
        """
        Setup the complete system by ensuring all prerequisites are met.
        
        Args:
            force: If True, regenerate even if files exist
            
        Returns:
            True if setup successful, False otherwise
        """
        logger.info("🔧 Setting up Threat Hunting RAG System...")
        
        try:
            # Create base directories
            self._create_directories()
            
            # Check current status
            status = self.check_prerequisites()
            
            if status['all_ready'] and not force:
                logger.info("✅ System already configured and ready!")
                return True
            
            # Generate missing components
            for req_name in status['missing']:
                if req_name == 'python_dependencies':
                    logger.error("❌ Please install Python dependencies: pip install -r requirements.txt")
                    return False
                
                if req_name in self.requirements:
                    req_info = self.requirements[req_name]
                    logger.info(f"🔧 Generating {req_info['description']}...")
                    
                    success = req_info['generator']()
                    if not success:
                        logger.error(f"❌ Failed to generate {req_info['description']}")
                        return False
                    
                    logger.info(f"✅ Generated {req_info['description']}")
            
            # Final validation
            final_status = self.check_prerequisites()
            if final_status['all_ready']:
                logger.info("🎉 System setup completed successfully!")
                self._print_system_summary()
                return True
            else:
                logger.error("❌ System setup incomplete")
                return False
        
        except Exception as e:
            logger.error(f"❌ System setup failed: {e}")
            return False
    
    def _create_directories(self):
        """Create all required directories."""
        directories = [
            self.data_dir,
            self.cache_dir,
            self.logs_dir,
            self.cache_dir / "embeddings",
            self.cache_dir / "models", 
            self.cache_dir / "query_results"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Created directory: {directory}")

    def reset_system(self) -> bool:
        """Fully remove dataset, vector indices, and relevant caches, then run setup.

        Returns:
            True if reset & setup succeeded, False otherwise.
        """
        logger.info("🧹 Performing full system reset (dataset + vector index + caches)...")
        try:
            # Remove dataset file
            dataset_path = self.data_dir / 'emails.csv'
            if dataset_path.exists():
                dataset_path.unlink()
                logger.info(f"   🗑 Removed dataset: {dataset_path}")

            # Remove ChromaDB directory
            if self.vector_dir.exists():
                import shutil
                shutil.rmtree(self.vector_dir)
                logger.info(f"   🗑 Removed Chroma vector dir: {self.vector_dir}")

            # Remove simple vector fallback dir if present
            if self.simple_vector_dir.exists():
                import shutil
                shutil.rmtree(self.simple_vector_dir)
                logger.info(f"   🗑 Removed simple vector dir: {self.simple_vector_dir}")

            # Remove cache subdirectories selectively (not logs)
            if self.cache_dir.exists():
                for sub in ["embeddings", "models", "query_results"]:
                    target = self.cache_dir / sub
                    if target.exists():
                        import shutil
                        shutil.rmtree(target)
                        logger.info(f"   🗑 Cleared cache: {target}")

            # Recreate directories
            self._create_directories()
            logger.info("🔄 Re-running setup after reset...")
            return self.setup_system(force=True)
        except Exception as e:
            logger.error(f"❌ Reset failed: {e}")
            return False
    
    def _generate_dataset(self) -> bool:
        """Generate email dataset."""
        try:
            logger.info("📊 Generating synthetic email dataset...")
            result = subprocess.run([
                sys.executable, 
                str(self.project_root / "src" / "data_preparation" / "generators" / "generate_dataset.py")
            ], cwd=self.project_root, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("📧 Email dataset generated successfully")
                return True
            else:
                logger.error(f"Dataset generation failed: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Dataset generation error: {e}")
            return False
    
    def _build_vector_index(self) -> bool:
        """Build ChromaDB vector search index using UnifiedSearchService."""
        try:
            logger.info("🔍 Building ChromaDB vector search index...")
            
            # Add src to Python path
            sys.path.insert(0, str(self.project_root / "src"))
            
            # Import and use UnifiedSearchService to build the complete pipeline
            from query_processing.services.unified_search import UnifiedSearchService
            
            search_service = UnifiedSearchService()
            
            # This will automatically:
            # 1. Load emails from CSV
            # 2. Build ChromaDB vector index  
            # 3. Create searchable index
            success = search_service.ensure_index_ready()
            
            if success:
                logger.info("🎯 ChromaDB vector index built successfully")
                
                # Get stats to show what was built
                stats = search_service.get_stats()
                logger.info(f"   📊 Indexed {stats['total_emails']} emails")
                logger.info(f"   📧 Phishing: {stats['phishing_emails']}, Legitimate: {stats['legitimate_emails']}")
                
                return True
            else:
                logger.error("ChromaDB vector index build failed")
                return False
                
        except Exception as e:
            logger.error(f"ChromaDB vector index build error: {e}")
            return False
    
    def _create_config(self) -> bool:
        """Create configuration file from template."""
        try:
            source = self.project_root / ".env.example"
            target = self.project_root / ".env"
            
            if source.exists():
                import shutil
                shutil.copy2(source, target)
                logger.info("⚙️ Configuration file created from template")
                return True
            else:
                # Create minimal config
                config_content = """# Threat Hunting RAG System Configuration
EMAIL_DATASET_PATH=data/emails.csv
VECTOR_DB_PATH=data/simple_vector_db
EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
MAX_RESULTS=10
API_KEY=demo-key-12345
DEBUG=false
"""
                target.write_text(config_content)
                logger.info("⚙️ Minimal configuration file created")
                return True
        except Exception as e:
            logger.error(f"Config creation error: {e}")
            return False
    
    def _print_system_summary(self):
        """Print system summary after successful setup."""
        logger.info("\n" + "="*60)
        logger.info("🛡️  THREAT HUNTING RAG SYSTEM - READY")
        logger.info("="*60)
        
        # Check dataset stats
        try:
            import pandas as pd
            df = pd.read_csv(self.data_dir / "emails.csv")
            phishing_count = len(df[df['is_phishing'] == True])
            logger.info(f"📊 Dataset: {len(df)} emails ({phishing_count} phishing)")
        except:
            logger.info("📊 Dataset: Available")
        
        logger.info("🔍 Vector Index: Ready for semantic search")
        logger.info("⚙️ Configuration: Loaded")
        logger.info("")
        logger.info("🚀 Ready to start threat hunting!")
    
    def start_cli(self, query: Optional[str] = None):
        """Start CLI interface."""
        logger.info("💻 Starting CLI interface...")
        
        try:
            if query:
                # Execute single query
                cmd = [
                    sys.executable, "-m", "src.interfaces.cli.app",
                    "--query", query
                ]
            else:
                # Interactive mode
                cmd = [
                    sys.executable, "-m", "src.interfaces.cli.app",
                    "--interactive"
                ]
            
            subprocess.run(cmd, cwd=self.project_root)
        except KeyboardInterrupt:
            logger.info("👋 CLI session ended")
        except Exception as e:
            logger.error(f"CLI error: {e}")
    
    def start_api(self, host: str = "localhost", port: int = 8000):
        """Start API server."""
        logger.info(f"🌐 Starting API server on http://{host}:{port}")
        
        try:
            cmd = [
                sys.executable, "-m", "src.interfaces.api.app"
            ]
            
            # Set environment variables
            env = os.environ.copy()
            env["API_HOST"] = host
            env["API_PORT"] = str(port)
            
            subprocess.run(cmd, cwd=self.project_root, env=env)
        except KeyboardInterrupt:
            logger.info("👋 API server stopped")
        except Exception as e:
            logger.error(f"API error: {e}")


def main():
    """Main application entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description="Threat Hunting RAG System - Intelligent Phishing Detection",
        epilog="""
Examples:
  python app.py --setup                     # Setup system
  python app.py --cli                       # Start CLI interface
  python app.py --api                       # Start API server
  python app.py --query "urgent payments"   # Execute single query
  python app.py --validate                  # Check system status
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Command options
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--setup", action="store_true", help="Setup system prerequisites")
    group.add_argument("--reset", action="store_true", help="Reset dataset, vector index and caches then re-setup")
    group.add_argument("--validate", action="store_true", help="Validate system status")
    group.add_argument("--cli", action="store_true", help="Start CLI interface")
    group.add_argument("--api", action="store_true", help="Start REST API server")
    group.add_argument("--query", type=str, help="Execute single query")
    
    # Additional options
    parser.add_argument("--force", action="store_true", help="Force regeneration of existing components")
    parser.add_argument("--host", default="localhost", help="API server host (default: localhost)")
    parser.add_argument("--port", type=int, default=8000, help="API server port (default: 8000)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Adjust logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize bootstrap
    bootstrap = SystemBootstrap()
    
    try:
        if args.setup:
            # Setup system
            success = bootstrap.setup_system(force=args.force)
            sys.exit(0 if success else 1)
        elif args.reset:
            # Full reset then setup
            success = bootstrap.reset_system()
            sys.exit(0 if success else 1)
        
        elif args.validate:
            # Validate system status
            status = bootstrap.check_prerequisites()
            if status['all_ready']:
                print("✅ System is ready for operation")
                sys.exit(0)
            else:
                print("❌ System has missing prerequisites:")
                for missing in status['missing']:
                    req = status['requirements'].get(missing, {})
                    print(f"  - {req.get('description', missing)}")
                print("\nRun 'python app.py --setup' to initialize the system")
                sys.exit(1)
        
        elif args.cli or args.query:
            # Ensure system is ready
            status = bootstrap.check_prerequisites()
            if not status['all_ready']:
                logger.error("❌ System not ready. Run 'python app.py --setup' first")
                sys.exit(1)
            
            # Start CLI
            bootstrap.start_cli(query=args.query)
        
        elif args.api:
            # Ensure system is ready
            status = bootstrap.check_prerequisites()
            if not status['all_ready']:
                logger.error("❌ System not ready. Run 'python app.py --setup' first")
                sys.exit(1)
            
            # Start API server
            bootstrap.start_api(host=args.host, port=args.port)
    
    except KeyboardInterrupt:
        logger.info("👋 Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Application error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()