"""
Configuration management for the threat hunting RAG system.

This module handles loading and validation of configuration from environment 
variables with secure defaults and validation.
"""

import os
from dataclasses import dataclass
from typing import Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

@dataclass
class Config:
    """Configuration class for the threat hunting RAG system."""
    
    # Model Configuration
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    model_cache_dir: str = "models/"
    
    # Data Paths
    vector_db_path: str = "data/chroma"
    email_dataset_path: str = "data/emails.csv"
    
    # Performance Settings
    phishing_threshold: float = 0.7
    max_results: int = 10
    batch_size: int = 32
    cache_ttl_seconds: int = 3600  # 1 hour cache
    
    # API Configuration (Optional)
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"
    
    # API Server Settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_workers: int = 4
    api_key: Optional[str] = None
    
    # Rate Limiting & Security
    rate_limit_per_minute: int = 100
    rate_limit_burst: int = 20
    enable_api_auth: bool = True
    cors_origins: str = "http://localhost:3000,https://your-domain.com"
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    # Performance Tuning
    enable_query_cache: bool = True
    enable_embedding_cache: bool = True
    max_cache_size: int = 1000
    
    # Development Settings
    debug: bool = False
    verbose_logging: bool = False
    
    # Security Settings
    cli_rate_limit_per_minute: int = 60
    require_admin_confirmation: bool = False
    enable_audit_logging: bool = True
    audit_log_path: str = "logs/security_audit.log"
    enable_input_sanitization: bool = True
    max_query_length: int = 500
    allowed_data_dirs: str = "data/,cache/,models/"
    
    @classmethod
    def from_env(cls) -> 'Config':
        """Load configuration from environment variables."""
        try:
            config = cls(
                # Model settings
                embedding_model=os.getenv('EMBEDDING_MODEL', cls.embedding_model),
                model_cache_dir=os.getenv('MODEL_CACHE_DIR', cls.model_cache_dir),
                
                # Paths
                vector_db_path=os.getenv('VECTOR_DB_PATH', cls.vector_db_path),
                email_dataset_path=os.getenv('EMAIL_DATASET_PATH', cls.email_dataset_path),
                
                # Performance
                phishing_threshold=float(os.getenv('PHISHING_THRESHOLD', cls.phishing_threshold)),
                max_results=int(os.getenv('MAX_RESULTS', cls.max_results)),
                batch_size=int(os.getenv('BATCH_SIZE', cls.batch_size)),
                cache_ttl_seconds=int(os.getenv('CACHE_TTL_SECONDS', cls.cache_ttl_seconds)),
                
                # API keys
                openai_api_key=os.getenv('OPENAI_API_KEY'),
                openai_model=os.getenv('OPENAI_MODEL', cls.openai_model),
                
                # API Server
                api_host=os.getenv('API_HOST', cls.api_host),
                api_port=int(os.getenv('API_PORT', cls.api_port)),
                api_workers=int(os.getenv('API_WORKERS', cls.api_workers)),
                api_key=os.getenv('API_KEY'),
                
                # Rate Limiting
                rate_limit_per_minute=int(os.getenv('RATE_LIMIT_PER_MINUTE', cls.rate_limit_per_minute)),
                rate_limit_burst=int(os.getenv('RATE_LIMIT_BURST', cls.rate_limit_burst)),
                enable_api_auth=os.getenv('ENABLE_API_AUTH', 'true').lower() == 'true',
                cors_origins=os.getenv('CORS_ORIGINS', cls.cors_origins),
                
                # Logging
                log_level=os.getenv('LOG_LEVEL', cls.log_level),
                log_file=os.getenv('LOG_FILE'),
                
                # Caching
                enable_query_cache=os.getenv('ENABLE_QUERY_CACHE', 'true').lower() == 'true',
                enable_embedding_cache=os.getenv('ENABLE_EMBEDDING_CACHE', 'true').lower() == 'true',
                max_cache_size=int(os.getenv('MAX_CACHE_SIZE', cls.max_cache_size)),
                
                # Development
                debug=os.getenv('DEBUG', 'false').lower() == 'true',
                verbose_logging=os.getenv('VERBOSE_LOGGING', 'false').lower() == 'true',
                
                # Security
                cli_rate_limit_per_minute=int(os.getenv('CLI_RATE_LIMIT_PER_MINUTE', cls.cli_rate_limit_per_minute)),
                require_admin_confirmation=os.getenv('REQUIRE_ADMIN_CONFIRMATION', 'false').lower() == 'true',
                enable_audit_logging=os.getenv('ENABLE_AUDIT_LOGGING', 'true').lower() == 'true',
                audit_log_path=os.getenv('AUDIT_LOG_PATH', cls.audit_log_path),
                enable_input_sanitization=os.getenv('ENABLE_INPUT_SANITIZATION', 'true').lower() == 'true',
                max_query_length=int(os.getenv('MAX_QUERY_LENGTH', cls.max_query_length)),
                allowed_data_dirs=os.getenv('ALLOWED_DATA_DIRS', cls.allowed_data_dirs)
            )
            
            logger.info("Configuration loaded successfully from environment")
            return config
            
        except (ValueError, TypeError) as e:
            logger.error(f"Configuration error: {e}")
            logger.info("Using default configuration")
            return cls()
    
    def validate(self) -> bool:
        """Validate configuration values."""
        try:
            # Validate paths exist or can be created
            for path_attr in ['vector_db_path', 'email_dataset_path', 'model_cache_dir']:
                path_value = getattr(self, path_attr)
                path_obj = Path(path_value).parent
                path_obj.mkdir(parents=True, exist_ok=True)
            
            # Validate numeric ranges
            if not 0.0 <= self.phishing_threshold <= 1.0:
                raise ValueError("phishing_threshold must be between 0.0 and 1.0")
            
            if self.max_results <= 0:
                raise ValueError("max_results must be positive")
            
            if self.batch_size <= 0:
                raise ValueError("batch_size must be positive")
            
            # Validate log level
            valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if self.log_level.upper() not in valid_levels:
                raise ValueError(f"log_level must be one of: {valid_levels}")
            
            # Validate API configuration
            if self.enable_api_auth and not self.api_key:
                logger.warning("API authentication enabled but no API key provided")
            
            # Validate rate limiting
            if self.rate_limit_per_minute <= 0:
                raise ValueError("rate_limit_per_minute must be positive")
            
            logger.info("Configuration validation passed")
            return True
            
        except ValueError as e:
            logger.error(f"Configuration validation failed: {e}")
            return False
    
    def setup_logging(self) -> None:
        """Set up logging based on configuration."""
        # Configure logging level
        log_level = getattr(logging, self.log_level.upper())
        
        # Create formatters
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Setup root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
        # File handler (optional)
        if self.log_file:
            log_path = Path(self.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_path)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        
        logger.info(f"Logging configured: level={self.log_level}, file={self.log_file}")
    
    def get_cors_origins_list(self) -> list[str]:
        """Get CORS origins as a list."""
        return [origin.strip() for origin in self.cors_origins.split(',')]
    
    def get_allowed_data_dirs_list(self) -> list[str]:
        """Get allowed data directories as a list."""
        return [dir_path.strip() for dir_path in self.allowed_data_dirs.split(',')]
    
    def __repr__(self) -> str:
        """String representation with sensitive data masked."""
        config_dict = {}
        for key, value in self.__dict__.items():
            if 'key' in key.lower() or 'password' in key.lower():
                config_dict[key] = '***masked***' if value else None
            else:
                config_dict[key] = value
        
        return f"Config({config_dict})"


# Global configuration instance
_config_instance: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config.from_env()
        _config_instance.validate()
        _config_instance.setup_logging()
    return _config_instance


def reload_config() -> Config:
    """Reload configuration from environment."""
    global _config_instance
    _config_instance = None
    return get_config()


if __name__ == "__main__":
    # Test configuration loading
    print("Testing configuration system...")
    
    # Load configuration
    config = get_config()
    print(f"Loaded config: {config}")
    
    # Test validation
    is_valid = config.validate()
    print(f"Configuration valid: {is_valid}")
    
    print("Configuration system test complete!")
