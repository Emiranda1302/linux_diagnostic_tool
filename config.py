"""Configuration module for LDT"""

import logging
import logging.handlers
from pathlib import Path

# Logging configuration
LOG_DIR = Path.home() / ".ldt" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "ldt.log"

# Logger setup
def get_logger(name: str) -> logging.Logger:
    """Get or create a logger instance"""
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        # Create handlers
        file_handler = logging.FileHandler(LOG_FILE)
        console_handler = logging.StreamHandler()
        
        # Create formatters
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        # Set level
        logger.setLevel(logging.INFO)
    
    return logger
