import logging
import os
import sys
from datetime import datetime

class Logger:
    """Centralized logging system for NetScan Studio"""
    
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        self.ensure_log_dir()
        self.setup_logging()
    
    def ensure_log_dir(self):
        """Create logs directory if it doesn't exist"""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
    
    def setup_logging(self):
        """Configure logging with both file and console handlers"""
        log_filename = os.path.join(
            self.log_dir,
            f"netscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        
        # Configure logging
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        
        # File handler
        file_handler = logging.FileHandler(log_filename, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler with error handling
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        # Handle Unicode errors gracefully in console output
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        
        # Add handlers
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        self.logger = logging.getLogger("NetScan Studio")
    
    def get_logger(self, name):
        """Get logger instance for a module"""
        logger = logging.getLogger(name)
        # Configure stream handler with error handling
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                if hasattr(handler, 'stream'):
                    # This will help with Unicode on Windows
                    pass
        return logger
    
    def info(self, message):
        self.logger.info(message)
    
    def error(self, message):
        self.logger.error(message)
    
    def warning(self, message):
        self.logger.warning(message)
    
    def debug(self, message):
        self.logger.debug(message)

# Global logger instance
_logger = Logger()
get_logger = _logger.get_logger
