# Log file setup and rotation
import logging
from logging.handlers import RotatingFileHandler

# Function to setup logging configuration
def setup_logging():
    """
    Sets up logging with a rotating file handler.
    """
    log_file = "traffic_log.txt"  # File to store logs
    log_handler = RotatingFileHandler(
        log_file,
        maxBytes=1024 * 1024,  # Maximum size of each log file: 1MB
        backupCount=5,  # Keep 5 backup log files
    )
    logging.basicConfig(
        handlers=[log_handler],
        level=logging.INFO,  # Log level: INFO
        format="%(asctime)s | %(message)s",  # Log format
        datefmt="%Y-%m-%d %H:%M:%S",  # Date format
    )
