import logging
import os
import sys
from pathlib import Path

# Create logs directory if it doesn't exist
log_dir = Path(os.getcwd()) / "logs"
log_dir.mkdir(exist_ok=True)

# Format for evidence/forensic logging (timestamp, level, module, message)
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

def get_logger(name: str) -> logging.Logger:
    """Get a configured logger for the application."""
    logger = logging.getLogger(name)

    # Only configure if not already configured
    if not logger.handlers:
        logger.setLevel(logging.INFO)

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
        logger.addHandler(console_handler)

        # File handler
        file_handler = logging.FileHandler(log_dir / "securemailscope.log")
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
        logger.addHandler(file_handler)

    return logger
