import logging
import os
from typing import Optional

def setup_logger(log_file: Optional[str] = "logs/analysis.log", verbose: bool = False) -> logging.Logger:
    """
    Sets up the logger. If a log_file path is specified, it writes log messages to that file.
    If verbose is True, sets the logging level to DEBUG, otherwise INFO.
    """
    logger = logging.getLogger("phishing_analyzer")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Avoid adding multiple handlers if setup is called multiple times
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(console_handler)

    # File handler
    if log_file:
        try:
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)  # Always log debug to file
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not setup file log handler for '{log_file}': {e}")

    return logger

def get_logger() -> logging.Logger:
    """
    Gets the existing package logger.
    """
    return logging.getLogger("phishing_analyzer")
