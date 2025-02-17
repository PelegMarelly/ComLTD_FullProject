from loguru import logger
import sys
import os

def setup_loguru():
    """
    Set up Loguru logger with both console and file handlers.
    Configures Loguru to log messages to both the console and a rotating log file.
    Creates a new log file every day and compresses old logs. The retention is set to 7 days.

    :return: Configured Loguru logger instance.
    """
    # Clear default handlers to avoid duplicate logs
    logger.remove()

    # Add console handler to output logs to the console (stdout)
    logger.add(
        sys.stdout,  # Use standard output for console logging
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level}</level> | "
               "<cyan>{name}</cyan>:<light-blue>{function}</light-blue>:<yellow>{line}</yellow> | <level>{message}</level>",
        level="DEBUG",  # Set the log level to DEBUG for console output (show all messages including debug)
        colorize=True,  # Enable colorization of log output in the console
    )

    # Directory for storing log files
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)  # Ensure that the logs directory exists (creates it if not)

    # Add file handler to output logs to a file, with daily rotation and 7-day retention
    logger.add(
        os.path.join(log_dir, "app_{time:YYYY-MM-DD}.log"),  # File name includes the current date
        rotation="1 day",  # Create a new log file every day
        retention="7 days",  # Retain logs for 7 days before they are deleted
        compression="zip",  # Compress old logs to save space
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",  # Log format
        level="INFO",  # Set the log level to INFO for file logs (show messages from INFO and higher)
    )

    return logger

loguru_logger = setup_loguru()  # Set up and return the configured Loguru logger instance
