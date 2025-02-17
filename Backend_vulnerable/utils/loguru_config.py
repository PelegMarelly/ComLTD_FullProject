from loguru import logger
import sys
import os

def setup_loguru():
    """
    Setup Loguru logger with console and file handlers.
    :return: Configured Loguru logger.
    """
    # Clear default handlers to avoid duplicate logs
    logger.remove()

    # Add console handler
    logger.add(
        sys.stdout,  # Direct the log output to the console
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level}</level> | "
               "<magenta>{name}</magenta>:<light-magenta>{function}</light-magenta>:<light-yellow>{line}</light-yellow> | <level>{message}</level>",  # Define log format
        level="DEBUG",  # Console log level (shows all logs from DEBUG level and above)
        colorize=True,  # Enable colored output for better readability
    )

    # Directory for log files
    log_dir = "logs"  # Set the log directory path
    os.makedirs(log_dir, exist_ok=True)  # Ensure the logs directory exists (create if not)

    # Add file handler
    logger.add(
        os.path.join(log_dir, "app_{time:YYYY-MM-DD}.log"),  # Log file with daily rotation based on date
        rotation="1 day",  # Create a new log file every day
        retention="7 days",  # Keep logs for 7 days before deletion
        compression="zip",  # Compress old logs to save space
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",  # Log format for file
        level="INFO",  # File log level (logs from INFO level and above)
    )

    return logger  # Return the configured logger

loguru_logger = setup_loguru()  # Initialize the Loguru logger with the defined settings
