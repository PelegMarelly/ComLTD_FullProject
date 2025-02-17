import re
from html import escape
from ..utils.loguru_config import logger  # Import logger for logging


# Compile patterns once and reuse
# XSS patterns to detect potential Cross-Site Scripting attacks
XSS_PATTERNS = [
    re.compile(r"<.*?>", re.IGNORECASE),  # Detects HTML tags
    re.compile(r"javascript:.*", re.IGNORECASE),  # Detects JavaScript-based XSS attacks
    re.compile(r"on\w+=\".*?\"", re.IGNORECASE),  # Detects inline event handlers like onClick, onLoad
    re.compile(r"&[a-zA-Z]+;", re.IGNORECASE),  # Detects HTML entities
]

# SQL patterns to detect potential SQL Injection attacks
SQL_PATTERNS = [
    re.compile(r"(--|;|/*|\*/|\\x27|\\x22|\\x2f\\x2a)", re.IGNORECASE),  # Detects SQL special characters and comments
    re.compile(r"(['\"]\s*(OR|AND)\s*['\"]|(['\"]\s*=\s*['\"]))", re.IGNORECASE),  # Detects 'OR'/'AND' SQL conditions
    re.compile(r"(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC).*", re.IGNORECASE),  # Detects SQL commands
    re.compile(r"\b(\d+\s*=\s*\d+)\b", re.IGNORECASE),  # Detects numeric equality
]

def contains_xss(value: str) -> bool:
    """
    Check if the provided value contains any potential XSS patterns.

    :param value: The input value to check.
    :return: True if XSS pattern is detected, False otherwise.
    """
    if not value:
        return False  # Return False if input is empty
    for pattern in XSS_PATTERNS:
        if pattern.search(value):
            logger.warning(f"XSS pattern detected: {pattern.pattern} in value: {value}")
            return True  # Return True if any XSS pattern is detected
    return False  # Return False if no XSS pattern is found

def contains_sql_injection(value: str) -> bool:
    """
    Check if the provided value contains any potential SQL injection patterns.

    :param value: The input value to check.
    :return: True if SQL injection pattern is detected, False otherwise.
    """
    if not value:
        return False  # Return False if input is empty
    for pattern in SQL_PATTERNS:
        if pattern.search(value):
            logger.warning(f"SQL Injection pattern detected: {pattern.pattern} in value: {value}")
            return True  # Return True if any SQL injection pattern is detected
    return False  # Return False if no SQL injection pattern is found

def sanitize_input(input_value: str) -> str:
    """
    Escape special characters in the input to prevent XSS attacks.

    :param input_value: The input value to sanitize.
    :return: Sanitized string that is safe for HTML output.
    """
    logger.debug(f"Sanitizing input: {input_value}")
    if not isinstance(input_value, str):  # Ensure input is a string
        logger.error("Input for sanitization is not a string.")
        raise ValueError("Input must be a string.")
    sanitized_value = escape(input_value)  # Escape special HTML characters like <, >, & to prevent XSS
    if sanitized_value != input_value:  # Log the sanitized input if it was changed
        logger.debug(f"Sanitized input: Original: {input_value}, Sanitized: {sanitized_value}")
    else:
        logger.debug(f"Input --> {input_value} is valid!")  # Log if no change was made
    return sanitized_value  # Return the sanitized input

def prevent_sql_injection(input_value: str) -> str:
    """
    Detect and sanitize SQL Injection attempts by removing dangerous keywords and characters.

    :param input_value: The input value to sanitize.
    :return: Sanitized string that is safe from SQL injection attacks.
    """
    logger.debug(f"Checking for SQL injection in input: {input_value}")
    if not isinstance(input_value, str):  # Ensure input is a string
        logger.error("Input for SQL injection prevention is not a string.")
        raise ValueError("Input must be a string.")

    # List of SQL keywords and patterns to block to prevent SQL injection
    dangerous_patterns = [
        r"(?i)(\bSELECT\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b|\bDROP\b|\bALTER\b|\bCREATE\b|\bEXEC\b|\bUNION\b|\b--\b|\b;\b|\bOR\b|\bAND\b)",
        r"(--|;|\\'|\\\")"  # SQL special characters to block
    ]

    sanitized_value = input_value  # Start with the original input value
    for pattern in dangerous_patterns:  # Check and remove dangerous patterns
        if re.search(pattern, sanitized_value):
            logger.warning(f"Potential SQL injection pattern detected in {sanitized_value}")
        sanitized_value = re.sub(pattern, "", sanitized_value)  # Replace dangerous patterns with empty string

    logger.debug(f"SQL-safe input: Original: {input_value}, Sanitized: {sanitized_value}")
    return sanitized_value  # Return the sanitized value free of SQL injection risks
