import re
import hashlib
import os
import json
from decouple import config
from sqlalchemy.orm import Session
from ..models.tables import User
from ..utils.loguru_config import logger

def validate_password(password: str, user_id: str, db_session: Session, password_history: list = None) -> bool:
    """
    Validates a password against rules and history.
    
    This function checks if the given password meets complexity requirements,
    whether it matches any previously used passwords, and if the password is valid
    according to predefined rules (length, special characters, etc.).

    :param password: The password to validate.
    :param user_id: The ID of the user to fetch password history from the database.
    :param db_session: The active database session.
    :param password_history: Optional list of previous passwords for validation.
    :return: True if the password is valid, False otherwise.
    """
    # Validate inputs
    if not password or not user_id or not db_session:
        logger.error("Invalid input: password, user_id, and db_session are required.")
        return False

    # Fetch the user from the database
    user = db_session.query(User).filter(User.id == user_id).first()
    if not user:
        logger.warning(f"User with ID {user_id} not found.")
        return False

    # Load password history if not provided
    if password_history is None:
        try:
            password_history = json.loads(user.password_history) if user.password_history else []
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON format in password history: {e}. Resetting history.")
            password_history = []

    if not password_history:
        logger.info("Password history is empty. Skipping history validation.")

    # Validate against password history
    for old_password in password_history:
        if isinstance(old_password, dict) and "salt" in old_password and "hashed_password" in old_password:
            if verify_password(password, old_password["salt"], old_password["hashed_password"]):
                logger.warning("Password has been used before.")
                return False
        else:
            logger.error(f"Invalid password history entry: {old_password}")

    # Validate password complexity
    min_length = int(config("MIN_PASSWORD_LENGTH", default="8"))
    complexity = config("PASSWORD_COMPLEXITY", default="lowercase,numbers").split(",")
    complexity = [req.strip().lower() for req in complexity if req.strip()]
    blocked_words = [word.strip().lower() for word in config("BLOCKED_PASSWORD_WORDS", default="").split(",") if word.strip()]

    if len(password) < min_length:
        logger.warning("Password is too short.")
        return False

    if "uppercase" in complexity and not re.search(r'[A-Z]', password):
        logger.warning("Password is missing an uppercase letter.")
        return False
    if "lowercase" in complexity and not re.search(r'[a-z]', password):
        logger.warning("Password is missing a lowercase letter.")
        return False
    if "numbers" in complexity and not re.search(r'\d', password):
        logger.warning("Password is missing a number.")
        return False
    if "special_characters" in complexity and not re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:\'",.<>?/`~]', password):
        logger.warning("Password is missing a special character.")
        return False

    for word in blocked_words:
        if word in password.lower():
            logger.warning(f"Password contains a blocked word: {word}")
            return False

    logger.info("Password passed all validation checks.")
    return True

def hash_password(password: str) -> tuple:
    """
    Hashes the password using HMAC with a unique salt.

    This function generates a cryptographic hash of the password using a random salt
    and HMAC (Hash-based Message Authentication Code) with a specified number of iterations.

    :param password: The password to hash.
    :return: A tuple containing the salt and the hashed password.
    """
    # Load hashing configuration from .env
    hash_algorithm = config("HASH_ALGORITHM", default="sha256")
    iterations = int(config("HASH_ITERATIONS", default=100000))
    salt_length = int(config("SALT_LENGTH", default=16))

    # Generate a unique salt
    salt = os.urandom(salt_length)

    # Create the HMAC hash using the specified algorithm
    hashed_password = hashlib.pbkdf2_hmac(
        hash_algorithm,  # Hash algorithm
        password.encode('utf-8'),  # Password to hash
        salt,  # Unique salt
        iterations  # Number of iterations
    )

    return salt.hex(), hashed_password.hex()

def verify_password(provided_password: str, stored_salt: str, stored_hash: str) -> bool:
    """
    Verifies if the provided password matches the stored hash using the stored salt.

    This function takes the user's provided password, combines it with the stored salt,
    and checks if the resulting hash matches the stored hash.

    :param provided_password: The password provided by the user.
    :param stored_salt: The salt stored in the database (hex format).
    :param stored_hash: The hashed password stored in the database (hex format).
    :return: True if the password matches, False otherwise.
    """
    # Load hashing configuration from .env
    hash_algorithm = config("HASH_ALGORITHM", default="sha256")
    iterations = int(config("HASH_ITERATIONS", default=100000))

    # Convert the salt back to bytes
    salt = bytes.fromhex(stored_salt)

    # Compute the hash of the provided password
    computed_hash = hashlib.pbkdf2_hmac(
        hash_algorithm,  # Hash algorithm
        provided_password.encode('utf-8'),  # Password to hash
        salt,  # Unique salt
        iterations  # Number of iterations
    )

    # Compare the computed hash with the stored hash
    return computed_hash.hex() == stored_hash

def check_login_attempts(failed_attempts: int) -> bool:
    """
    Checks if the number of failed login attempts exceeds the limit.

    This function ensures that a user is locked out after exceeding a set number of failed login attempts.

    :param failed_attempts: The current number of failed login attempts.
    :return: True if the user should be locked, False otherwise.
    """
    login_attempts_limit = int(config("LOGIN_ATTEMPTS_LIMIT", default=5))
    return failed_attempts >= login_attempts_limit

def update_password_history(user_id: str, new_password: str, db_session: Session) -> None:
    """
    Updates the password history for a user in the database.

    This function adds the new password to the user's password history and ensures that
    the password history does not exceed the configured limit.

    :param user_id: The ID of the user to update.
    :param new_password: The new password to be hashed and added to the history.
    :param db_session: The active database session to commit changes.
    """
    user = db_session.query(User).filter(User.id == user_id).first()
    if not user:
        raise ValueError("User not found")

    salt, hashed_password = hash_password(new_password)

    try:
        password_history = json.loads(user.password_history) if user.password_history else []
    except json.JSONDecodeError:
        logger.error("Password history is not in a valid JSON format. Resetting history.")
        password_history = []

    password_history.append({"salt": salt, "hashed_password": hashed_password})

    password_history_limit = int(config("PASSWORD_HISTORY_LIMIT", default=3))
    if len(password_history) > password_history_limit:
        logger.info("Password history limit reached. Removing oldest password.")
        password_history.pop(0)

    user.salt = salt
    user.hashed_password = hashed_password
    user.password_history = json.dumps(password_history)

    db_session.commit()
    logger.info(f"Password history updated successfully for user ID {user_id}.")
