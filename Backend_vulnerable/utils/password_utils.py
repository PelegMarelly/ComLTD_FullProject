import re
import os
import hashlib
import json
from utils.loguru_config import loguru_logger
from db.connection import create_connection, fetch_results, execute_query
from decouple import config

def validate_password(password: str, user_id: str) -> bool:
    """
    Validates a password against rules and history.

    :param password: The password to validate.
    :param user_id: The ID of the user to fetch password history from the database.
    :return: True if the password is valid, False otherwise.
    """
    loguru_logger.info(f"Validating password for user ID: {user_id}")

    connection = create_connection()
    if not connection:
        loguru_logger.error("Failed to connect to the database.")
        return False

    try:
        # Fetch password history
        query = f"SELECT password_history FROM users WHERE id = '{user_id}'"
        result = fetch_results(connection, query)
        password_history = json.loads(result[0]['password_history']) if result and result[0].get('password_history') else []

        # Check if the password has been used before
        for old_password in password_history:
            if "salt" in old_password and "hashed_password" in old_password:
                if verify_password(password, old_password["salt"], old_password["hashed_password"]):
                    loguru_logger.warning("Password has been used before.")
                    return False

        # Password complexity checks
        min_length = int(config("MIN_PASSWORD_LENGTH", default=8))
        if len(password) < min_length:
            loguru_logger.warning(f"Password is too short. Minimum length: {min_length}")
            return False

        complexity = config("PASSWORD_COMPLEXITY", default="lowercase,numbers,uppercase").split(",")
        complexity = [c.strip().lower() for c in complexity]

        if "uppercase" in complexity and not re.search(r'[A-Z]', password):
            loguru_logger.warning("Password is missing an uppercase letter.")
            return False
        if "lowercase" in complexity and not re.search(r'[a-z]', password):
            loguru_logger.warning("Password is missing a lowercase letter.")
            return False
        if "numbers" in complexity and not re.search(r'\d', password):
            loguru_logger.warning("Password is missing a number.")
            return False
        if "special_characters" in complexity and not re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:\'",.<>?/`~]', password):
            loguru_logger.warning("Password is missing a special character.")
            return False

        # Check for forbidden words in the password
        blocked_words = [word.strip().lower() for word in config("BLOCKED_PASSWORD_WORDS", default="password,123456,admin").split(",")]
        for word in blocked_words:
            if word in password.lower():
                loguru_logger.warning(f"Password contains a blocked word: {word}")
                return False

        loguru_logger.info("Password passed all validation checks.")
        return True

    except Exception as e:
        loguru_logger.error(f"Failed to validate password: {e}")
        return False

    finally:
        connection.close()


def hash_password(password: str) -> tuple:
    """
    Hashes the password using HMAC with a unique salt.

    :param password: The password to hash.
    :return: A tuple containing the salt and the hashed password.
    """
    loguru_logger.info("Hashing password...")

    # Configurations from .env
    hash_algorithm = config("HASH_ALGORITHM", default="sha256")
    iterations = int(config("HASH_ITERATIONS", default=100000))
    salt_length = int(config("SALT_LENGTH", default=16))

    # Create a unique salt
    salt = os.urandom(salt_length)

    # Create hash of the password
    hashed_password = hashlib.pbkdf2_hmac(
        hash_algorithm,
        password.encode('utf-8'),
        salt,
        iterations
    )

    loguru_logger.info("Password hashed successfully.")
    return salt.hex(), hashed_password.hex()

def verify_password(provided_password: str, stored_salt: str, stored_hash: str) -> bool:
    """
    Verifies if the provided password matches the stored hash using the stored salt.

    :param provided_password: The password provided by the user.
    :param stored_salt: The salt stored in the database (hex format).
    :param stored_hash: The hashed password stored in the database (hex format).
    :return: True if the password matches, False otherwise.
    """
    loguru_logger.info("Verifying password...")

    # Read configurations from .env
    hash_algorithm = config("HASH_ALGORITHM", default="sha256")
    iterations = int(config("HASH_ITERATIONS", default=100000))

    # Convert to bytes
    salt = bytes.fromhex(stored_salt)

    # Compute the hash
    computed_hash = hashlib.pbkdf2_hmac(
        hash_algorithm,  # Algorithm used for hashing
        provided_password.encode('utf-8'),  # Provided password
        salt,  # Stored salt
        iterations  # Number of iterations
    )

    loguru_logger.info("Password verification completed.")
    return computed_hash.hex() == stored_hash

def update_password_history(user_id: str, new_password: str):
    """
    Updates the password history for a user in the database.

    :param user_id: The ID of the user to update.
    :param new_password: The new password to be hashed and added to the history.
    """
    loguru_logger.info(f"Updating password history for user ID: {user_id}")

    # Connect to the database
    connection = create_connection()
    if not connection:
        loguru_logger.error("Failed to connect to the database.")
        return

    try:
        # Fetch password history using fetch_results from connection.py
        query = f"SELECT password_history FROM users WHERE id = '{user_id}'"
        result = fetch_results(connection, query)
        password_history = json.loads(result[0]['password_history']) if result and result[0].get('password_history') else []

        # Add the new password
        salt, hashed_password = hash_password(new_password)
        password_history.append({"salt": salt, "hashed_password": hashed_password})

        # Password history limit
        password_history_limit = int(config("PASSWORD_HISTORY_LIMIT", default=3))
        if len(password_history) > password_history_limit:
            loguru_logger.info("Password history limit reached. Removing oldest password.")
            password_history.pop(0)

        # Save the updated history to the database
        query_update = f"""
        UPDATE users
        SET password_history = '{json.dumps(password_history)}',
        salt = '{salt}',
        hashed_password = '{hashed_password}'
        WHERE id = '{user_id}'
        """

        execute_query(connection, query_update)
        loguru_logger.info(f"Password history updated successfully for user ID {user_id}.")

    except Exception as e:
        connection.rollback()
        loguru_logger.error(f"Failed to update password history: {e}")

    finally:
        connection.close()
