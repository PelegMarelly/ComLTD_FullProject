from sqlalchemy.orm import Session
from ..models.tables import AuditLog
from ..utils.loguru_config import logger


def create_audit_log_entry(user_id: str, action: str, db: Session):
    """
    Create a new audit log entry to track user actions in the system.

    :param user_id: ID of the user performing the action.
    :param action: Description of the action performed by the user.
    :param db: Database session used to commit the log entry.
    :raises ValueError: If input data is invalid (e.g., empty user_id or action).
    :raises HTTPException: If a database operation fails during the log creation.
    """
    # Log the attempt to create an audit log entry
    logger.info(f"Attempting to create audit log for user_id: {user_id}, action: {action}")

    # Input validation for user_id and action
    if not user_id or not isinstance(user_id, str):  # Check if user_id is valid
        logger.error("Invalid user_id provided for audit log entry.")
        raise ValueError("Invalid user_id. It must be a non-empty string.")

    if not action or not isinstance(action, str):  # Check if action is valid
        logger.error("Invalid action provided for audit log entry.")
        raise ValueError("Invalid action. It must be a non-empty string.")

    try:
        # Create a new audit log entry with sanitized inputs
        new_audit_log = AuditLog(
            user_id=user_id.strip(),  # Remove leading/trailing spaces from user_id
            action=action.strip()  # Remove leading/trailing spaces from action
        )
        db.add(new_audit_log)  # Add the new audit log entry to the session
        db.commit()  # Commit the transaction to the database
        logger.info(f"Audit log created successfully for user_id: {user_id}, action: {action}")  # Log success message
    except Exception as e:
        db.rollback()  # Rollback the transaction in case of error
        logger.error(f"Failed to create audit log for user_id: {user_id}, action: {action}. Error: {e}")  # Log failure
        raise  # Re-raise the exception to propagate the error
