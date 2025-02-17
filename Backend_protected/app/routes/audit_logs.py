from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from ..models.tables import AuditLog, User
from ..models.database import get_db
from ..utils.loguru_config import logger
from ..utils.attack_detectors import sanitize_input, prevent_sql_injection

router = APIRouter()

# Models for request validation
class AuditLogCreate(BaseModel):
    """
    Pydantic model for validating the structure of audit log creation requests.

    Attributes:
        user_id: ID of the user performing the action.
        action: Description of the action performed by the user.
    """
    user_id: str
    action: str

@router.get("/")
def get_audit_logs(db: Session = Depends(get_db)):
    """
    Fetch all audit logs from the database.

    :param db: Database session.
    :return: List of all audit logs.
    """
    logger.info("Fetching all audit logs from the database.")
    audit_logs = db.query(AuditLog).all()  # Query to fetch all audit logs
    logger.debug(f"Fetched {len(audit_logs)} audit logs.")
    return audit_logs

@router.get("/{log_id}")
def get_audit_log(log_id: int, db: Session = Depends(get_db)):
    """
    Fetch a specific audit log by its ID.

    :param log_id: The ID of the audit log to fetch.
    :param db: Database session.
    :return: Audit log details.
    """
    sanitized_log_id = prevent_sql_injection(log_id)  # Prevents SQL Injection
    logger.info(f"Fetching audit log with ID: {sanitized_log_id}")
    audit_log = db.query(AuditLog).filter(AuditLog.id == sanitized_log_id).first()  # Query for specific audit log
    if not audit_log:
        logger.warning(f"Audit log with ID {sanitized_log_id} not found.")
        raise HTTPException(status_code=404, detail="Audit log not found")  # Raise 404 if not found
    logger.debug(f"Fetched audit log details: {audit_log}")
    return audit_log

@router.get("/user/{user_id}")
def get_audit_logs_by_user(user_id: str, db: Session = Depends(get_db)):
    """
    Fetch all audit logs for a specific user.

    :param user_id: The ID of the user.
    :param db: Database session.
    :return: List of audit logs for the user.
    """
    sanitized_user_id = sanitize_input(user_id)  # Protects against XSS (cross-site scripting attacks)
    logger.info(f"Fetching audit logs for user ID: {sanitized_user_id}")
    audit_logs = db.query(AuditLog).filter(AuditLog.user_id == sanitized_user_id).all()  # Query for user-specific logs
    logger.debug(f"Fetched {len(audit_logs)} audit logs for user ID {sanitized_user_id}.")
    return audit_logs

@router.post("/")
def create_audit_log(audit_log: AuditLogCreate, db: Session = Depends(get_db)):
    """
    Create a new audit log entry in the database.

    :param audit_log: Details of the audit log to create.
    :param db: Database session.
    :return: Details of the created audit log.
    """
    sanitized_user_id = sanitize_input(audit_log.user_id)  # Protects against XSS
    sanitized_action = sanitize_input(audit_log.action)  # Protects against XSS
    logger.info(f"Creating a new audit log for user ID: {sanitized_user_id}")
    user = db.query(User).filter(User.id == sanitized_user_id).first()  # Ensure user exists before creating log
    if not user:
        logger.warning(f"User with ID {sanitized_user_id} not found.")
        raise HTTPException(status_code=404, detail="User not found")  # Raise 404 if user not found

    # Creating a new audit log entry
    new_audit_log = AuditLog(
        user_id=sanitized_user_id,
        action=sanitized_action
    )
    db.add(new_audit_log)  # Add the new entry to the session
    db.commit()  # Commit changes to the database
    db.refresh(new_audit_log)  # Refresh the new audit log to retrieve its ID
    logger.info(f"Audit log created successfully with ID: {new_audit_log.id}")
    return new_audit_log

@router.get("/actions")
def get_possible_actions():
    """
    Fetch all possible actions for audit logging.

    :return: List of predefined actions that can be logged.
    """
    logger.info("Fetching possible audit log actions.")
    return [
        "User login",
        "User logout",
        "User registration",
        "Package created",
        "Package updated",
        "Customer deleted",
        "Profile updated",
        # Add more actions as needed
    ]
