from db.connection import create_connection
from utils.loguru_config import loguru_logger

def create_audit_log_entry(user_id, action):
    """
    Inserts an audit log entry into the audit_logs table.

    :param user_id: ID of the user performing the action.
    :param action: Description of the action performed.
    """
    connection = None
    try:
        # Create a new connection
        connection = create_connection()
        if not connection:
            loguru_logger.error("Failed to connect to the database while creating audit log.")
            return

        loguru_logger.info(f"Attempting to create audit log for user_id: {user_id}, action: {action}")

        # Query using parameterized statements to avoid syntax issues
        query = """
            INSERT INTO audit_logs (user_id, action)
            VALUES (%s, %s)
        """
        cursor = connection.cursor()
        cursor.execute(query, (user_id, action))  # Use parameterized query
        connection.commit()

        loguru_logger.info(f"Audit log created successfully for user_id: {user_id}, action: {action}")
    except Exception as e:
        if connection:
            connection.rollback()
        loguru_logger.error(f"Failed to create audit log for user_id: {user_id}, action: {action}. Error: {e}")
    finally:
        if connection:
            connection.close()  # Ensure the connection is closed
