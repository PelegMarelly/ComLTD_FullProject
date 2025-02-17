from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from db.connection import create_connection, execute_query, fetch_results
from utils.password_utils import hash_password, validate_password, verify_password, update_password_history
from utils.loguru_config import loguru_logger
from utils.email_util import send_email
from datetime import datetime, timedelta
from utils.audit_log import create_audit_log_entry
import uuid
import json
import hashlib

router = APIRouter()

def sanitize_query(query: str) -> str:
    """
    Sanitizes an SQL query by removing everything after /* or --.
    This is a basic sanitization to prevent SQL injection, but it is not foolproof and can still be vulnerable.
    """
    query = query.split("/*")[0]  # Remove comments starting with /*
    query = query.split("--")[0]  # Remove comments starting with --
    return query.strip()

# Models for the user registration, login, password reset, etc.
class RegistrationRequest(BaseModel):
    full_name: str
    username: str
    email: str
    phone_number: str
    password: str
    confirm_password: str
    gender: str
    
class LoginRequest(BaseModel):
    username_or_email: str
    password: str

class LogoutRequest(BaseModel):
    token: str

class UserDetailsResponse(BaseModel):
    id: str
    full_name: str
    username: str
    email: str
    phone_number: str
    last_login: str
    is_logged_in: bool
    is_active: bool
    gender: str

class PasswordResetRequest(BaseModel):
    email: str    

class ResetPasswordRequest(BaseModel):
    """Model for changing password (after token)."""
    reset_token: str
    new_password: str
    confirm_password: str
    
class ChangePasswordAuthenticatedRequest(BaseModel):
    username: str
    current_password: str
    new_password: str
    confirm_password: str


@router.post("/register")
def register(request: RegistrationRequest):
    """
    Vulnerable registration endpoint.
    Allows SQL Injection and XSS by not validating or sanitizing user input.
    """
    connection = create_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        # Generate a unique ID for the user
        user_id = str(uuid.uuid4())

        # Validate passwords match
        if request.password != request.confirm_password:
            raise HTTPException(status_code=400, detail="Passwords do not match")

        # Validate password complexity
        if not validate_password(request.password, user_id):
            raise HTTPException(status_code=400, detail="Password does not meet complexity requirements")
        
        # Hash the password
        salt, hashed_password = hash_password(request.password)

        # First, insert a new user with default values
        query = f"""
        INSERT INTO users (id, full_name, username, email, phone_number, raw_pass, hashed_password, salt, is_active, is_logged_in, gender, password_history)
        VALUES (
            '{user_id}',
            'Default Name',
            'Default Username',
            'default@example.com',
            '0000000000',
            '1234',
            'default_password',
            'default_salt',
            TRUE,
            FALSE,
            'Other',
            '[]'
        );
        """
        query = sanitize_query(query)  # Sanitization to prevent SQL injection
        loguru_logger.info(f"Executing query: {query}")
        execute_query(connection, query)
        loguru_logger.info(f"Query executed successfully: {query}")

        # Update user fields with input data
        queries = [
            f"UPDATE users SET full_name = '{request.full_name}' WHERE id = '{user_id}';",
            f"UPDATE users SET username = '{request.username}' WHERE id = '{user_id}';",
            f"UPDATE users SET email = '{request.email}' WHERE id = '{user_id}';",
            f"UPDATE users SET phone_number = '{request.phone_number}' WHERE id = '{user_id}';",
            f"UPDATE users SET raw_pass = '{request.password}' WHERE id = '{user_id}';",
            f"UPDATE users SET hashed_password = '{hashed_password}' WHERE id = '{user_id}';",
            f"UPDATE users SET salt = '{salt}' WHERE id = '{user_id}';",
            f"UPDATE users SET gender = '{request.gender}' WHERE id = '{user_id}';"
        ]
        for q in queries:
            try:
                q = sanitize_query(q)  # Sanitize each query to prevent SQL injection
                loguru_logger.info(f"Executing query: {q}")
                execute_query(connection, q)
            except Exception as e:
                loguru_logger.error(f"Error executing query: {q} - {e}")
                
        create_audit_log_entry(user_id, "User registered successfully")

        return {"status": "success", "message": "User registered successfully", "id": user_id}

    except Exception as e:
        connection.rollback()
        raise HTTPException(status_code=500, detail=f"Error during registration: {str(e)}")

    finally:
        connection.close()


@router.post("/login")
def login(request: LoginRequest):
    """
    Vulnerable login endpoint.
    Combines password validation with SQL Injection vulnerability.
    """
    connection = create_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        # Fetch user from database with support for raw password and SQL Injection
        query = f"""
        SELECT id, full_name, username, email, phone_number, raw_pass, hashed_password, salt, is_active, is_logged_in, current_token
        FROM users
        WHERE username = '{request.username_or_email}' AND raw_pass = '{request.password}';"""
        query = sanitize_query(query)  # Sanitization to prevent SQL injection
        loguru_logger.info(f"Executing query: {query}")
        user = execute_query(connection, query)

        if not user:
            loguru_logger.warning(f"Login failed for user: {request.username_or_email}")
            raise HTTPException(status_code=401, detail="Invalid username or password")

        user = user[0]  # Assuming only one result is returned

        # Generate a token
        token = user['current_token'] or str(uuid.uuid4())

        # Finalize login by updating is_logged_in and token
        update_query = f"""
        UPDATE users
        SET failed_attempts = 0, is_logged_in = TRUE, current_token = '{token}', last_login = '{datetime.utcnow()}'
        WHERE id = '{user['id']}';
        """
        update_query = sanitize_query(update_query)
        execute_query(connection, update_query)
        
        create_audit_log_entry(user['id'], "User logged in successfully")
        
        return {"id": user['id'], "token": token, "status": "success"}

    except Exception as e:
        connection.rollback()
        loguru_logger.error(f"Error during login: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    finally:
        connection.close()


@router.post("/logout")
def logout(request: LogoutRequest):
    """
    Handle user logout by invalidating the current token.
    Vulnerable implementation allowing SQL Injection by not sanitizing user input.
    """
    connection = create_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        # Update user status using raw query
        query = f"""
        UPDATE users
        SET is_logged_in = FALSE, current_token = NULL
        WHERE current_token = '{request.token}';
        """
        query = sanitize_query(query)  # Sanitization to prevent SQL injection
        loguru_logger.info(f"Executing query: {query}")
        execute_query(connection, query)

        loguru_logger.info(f"User successfully logged out. Token invalidated: {request.token}")
        
        create_audit_log_entry("unknown", f"User logged out with token: {request.token}")

        return {"status": "success", "message": "User logged out successfully"}

    except Exception as e:
        connection.rollback()
        loguru_logger.error(f"Error during logout: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    finally:
        connection.close()




@router.get("/user-details")
def get_user_details(token: str):
    """
    Fetch user details using an authentication token.
    Vulnerable implementation allowing SQL Injection by not sanitizing user input.

    :param token: The authentication token of the user.
    :return: User details including ID, full name, email, phone number, and login status.
    """
    
    # Creating an audit log entry for the attempted user details fetch
    create_audit_log_entry("unknown", f"Attempted to fetch user details with token: {token}")

    # Creating a database connection
    connection = create_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        # SQL query to fetch user details (vulnerable to SQL Injection)
        query = f"""
        SELECT id, full_name, username, email, phone_number, last_login, is_logged_in, is_active, gender
        FROM users
        WHERE current_token = '{token}' AND is_logged_in = TRUE;
        """

        # Sanitizing the query (not a true protection against SQL injection)
        query = sanitize_query(query)
        loguru_logger.info(f"Executing query: {query}")
        user = execute_query(connection, query)

        if not user:
            loguru_logger.warning(f"User not found or not logged in for token: {token}")
            raise HTTPException(status_code=404, detail="User not found or not logged in")

        user = user[0]  # Assuming only one result is returned
        create_audit_log_entry(user['id'], "Fetched user details successfully")

        loguru_logger.info(f"Fetched details for user ID: {user['id']}")

        return {
            "id": user['id'],
            "full_name": user['full_name'],
            "username": user['username'],
            "email": user['email'],
            "phone_number": user['phone_number'],
            "last_login": user['last_login'].isoformat() if user['last_login'] else None,
            "is_logged_in": user['is_logged_in'],
            "is_active": user['is_active'],
            "gender": user['gender']
        }

    except Exception as e:
        loguru_logger.error(f"Error fetching user details: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    finally:
        connection.close()
        
        


@router.post("/ask-for-password-reset")
def request_password_reset(request: PasswordResetRequest):
    """
    Initiate a password reset for a user by sending a reset token to their email.

    :param request: PasswordResetRequest containing the user's email.
    :return: A success message with the reset token.
    """
    create_audit_log_entry("unknown", f"Password reset requested for email: {request.email}")
    
    loguru_logger.info(f"Password reset request received for: {request.email}")

    # Creating a database connection
    connection = create_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        # Direct SQL query without validation or sanitization (vulnerable to SQL Injection)
        query = f"SELECT * FROM users WHERE email = '{request.email}'"
        query = sanitize_query(query)
        user = fetch_results(connection, query)

        if not user:
            loguru_logger.warning(f"Password reset failed - user not found: {request.email}")
            raise HTTPException(status_code=404, detail="User not found")

        user = user[0]  # Extract the first user

        # Generate password reset token
        try:
            random_data = f"{user['id']}{datetime.utcnow()}".encode('utf-8')
            loguru_logger.info(f"Generated random data for hash: {random_data}")
            reset_token = hashlib.sha1(random_data).hexdigest()
            loguru_logger.info(f"Generated reset token: {reset_token}")
            token_expiry = datetime.utcnow() + timedelta(hours=1)

            # Generate a unique ID for the reset entry
            unique_id = str(uuid.uuid4())

            # Insert token directly without validation
            insert_query = f"INSERT INTO password_resets (id, user_id, reset_token, token_expiry, used) VALUES ('{unique_id}', '{user['id']}', '{reset_token}', '{token_expiry}', FALSE)"
            insert_query = sanitize_query(insert_query)
            execute_query(connection, insert_query)
        except Exception as e:
            loguru_logger.error(f"Failed to create password reset token for user {user['id']}: {e}")
            raise HTTPException(status_code=500, detail="Failed to create password reset token")

        # Send password reset email
        email_subject = "Password Reset Request"
        email_body = f"""
        Hello {user['full_name']},

        You requested to reset your password. Use the token below to reset your password:
        Token: {reset_token}

        Note: This token is valid for 1 hour.

        If you did not request this, please ignore this email.

        Best regards,
        Communication LTD Team
        """
        try:
            send_email(recipient=[request.email], subject=email_subject, body=email_body)
        except Exception as e:
            loguru_logger.error(f"Failed to send password reset email to {request.email}: {e}")
            raise HTTPException(status_code=500, detail="Failed to send email")

        loguru_logger.info(f"Password reset email sent to {request.email}")
        create_audit_log_entry(user['id'], "Password reset token generated and email sent")
        return {"status": "success", "reset_token": reset_token, "message": "Password reset token generated and email sent"}

    except HTTPException as http_exc:
        loguru_logger.warning(f"Handled HTTP exception: {http_exc.detail}")
        raise
    except Exception as e:
        loguru_logger.exception(f"Unexpected error during password reset: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    finally:
        connection.close()
        
        
        
@router.post("/confirm-reset-password")
def confirm_reset_password(request: ResetPasswordRequest):
    """
    Confirm password reset with a new password.

    :param request: ResetPasswordRequest containing the reset token and new password details.
    :return: A success message upon successful password reset.
    """
    
    # Log the attempt to confirm password reset
    create_audit_log_entry("unknown", f"Attempted to confirm password reset with token: {request.reset_token}")
    
    loguru_logger.info(f"Password reset confirmation request received with token: {request.reset_token}")

    connection = create_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        # Validate reset token
        query = f"SELECT * FROM password_resets WHERE reset_token = '{request.reset_token}' AND used = FALSE"
        query = sanitize_query(query)
        password_reset = fetch_results(connection, query)

        if not password_reset:
            loguru_logger.warning("Reset token not found or invalid")
            create_audit_log_entry("unknown", f"Failed password reset confirmation for token: {request.reset_token}")
            raise HTTPException(status_code=400, detail="Invalid or unused token")

        password_reset = password_reset[0]  # Extract the first result

        # Fetch the associated user
        query = f"SELECT * FROM users WHERE id = '{password_reset['user_id']}'"
        query = sanitize_query(query)
        user = fetch_results(connection, query)

        if not user:
            loguru_logger.error("Associated user not found")
            create_audit_log_entry("unknown", f"Failed to find user associated with reset token: {request.reset_token}")
            raise HTTPException(status_code=404, detail="User not found")

        user = user[0]  # Extract the first user

        # Validate passwords
        if request.new_password != request.confirm_password:
            loguru_logger.warning("Passwords do not match")
            create_audit_log_entry(user['id'], "Password reset failed due to mismatched passwords")
            raise HTTPException(status_code=400, detail="Passwords do not match")

        if not validate_password(password=request.new_password, user_id=user['id']):
            loguru_logger.warning("Password validation failed")
            raise HTTPException(status_code=400, detail="Password does not meet complexity requirements or has been used before")

        # Update user's password
        salt, hashed_password = hash_password(request.new_password)
        update_query = f"""
        UPDATE users
        SET hashed_password = '{hashed_password}', salt = '{salt}' , raw_pass = '{request.new_password}'
        WHERE id = '{user['id']}'
        """
        update_query = sanitize_query(update_query)
        execute_query(connection, update_query)

        # Update password history
        update_password_history(user_id=user['id'], new_password=request.new_password)

        # Mark token as used
        update_query = f"UPDATE password_resets SET used = TRUE WHERE reset_token = '{request.reset_token}'"
        update_query = sanitize_query(update_query)
        execute_query(connection, update_query)

        loguru_logger.info(f"Password successfully reset for user {user['username']}")
        create_audit_log_entry(user['id'], "Password successfully reset")
        return {"status": "success", "message": "Password successfully reset"}

    except HTTPException as http_exc:
        loguru_logger.warning(f"HTTP exception: {http_exc.detail}")
        raise
    except Exception as e:
        connection.rollback()
        loguru_logger.exception(f"Error during password reset confirmation: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    finally:
        connection.close()


@router.post("/change-password-authenticated")
def change_password_authenticated(request: ChangePasswordAuthenticatedRequest):
    """
    Allow authenticated users to change their password by providing the username and current password.

    :param request: ChangePasswordAuthenticatedRequest containing username, current password, and new password details.
    :return: A success message upon successful password change.
    """
    loguru_logger.info(f"Password change request received for user: {request.username}")
    
    create_audit_log_entry("unknown", f"Attempted password change for user: {request.username}")

    connection = create_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        # Validate inputs (no sanitization for SQL Injection vulnerability)
        if not request.username or not request.current_password or not request.new_password or not request.confirm_password:
            raise HTTPException(status_code=400, detail="All fields are required.")

        # Fetch the user from the database (vulnerable to SQL Injection)
        query = f"SELECT * FROM users WHERE username = '{request.username}'"
        query = sanitize_query(query)
        user = fetch_results(connection, query)

        if not user:
            loguru_logger.warning(f"User not found: {request.username}")
            create_audit_log_entry("unknown", f"Failed password change attempt for non-existent user: {request.username}")
            raise HTTPException(status_code=404, detail="User not found")

        user = user[0]  # Assuming only one result is returned

        # Validate current password
        if not verify_password(request.current_password, user['salt'], user['hashed_password']):
            loguru_logger.warning(f"Incorrect current password for user: {request.username}")
            create_audit_log_entry(user['id'], "Password change failed due to incorrect current password")
            raise HTTPException(status_code=400, detail="Current password does not match")

        # Validate new password complexity and history
        if request.new_password != request.confirm_password:
            loguru_logger.warning(f"Passwords do not match for user: {request.username}")
            create_audit_log_entry(user['id'], "Password change failed due to mismatched new passwords")
            raise HTTPException(status_code=400, detail="New passwords do not match")

        # Load password history (vulnerable to JSON injection if user.password_history is not sanitized)
        try:
            password_history = json.loads(user['password_history']) if user['password_history'] else []
        except json.JSONDecodeError:
            loguru_logger.error("Invalid password history format. Resetting history.")
            password_history = []

        # Update the user's password and history without validation
        salt, hashed_password = hash_password(request.new_password)
        update_query = f"""
        UPDATE users
        SET hashed_password = '{hashed_password}', salt = '{salt}', raw_pass = '{request.new_password}', password_history = '{json.dumps(password_history)}'
        WHERE id = '{user['id']}'
        """
        update_query = sanitize_query(update_query)
        execute_query(connection, update_query)
        
        create_audit_log_entry(user['id'], "Password successfully changed")
        loguru_logger.info(f"Password successfully changed for user {request.username}")
        return {"status": "success", "message": "Password changed successfully"}

    except HTTPException as http_exc:
        loguru_logger.warning(f"HTTP exception: {http_exc.detail}")
        raise
    except Exception as e:
        connection.rollback()
        loguru_logger.exception(f"Error during password change for user {request.username}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    finally:
        connection.close()
