import hashlib

import sqlalchemy
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from uuid import uuid4
from pydantic import BaseModel, EmailStr, ValidationError
from ..models.tables import User, PasswordReset, Gender
from ..models.database import get_db
from ..utils.loguru_config import logger
from ..utils.audit_log import create_audit_log_entry
from ..utils.attack_detectors import sanitize_input, prevent_sql_injection
from ..utils.email import send_email
import json
from ..utils.validators import validate_password, verify_password, hash_password, check_login_attempts , update_password_history


# Title: User Management Routes

router = APIRouter()

# Title: Pydantic Models

class LoginRequest(BaseModel):
    """
    Model for login request data.
    """
    username_or_email: str  # Username or email of the user trying to log in
    password: str  # User's password
    remember_me: bool = False  # Option to remember the user for future logins

class LoginResponse(BaseModel):
    """
    Response model for a successful login.
    """
    id: str  # User ID
    token: str  # Authentication token for the user
    status: str  # Status of the login attempt

class RegistrationRequest(BaseModel):
    """
    Model for user registration request data.
    """
    full_name: str  # Full name of the user
    username: str  # Desired username for the user
    email: EmailStr  # Email address of the user
    phone_number: str  # Phone number of the user
    password: str  # Password for the user
    confirm_password: str  # Confirm the password to ensure they match
    accept_terms: bool  # User must accept the terms and conditions
    gender: str  # Gender of the user

class UserDetailsRequest(BaseModel):
    """
    Model for requesting user details.
    """
    token: str  # Authentication token of the user

class UserDetailsResponse(BaseModel):
    """
    Response model for user details.
    """
    id: str  # User ID
    full_name: str  # Full name of the user
    username: str  # Username of the user
    email: str  # Email address of the user
    phone_number: str  # Phone number of the user
    last_login: str  # Last login timestamp
    is_logged_in: bool  # Whether the user is currently logged in
    is_active: bool  # Whether the user's account is active
    gender: str  # Gender of the user

    class Config:
        orm_mode = True  # To support Pydantic's ORM model configuration

class UpdateUserRequest(BaseModel):
    """
    Model for updating user details.
    """
    full_name: str = None  # New full name (optional)
    phone_number: str = None  # New phone number (optional)
    email: EmailStr = None  # New email address (optional)
    gender: str = None  # New gender (optional)

class PasswordResetRequest(BaseModel):
    """
    Model for initiating a password reset.
    """
    email: str  # Email address to send the reset link

class TokenValidationRequest(BaseModel):
    """
    Model for validating a password reset token.
    """
    reset_token: str  # The password reset token

class LogoutRequest(BaseModel):
    """
    Model for user logout request.
    """
    token: str  # The token of the logged-in user

class EmailValidationRequest(BaseModel):
    """
    Model for validating an email.
    """
    email: EmailStr  # The email to validate

class ChangePasswordRequest(BaseModel):
    """
    Model for changing password using reset token.
    """
    reset_token: str  # The reset token
    new_password: str  # New password for the user
    confirm_password: str  # Confirm the new password

class ResetPasswordRequest(BaseModel):
    """
    Model for changing password after token verification.
    """
    reset_token: str  # The reset token
    new_password: str  # New password
    confirm_password: str  # Confirm new password

class ChangePasswordAuthenticatedRequest(BaseModel):
    """
    Model for changing password while authenticated.
    """
    username: str  # Username of the authenticated user
    current_password: str  # Current password of the user
    new_password: str  # New password to set
    confirm_password: str  # Confirm new password

class TokenValidationRequest(BaseModel):
    """
    Model for validating the token.
    """
    token: str  # Token to be validated


# Title: User Endpoints

@router.post("/login", response_model=LoginResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    """
    Handle user login.

    :param request: LoginRequest containing username or email and password.
    :param db: Database session.
    :return: Token and user ID on successful login.
    """
    logger.info(f"Login request received for: {request.username_or_email}")
    try:
        # Sanitize input for XSS and SQL injection
        sanitized_username_or_email = sanitize_input(prevent_sql_injection(request.username_or_email))
        sanitized_password = sanitize_input(request.password)

        # Check if the input matches the sanitized input
        if sanitized_username_or_email != request.username_or_email:
            logger.warning("XSS or SQL Injection attempt detected during login.")
            raise HTTPException(status_code=400, detail="Invalid input detected.")

        # Fetch user from database by email or username
        user = db.query(User).filter(
            (User.email == sanitized_username_or_email) | (User.username == sanitized_username_or_email)
        ).first()

        # Check if the user exists
        if not user:
            logger.warning(f"Login failed for user: {sanitized_username_or_email}")
            raise HTTPException(status_code=401, detail="Invalid username or password")

        # Check if the user is already logged in
        if user.is_logged_in:
            logger.warning(f"User {sanitized_username_or_email} is already logged in.")
            raise HTTPException(status_code=409, detail="User is already logged in")

        # Check if the user account is active
        if not user.is_active:
            logger.warning(f"Login attempt for inactive user: {sanitized_username_or_email}")
            raise HTTPException(status_code=403, detail="Account is locked due to multiple failed login attempts")

        # Verify the password
        if not verify_password(sanitized_password, user.salt, user.hashed_password):
            user.failed_attempts += 1

            # Lock the account if too many failed attempts
            if check_login_attempts(user.failed_attempts):
                user.is_active = False
                logger.warning(f"User {sanitized_username_or_email} locked due to too many failed login attempts")

            db.commit()
            logger.warning(f"Login failed for user: {sanitized_username_or_email}. Failed attempts: {user.failed_attempts}")
            raise HTTPException(status_code=401, detail="Invalid username or password")

        # Reset failed attempts on successful login
        user.failed_attempts = 0

        # Generate a new token for the user
        token = str(uuid4())
        user.current_token = token
        user.is_logged_in = True
        user.last_login = datetime.utcnow()
        db.commit()

        # Create an audit log entry
        create_audit_log_entry(user_id=user.id, action="User login", db=db)

        return {"id": user.id, "token": token, "status": "success"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"Unexpected error during login: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")




@router.post("/logout")
def logout(request: LogoutRequest, db: Session = Depends(get_db)):
    """
    Handle user logout by invalidating the current token.
    Logs the user out by marking them as not logged in and nullifying their current token.
    
    :param request: LogoutRequest containing the token for the user to be logged out.
    :param db: Database session.
    :return: A success message upon successful logout.
    """
    logger.info(f"Logout request received with token: {request.token}")
    try:
        # Sanitize the token to prevent SQL injection and XSS attacks
        sanitized_token = sanitize_input(prevent_sql_injection(request.token))

        # If the token has been tampered with, raise an error
        if sanitized_token != request.token:
            logger.warning("Potential XSS or SQL Injection attempt detected in token.")
            raise HTTPException(status_code=400, detail="Invalid input detected.")

        # Fetch user based on the current token
        user = db.query(User).filter(User.current_token == sanitized_token).first()

        if not user:
            logger.warning(f"Logout failed - no user found with token: {request.token}")
            raise HTTPException(status_code=401, detail="Invalid token or user not logged in")

        # Mark the user as logged out and remove the current token
        user.is_logged_in = False
        user.current_token = None
        db.commit()

        logger.info(f"User {user.id} successfully logged out. is_logged_in: {user.is_logged_in}, current_token: {user.current_token}")

        # Create an audit log entry for this action
        create_audit_log_entry(user_id=user.id, action="User logout", db=db)
        
        return {"status": "success", "message": "User logged out successfully"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()  # Ensure any changes are reverted on error
        logger.exception(f"Error during logout: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")




@router.post("/register")
def register(request: RegistrationRequest, db: Session = Depends(get_db)):
    """
    Handle user registration. Checks if the user already exists, validates input, 
    and then creates a new user in the database.
    
    :param request: RegistrationRequest containing the user's registration details.
    :param db: Database session.
    :return: A success message upon successful registration.
    """
    logger.info(f"Registration request received for: {request.username}")
    try:
        # Sanitize user inputs to prevent XSS and SQL Injection
        sanitized_username = sanitize_input(prevent_sql_injection(request.username))
        sanitized_email = sanitize_input(prevent_sql_injection(request.email))
        sanitized_gender = sanitize_input(request.gender)

        # Validate the gender value to ensure it is a valid entry
        if sanitized_gender not in [gender.value for gender in Gender]:
            logger.warning(f"Invalid gender value: {sanitized_gender}")
            raise HTTPException(status_code=400, detail="Invalid input detected")

        # If the sanitized username or email does not match original, it indicates tampering
        if sanitized_username != request.username or sanitized_email != request.email:
            logger.warning("SQL Injection or XSS attempt detected during registration.")
            raise HTTPException(status_code=400, detail="Invalid input detected")

        sanitized_password = sanitize_input(request.password)
        sanitized_confirm_password = sanitize_input(request.confirm_password)

        # Ensure that the passwords match
        if sanitized_password != sanitized_confirm_password:
            logger.warning(f"Passwords do not match for user: {sanitized_username}")
            raise HTTPException(status_code=400, detail="Passwords do not match")

        # Check if the email or username already exists in the database
        existing_user = db.query(User).filter(
            (User.email == sanitized_email) | (User.username == sanitized_username)
        ).first()

        if existing_user:
            logger.warning(f"User already exists: {sanitized_username}")
            raise HTTPException(status_code=400, detail="User with this email or username already exists")

        # Hash the password before storing it
        salt, hashed_password = hash_password(sanitized_password)

        # Create new user object
        new_user = User(
            full_name=sanitize_input(request.full_name),
            username=sanitized_username,
            email=sanitized_email,
            phone_number=sanitize_input(request.phone_number),
            hashed_password=hashed_password,
            salt=salt,
            is_active=True,
            is_logged_in=False,
            current_token=None,
            last_login=None,
            gender=sanitized_gender,
            password_history=json.dumps([]),  # Initialize empty password history
            failed_attempts=0
        )

        # Add the new user to the database and commit
        db.add(new_user)
        db.commit()
        db.refresh(new_user)  # Ensure new_user.id is available after commit

        # Validate the password complexity before finalizing the registration
        if not validate_password(sanitized_password, user_id=new_user.id, db_session=db):
            logger.warning(f"Password does not meet complexity requirements for user: {sanitized_username}")
            db.delete(new_user)
            db.commit()
            raise HTTPException(status_code=400, detail="Password does not meet complexity requirements")
        
        # Update password history after successful validation
        update_password_history(new_user.id, sanitized_password, db)

        # Create an audit log entry for user registration
        create_audit_log_entry(user_id=new_user.id, action="User registration", db=db)
        
        return {"status": "success", "message": "User registered successfully", "id": new_user.id}

    except sqlalchemy.exc.DataError as de:
        logger.error(f"Invalid data for database field: {de}")
        raise HTTPException(status_code=400, detail="Invalid input detected")
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()  # Rollback any database changes in case of failure
        logger.exception(f"Error during registration for {request.username}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")




@router.get("/user-details", response_model=UserDetailsResponse)
def get_user_details(
    token: str,  # Token passed as query parameter
    db: Session = Depends(get_db)
):
    """
    Fetch user details using an authentication token.
    
    The endpoint checks whether the provided token matches an active user session 
    and returns the corresponding user details.

    :param token: The authentication token of the user.
    :param db: Database session.
    :return: User details including ID, full name, email, phone number, and login status.
    """
    sanitized_token = sanitize_input(prevent_sql_injection(token))  # Sanitize the token to prevent injection
    logger.info(f"Fetching user details for token: {sanitized_token}")

    # Fetch user from the database whose token matches and is logged in
    user = db.query(User).filter(User.current_token == sanitized_token, User.is_logged_in == True).first()

    if not user:
        logger.warning(f"User not found or not logged in for token: {sanitized_token}")
        raise HTTPException(status_code=404, detail="User not found or not logged in")

    # Log the action in audit logs
    create_audit_log_entry(user_id=user.id, action="Fetched user details", db=db)

    # Return the user details as a response
    return {
        "id": user.id,
        "full_name": user.full_name,
        "username": user.username,
        "email": user.email,
        "phone_number": user.phone_number,
        "last_login": user.last_login.isoformat() if user.last_login else None,  # Convert last login to ISO format
        "is_logged_in": user.is_logged_in,
        "is_active": user.is_active,
        "gender": user.gender
    }





@router.post("/ask-for-password-reset")
def request_password_reset(request: PasswordResetRequest, db: Session = Depends(get_db)):
    """
    Initiate a password reset for a user by sending a reset token to their email.

    :param request: PasswordResetRequest containing the user's email.
    :param db: Database session.
    :return: A success message with the reset token.
    """
    logger.info(f"Password reset request received for: {request.email}")
    try:
        # Validate email format using Pydantic model
        try:
            validated_request = EmailValidationRequest(email=request.email)
        except ValidationError as ve:
            logger.warning(f"Invalid email format: {request.email}. Details: {ve}")
            raise HTTPException(status_code=400, detail="Invalid email format")

        # Sanitize the email to prevent SQL injection
        sanitized_email = prevent_sql_injection(validated_request.email)
        if sanitized_email != request.email:
            logger.warning("SQL Injection attempt detected during password reset.")
            raise HTTPException(status_code=400, detail="Invalid input detected.")

        # Query the user from the database using the sanitized email
        user = db.query(User).filter(User.email == sanitized_email).first()
        if not user:
            logger.warning(f"Password reset failed - user not found: {sanitized_email}")
            raise HTTPException(status_code=404, detail="User not found")

        # Generate a password reset token using SHA-1
        try:
            random_data = f"{user.id}{datetime.utcnow()}".encode('utf-8')
            reset_token = hashlib.sha1(random_data).hexdigest()
            token_expiry = datetime.utcnow() + timedelta(hours=1)

            # Create a new password reset entry in the database
            password_reset = PasswordReset(
                user_id=user.id,
                reset_token=reset_token,
                token_expiry=token_expiry,
                used=False,
            )
            db.add(password_reset)
            db.commit()
        except Exception as e:
            logger.error(f"Failed to create password reset token for user {user.id}: {e}")
            db.rollback()
            raise HTTPException(status_code=500, detail="Failed to create password reset token")

        # Send the password reset email to the user
        email_subject = "Password Reset Request"
        email_body = f"""
        Hello {user.full_name},

        You requested to reset your password. Use the token below to reset your password:
        Token: {reset_token}

        Note: This token is valid for 1 hour.

        If you did not request this, please ignore this email.

        Best regards,
        Communication LTD Team
        """
        try:
            send_email(recipient=[sanitized_email], subject=email_subject, body=email_body)
        except Exception as e:
            logger.error(f"Failed to send password reset email to {sanitized_email}: {e}")
            raise HTTPException(status_code=500, detail="Failed to send email")

        logger.info(f"Password reset email sent to {sanitized_email}")
        return {"status": "success", "reset_token": reset_token, "message": "Password reset token generated and email sent"}

    except HTTPException as http_exc:
        logger.warning(f"Handled HTTP exception: {http_exc.detail}")
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during password reset: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")




@router.post("/confirm-reset-password")
def confirm_reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    """
    Confirm password reset with a new password.

    This endpoint validates the provided reset token and checks if it is valid, 
    then updates the user's password if it meets the required criteria.

    :param request: ResetPasswordRequest containing the reset token and new password details.
    :param db: Database session.
    :return: A success message upon successful password reset.
    """
    logger.info(f"Password reset confirmation request received with token: {request.reset_token}")
    try:
        # Sanitize and validate the reset token to prevent SQL injection
        sanitized_token = sanitize_input(prevent_sql_injection(request.reset_token))
        password_reset = db.query(PasswordReset).filter(PasswordReset.reset_token == sanitized_token).first()

        if not password_reset:
            logger.warning("Reset token not found or invalid")
            raise HTTPException(status_code=400, detail="Invalid or unused token")

        # Fetch the associated user from the database
        user = db.query(User).filter(User.id == password_reset.user_id).first()
        if not user:
            logger.error("Associated user not found")
            raise HTTPException(status_code=404, detail="User not found")

        # Ensure the new password matches the confirmation
        if request.new_password != request.confirm_password:
            logger.warning("Passwords do not match")
            raise HTTPException(status_code=400, detail="Passwords do not match")

        # Load password history and validate the new password
        try:
            password_history = json.loads(user.password_history) if user.password_history else []
        except json.JSONDecodeError:
            logger.error("Password history is not in a valid JSON format. Resetting history.")
            password_history = []

        # Validate the new password against complexity rules and history
        if not validate_password(
            password=request.new_password,
            user_id=user.id,
            db_session=db,
            password_history=password_history
        ):
            logger.warning("Password does not meet complexity requirements or is in history")
            raise HTTPException(
                status_code=400,
                detail="Password does not meet complexity requirements or has been used before"
            )

        # Update the user's password and password history
        update_password_history(user_id=user.id, new_password=request.new_password, db_session=db)

        # Mark the reset token as used
        password_reset.used = True
        db.commit()

        logger.info(f"Password successfully reset for user {user.username}")
        return {"status": "success", "message": "Password successfully reset"}

    except HTTPException as http_exc:
        logger.warning(f"HTTP exception: {http_exc.detail}")
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"Error during password reset confirmation: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")




@router.post("/change-password-authenticated")
def change_password_authenticated(
    request: ChangePasswordAuthenticatedRequest,
    db: Session = Depends(get_db)
):
    """
    Allow authenticated users to change their password by providing the username and current password.

    This endpoint allows users to change their password after verifying their current password and ensuring that the 
    new password meets the necessary requirements.

    :param request: ChangePasswordAuthenticatedRequest containing username, current password, and new password details.
    :param db: Database session.
    :return: A success message upon successful password change.
    """
    logger.info(f"Password change request received for user: {request.username}")
    try:
        # Ensure all required fields are provided
        if not request.username or not request.current_password or not request.new_password or not request.confirm_password:
            raise HTTPException(status_code=400, detail="All fields are required.")

        # Sanitize user inputs to prevent XSS and SQL Injection
        sanitized_username = sanitize_input(request.username)
        sanitized_current_password = sanitize_input(request.current_password)
        sanitized_new_password = sanitize_input(request.new_password)
        sanitized_confirm_password = sanitize_input(request.confirm_password)

        # Fetch the user from the database
        user = db.query(User).filter(User.username == sanitized_username).first()
        if not user:
            logger.warning(f"User not found: {sanitized_username}")
            raise HTTPException(status_code=404, detail="User not found")

        # Verify that the provided current password is correct
        if not verify_password(sanitized_current_password, user.salt, user.hashed_password):
            logger.warning(f"Incorrect current password for user: {sanitized_username}")
            raise HTTPException(status_code=400, detail="Current password does not match")

        # Ensure the new password and confirmation password match
        if sanitized_new_password != sanitized_confirm_password:
            logger.warning(f"Passwords do not match for user: {sanitized_username}")
            raise HTTPException(status_code=400, detail="New passwords do not match")

        # Load password history and validate the new password
        try:
            password_history = json.loads(user.password_history) if user.password_history else []
        except json.JSONDecodeError:
            logger.error("Invalid password history format. Resetting history.")
            password_history = []

        # Validate the new password for complexity and history
        if not validate_password(
            sanitized_new_password,
            user_id=user.id,
            db_session=db,
            password_history=password_history
        ):
            logger.warning(f"Password does not meet requirements for user: {sanitized_username}")
            raise HTTPException(
                status_code=400,
                detail="New password does not meet complexity requirements or has been used before"
            )

        # Update the user's password and password history
        update_password_history(user.id, sanitized_new_password, db_session=db)
        logger.info(f"Password successfully changed for user {sanitized_username}")
        create_audit_log_entry(user_id=user.id, action="Password changed successfully", db=db)

        return {"status": "success", "message": "Password changed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"Error during password change for user {request.username}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
