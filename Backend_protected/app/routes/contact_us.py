from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from ..models.database import get_db
from ..models.tables import User, ContactSubmission
from ..utils.loguru_config import logger
from ..utils.email import send_email
from ..utils.attack_detectors import sanitize_input, prevent_sql_injection
from decouple import config


router = APIRouter()


class ContactUsRequest(BaseModel):
    """
    Pydantic model to validate and structure incoming 'Contact Us' form submissions.

    Attributes:
        user_id: ID of the user submitting the form.
        name: Name of the person submitting the form.
        email: Email address of the submitter.
        message: Message content.
        send_copy: Flag to send a copy of the submission to the user (default: False).
    """
    user_id: str
    name: str
    email: EmailStr
    message: str
    send_copy: bool = False



@router.post("/contact-us-send")
def contact_us(request: ContactUsRequest, db: Session = Depends(get_db)):
    """
    Handles 'Contact Us' form submissions, validates user, saves data, and sends email notifications.
    
    :param request: ContactUsRequest model with form details.
    :param db: Database session.
    :return: A success message if the email is sent successfully.
    """
    try:
        # Validate and sanitize user_id to prevent potential SQL Injection or XSS
        sanitized_user_id = sanitize_input(prevent_sql_injection(request.user_id))
        if sanitized_user_id != request.user_id:
            logger.warning("Potential XSS or SQL Injection detected in user_id.")
            raise HTTPException(status_code=400, detail="Invalid input detected.")

        # Check if the user exists in the database
        user = db.query(User).filter(User.id == sanitized_user_id).first()
        if not user:
            logger.warning(f"Invalid user ID: {sanitized_user_id}")
            raise HTTPException(status_code=404, detail="User not found")

        # Sanitize other user inputs to prevent XSS attacks
        sanitized_name = sanitize_input(request.name)
        sanitized_email = sanitize_input(request.email)
        sanitized_message = sanitize_input(request.message)

        logger.info(f"Contact us form submitted by {sanitized_name} ({sanitized_email})")

        # Save the contact submission to the database
        contact_submission = ContactSubmission(
            name=sanitized_name,
            email=sanitized_email,
            message=sanitized_message,
            submitted_at=datetime.utcnow()  # Record submission time
        )
        db.add(contact_submission)
        db.commit()

        logger.info("Contact us submission saved to the database.")

        # Retrieve admin email from environment variables
        admin_email = config("EMAIL_SENDER")

        # Send email to the admin with the details of the submission
        send_email(
            recipient=[admin_email],
            subject="New Contact Us Submission",
            body=f"Name: {sanitized_name}\n"
                 f"Email: {sanitized_email}\n"
                 f"Message:\n{sanitized_message}"
        )
        logger.info("Contact us message sent to admin.")

        # Optionally send a copy of the message to the user
        if request.send_copy:
            send_email(
                recipient=[sanitized_email],
                subject="Your Contact Us Submission",
                body=f"Hello {sanitized_name},\n\n"
                     f"Thank you for reaching out to us. Here is a copy of your message:\n\n"
                     f"{sanitized_message}\n\n"
                     f"We'll get back to you as soon as possible.\n\n"
                     f"Best regards,\nCommunication LTD"
            )
            logger.info(f"Copy of contact us message sent to {sanitized_email}.")

        return {"status": "success", "message": "Message sent and saved successfully"}

    except HTTPException:
        # If an HTTPException is raised, re-raise it for handling
        raise
    except Exception as e:
        # In case of unexpected errors, rollback the transaction and log the error
        db.rollback()
        logger.exception(f"Failed to process contact us submission: {e}")
        raise HTTPException(status_code=500, detail="Failed to process message")
