from smtplib import SMTP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from decouple import config
from ..utils.loguru_config import logger

def send_email(recipient: list, subject: str, body: str):
    """
    Send an email using SMTP.

    :param recipient: List of recipient email addresses.
    :param subject: Subject of the email.
    :param body: Body content of the email.
    """
    # Load environment variables using decouple for sensitive data (email sender credentials)
    EMAIL_SENDER = config("EMAIL_SENDER")  # Sender's email address (should be in .env file)
    EMAIL_PASSWORD = config("EMAIL_PASSWORD")  # Sender's email password (should be in .env file)
    SMTP_SERVER = config("SMTP_SERVER", default="smtp.gmail.com")  # Default SMTP server (e.g., Gmail)
    SMTP_PORT = config("SMTP_PORT", default=587, cast=int)  # Default SMTP port (587 for TLS)

    # Check if the necessary configuration (email sender and password) is set
    if not EMAIL_SENDER or not EMAIL_PASSWORD:
        logger.error("Sender email or password not set in environment variables.")
        raise ValueError("Sender email or password not set in environment variables.")  # Raise error if not set

    try:
        # Construct the email using MIME (Multipurpose Internet Mail Extensions) format
        msg = MIMEMultipart()  # Create a multipart message (enables attachments and formatted content)
        msg["From"] = EMAIL_SENDER  # Set the 'From' field to the sender's email address
        msg["To"] = ", ".join(recipient)  # Set the 'To' field to the recipients (comma-separated)
        msg["Subject"] = subject  # Set the email subject
        msg.attach(MIMEText(body, "plain"))  # Attach the email body (in plain text format)

        logger.info(f"Attempting to send email to {recipient}")  # Log the attempt to send the email

        # Establish a connection to the SMTP server using the provided SMTP server and port
        with SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Upgrade the connection to TLS (Transport Layer Security) for encryption
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)  # Login to the email account
            server.sendmail(EMAIL_SENDER, recipient, msg.as_string())  # Send the email to the recipient(s)
            logger.info(f"Email successfully sent to {recipient}")  # Log success if email is sent

    except Exception as e:
        logger.error(f"Failed to send email to {recipient}: {e}")  # Log error if email sending fails
        raise RuntimeError(f"Failed to send email: {e}")  # Raise a runtime error with the error message
