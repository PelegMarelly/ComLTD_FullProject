from smtplib import SMTP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from decouple import config
from utils.loguru_config import loguru_logger  # Updated import

def send_email(recipient: list, subject: str, body: str):
    """
    Send an email using SMTP.

    :param recipient: List of recipient email addresses.
    :param subject: Email subject.
    :param body: Email body.
    """
    # Load environment variables using decouple
    EMAIL_SENDER = config("EMAIL_SENDER")  # The sender email address.
    EMAIL_PASSWORD = config("EMAIL_PASSWORD")  # The password for the sender's email.
    SMTP_SERVER = config("SMTP_SERVER", default="smtp.gmail.com")  # SMTP server address, default to Gmail.
    SMTP_PORT = config("SMTP_PORT", default=587, cast=int)  # SMTP server port, default to 587 (TLS).

    # Validate essential configurations
    if not EMAIL_SENDER or not EMAIL_PASSWORD:  # Check if the essential email configurations are set.
        loguru_logger.error("Sender email or password not set in environment variables.")
        raise ValueError("Sender email or password not set in environment variables.")

    try:
        # Create the email
        msg = MIMEMultipart()  # Create a multipart email message.
        msg["From"] = EMAIL_SENDER  # Set the sender's email.
        msg["To"] = ", ".join(recipient)  # Set the recipients of the email.
        msg["Subject"] = subject  # Set the subject of the email.
        msg.attach(MIMEText(body, "plain"))  # Attach the body of the email in plain text format.

        loguru_logger.info(f"Attempting to send email to {recipient}")  # Log the attempt to send the email.

        # Connect to the SMTP server
        with SMTP(SMTP_SERVER, SMTP_PORT) as server:  # Connect to the SMTP server.
            server.starttls()  # Secure the connection with TLS.
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)  # Log in to the email server with sender credentials.
            server.sendmail(EMAIL_SENDER, recipient, msg.as_string())  # Send the email.
            loguru_logger.info(f"Email successfully sent to {recipient}")  # Log the successful sending of the email.

    except Exception as e:  # Catch any exceptions during the email sending process.
        loguru_logger.error(f"Failed to send email to {recipient}: {e}")  # Log the error if sending fails.
        raise RuntimeError(f"Failed to send email: {e}")  # Raise an exception to indicate failure.
