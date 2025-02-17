from fastapi import APIRouter, HTTPException, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from utils.loguru_config import loguru_logger
from utils.email_util import send_email
from datetime import datetime
from db.connection import create_connection
from utils.audit_log import create_audit_log_entry
from typing import List

# Define the router for handling the "Contact Us" and related endpoints
router = APIRouter()

# Pydantic model to validate the "Contact Us" form submission
class ContactUsRequest(BaseModel):
    user_id: str
    name: str
    email: str
    message: str
    send_copy: bool = False  # Flag to send a copy of the email to the user


# Pydantic model for logging actions
class AuditLogRequest(BaseModel):
    user_id: str
    action: str


# Pydantic model for email sending
class EmailRequest(BaseModel):
    recipient: List[str]
    subject: str
    body: str


@router.post("/contact-us-send")
def contact_us(request: ContactUsRequest):
    """
    Vulnerable endpoint for "Contact Us" form submissions.
    This endpoint is susceptible to both XSS and SQL Injection vulnerabilities as it does not validate or sanitize user input.

    :param request: The ContactUsRequest model containing the user's message and details.
    :return: A success message if the email is sent successfully.
    """
    loguru_logger.info(f"Contact us form submitted by {request.name} ({request.email})")

    try:
        # Load admin email (hardcoded for simplicity)
        admin_email = "admin@example.com"

        # Send email to admin with the contact form details
        send_email(
            recipient=[admin_email],
            subject="New Contact Us Submission",
            body=f"Name: {request.name}\n"
                 f"Email: {request.email}\n"
                 f"Message:\n{request.message}"
        )
        loguru_logger.info("Contact us message sent to admin.")

        # Optionally send a copy to the user
        if request.send_copy:
            send_email(
                recipient=[request.email],
                subject="Your Contact Us Submission",
                body=f"Hello {request.name},\n\n"
                     f"Thank you for reaching out to us. Here is a copy of your message:\n\n"
                     f"{request.message}\n\n"
                     f"We'll get back to you as soon as possible.\n\n"
                     f"Best regards,\nCommunication LTD"
            )
            loguru_logger.info(f"Copy of contact us message sent to {request.email}.")

        return {"status": "success", "message": "Message sent successfully"}

    except Exception as e:
        loguru_logger.error(f"Failed to process contact us submission: {e}")
        raise HTTPException(status_code=500, detail="Failed to process message")


@router.get("/", response_class=HTMLResponse)
def landing_page():
    """
    Render the landing page with custom theme (Wine Red and Yellow/Orange buttons).
    This is the main page users will land on when they visit the site.
    """
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Landing Page</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js"></script>
        <style>
            body {
                background-color: #8B0000; /* Wine Red Background */
                color: white;
                font-family: Arial, sans-serif;
            }
            .container {
                max-width: 800px;
                margin: 50px auto;
                text-align: center;
            }
            .btn-yellow {
                background-color: #FFD700; /* Gold */
                color: black;
                border: none;
            }
            .btn-yellow:hover {
                background-color: #FFC107; /* Amber */
                color: black;
            }
            .btn-orange {
                background-color: #FF4500; /* Orange Red */
                color: white;
                border: none;
            }
            .btn-orange:hover {
                background-color: #FF6347; /* Tomato */
                color: white;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to Communication LTD API</h1>
            <p>This is the vulnerable version of the backend for demonstration purposes.</p>
            <div class="d-grid gap-2 d-md-flex justify-content-center mt-4">
                <button class="btn btn-yellow text-dark me-md-2" onclick="location.href='/docs'">OpenAPI Documentation</button>
                <button class="btn btn-orange text-dark" onclick="location.href='/audit-logs-view'">View Audit Logs</button>
                <button class="btn btn-yellow text-dark" onclick="location.href='/test-email'">Test Email</button>
                <button class="btn btn-orange text-dark" onclick="location.href='/redoc'">ReDoc Documentation</button>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@router.get("/health", response_class=HTMLResponse)
def health_check():
    """
    Health check endpoint to verify the application is running.
    Returns an HTML response with a success message.
    """
    loguru_logger.info("Health check endpoint called.")
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Health Check</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js"></script>
        <style>
            body {
                background-color: #8B0000; /* Wine Red Background */
                color: white;
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            h1 {
                font-size: 5rem;
                font-weight: bold;
                text-shadow: 2px 2px 5px black;
            }
        </style>
    </head>
    <body>
        <h1>I'm OK!!</h1>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@router.get("/test-email", response_class=HTMLResponse)
def test_email_page():
    """
    Render a page to test email sending functionality with a wine red theme.
    Provides a form for users to send a test email.
    """
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Email</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {
                background-color: #8B0000; /* Wine Red */
                color: white;
                font-family: Arial, sans-serif;
            }
            h1 {
                font-size: 3rem;
                margin-bottom: 1rem;
                text-align: center;
            }
            .form-label {
                font-size: 1.2rem;
            }
            .btn {
                background-color: #FFD700; /* Gold */
                color: black;
                border: none;
                font-size: 1.2rem;
            }
            .btn:hover {
                background-color: #FFC107; /* Amber */
            }
            .container {
                margin-top: 5rem;
                max-width: 500px;
            }
            .bg-secondary {
                background-color: #333333 !important;
                border-radius: 8px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Send Test Email</h1>
            <form method="post" action="/send-test-email" class="bg-secondary p-4">
                <div class="mb-3">
                    <label for="email" class="form-label">Email Address</label>
                    <input type="email" id="email" name="email" class="form-control" required>
                </div>
                <div class="d-grid">
                    <button type="submit" class="btn">Send Test Email</button>
                </div>
            </form>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@router.post("/send-test-email", response_class=HTMLResponse)
def send_test_email(email: str = Form(...)):
    """
    Handle test email sending without sanitization.
    This endpoint allows sending a test email to the given email address.
    """
    try:
        send_email(
            recipient=[email],  # No sanitization applied
            subject="Test Email",
            body=f"This is a test email sent on {datetime.utcnow()} (UTC)."
        )
        loguru_logger.info(f"Test email sent to {email}")

        # Return a styled HTML page to confirm email sent
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Sent</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body {{
                    background-color: #8B0000; /* Wine Red */
                    color: white;
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }}
                h1 {{
                    font-size: 3rem;
                    margin-bottom: 1rem;
                }}
                p {{
                    font-size: 1.5rem;
                }}
                .btn {{
                    background-color: #FFD700; /* Gold */
                    color: black;
                    border: none;
                    font-size: 1.2rem;
                }}
                .btn:hover {{
                    background-color: #FFC107; /* Amber */
                }}
            </style>
        </head>
        <body>
            <div class="text-center">
                <h1>Test Email Sent!</h1>
                <p>Email successfully sent to: <strong>{email}</strong></p>
                <button class="btn" onclick="location.href='/test-email'">Send Another Email</button>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content)

    except Exception as e:
        loguru_logger.error(f"Failed to send test email to {email}: {e}")
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Failed</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body {{
                    background-color: #8B0000; /* Wine Red */
                    color: white;
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }}
                h1 {{
                    font-size: 3rem;
                    margin-bottom: 1rem;
                }}
                p {{
                    font-size: 1.5rem;
                }}
                .btn {{
                    background-color: #FF4500; /* Orange Red */
                    color: white;
                    border: none;
                    font-size: 1.2rem;
                }}
                .btn:hover {{
                    background-color: #FF6347; /* Tomato */
                }}
            </style>
        </head>
        <body>
            <div class="text-center">
                <h1>Email Sending Failed!</h1>
                <p>Failed to send email to: <strong>{email}</strong></p>
                <p>Error: {str(e)}</p>
                <button class="btn" onclick="location.href='/test-email'">Try Again</button>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content)


@router.get("/audit-logs-view", response_class=HTMLResponse)
def audit_logs_view():
    """
    Render a page to view and filter Audit Logs with custom styling and a delete button.
    This endpoint provides a view to check the actions logged in the system.
    """
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Audit Logs</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {
                background-color: #8B0000; /* Wine Red */
                color: white;
                font-family: Arial, sans-serif;
            }
            .container {
                margin-top: 50px;
            }
            h1 {
                text-align: center;
                margin-bottom: 30px;
                color: #FFD700; /* Gold */
                text-shadow: 2px 2px 5px black;
            }
            .btn-yellow {
                background-color: #FFD700; /* Gold */
                color: black;
                border: none;
            }
            .btn-yellow:hover {
                background-color: #FFC107; /* Amber */
                color: black;
            }
            table {
                background-color: #5A0000; /* Darker Wine Red */
            }
            thead {
                background-color: #FFD700; /* Gold */
                color: black;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Audit Logs</h1>
            <div class="mb-3">
                <label for="userIdInput" class="form-label">Filter by User ID</label>
                <input type="text" id="userIdInput" class="form-control" placeholder="Enter User ID">
            </div>
            <div class="d-grid gap-2 d-md-flex justify-content-between mb-4">
                <button class="btn btn-yellow" onclick="filterLogs()">Filter Logs</button>
                <button class="btn btn-danger" onclick="deleteLogs()">Delete All Logs</button>
            </div>
            <table class="table table-dark table-striped">
                <thead>
                    <tr>
                        <th class="th text-light">ID</th>
                        <th class="th text-light">User ID</th>
                        <th class="th text-light">Action</th>
                        <th class="th text-light">Timestamp</th>
                    </tr>
                </thead>
                <tbody id="auditLogsTable">
                </tbody>
            </table>
        </div>

        <script>
            async function fetchLogs(userId = null) {
                const endpoint = userId ? `/audit-logs?user_id=${userId}` : '/audit-logs';
                const response = await fetch(endpoint);
                const logs = await response.json();
                const tableBody = document.getElementById("auditLogsTable");
                tableBody.innerHTML = "";
                logs.forEach(log => {
                    const row = `<tr>
                        <td>${log.id}</td>
                        <td>${log.user_id}</td>
                        <td>${log.action}</td>
                        <td>${new Date(log.timestamp).toLocaleString()}</td>
                    </tr>`;
                    tableBody.innerHTML += row;
                });
            }

            function filterLogs() {
                const userId = document.getElementById("userIdInput").value.trim();
                fetchLogs(userId || null);
            }

            async function deleteLogs() {
                const confirmation = confirm("Are you sure you want to delete all audit logs?");
                if (!confirmation) return;

                try {
                    const response = await fetch('/audit-logs', { method: 'DELETE' });
                    const result = await response.json();
                    alert(result.message);
                    fetchLogs();  // Refresh the logs after deletion
                } catch (error) {
                    alert("Failed to delete logs. Check the console for details.");
                    console.error("Error deleting logs:", error);
                }
            }

            // Load logs on page load
            document.addEventListener("DOMContentLoaded", () => fetchLogs());
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@router.get("/audit-logs")
def get_audit_logs(user_id: str = None):
    """
    Fetch Audit Logs, optionally filtered by User ID.
    This implementation is intentionally vulnerable to SQL Injection.
    :param user_id: Optional User ID to filter logs.
    :return: List of audit logs.
    """
    loguru_logger.info(f"Fetching audit logs with user_id: {user_id or 'All'}")

    # Create a connection to the database
    connection = create_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        # Construct the SQL query with potential for SQL Injection
        if user_id:
            query = f"SELECT id, user_id, action, timestamp FROM audit_logs WHERE user_id = '{user_id}'"
        else:
            query = "SELECT id, user_id, action, timestamp FROM audit_logs"

        loguru_logger.info(f"Executing query: {query}")
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query)
        logs = cursor.fetchall()

        loguru_logger.info(f"Fetched {len(logs)} audit logs.")
        return logs

    except Exception as e:
        loguru_logger.error(f"Error fetching audit logs: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    finally:
        if connection:
            connection.close()


@router.delete("/audit-logs")
def delete_audit_logs():
    """
    Delete all audit logs from the database.
    """
    loguru_logger.info("Deleting all audit logs...")

    # Create a connection to the database
    connection = create_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        # Execute deletion of all entries in the audit_logs table
        query = "DELETE FROM audit_logs"
        loguru_logger.info(f"Executing query: {query}")
        cursor = connection.cursor()
        cursor.execute(query)
        connection.commit()
        loguru_logger.info("All audit logs deleted successfully.")
        return {"status": "success", "message": "All audit logs deleted successfully."}

    except Exception as e:
        loguru_logger.error(f"Error deleting audit logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete audit logs")

    finally:
        if connection:
            connection.close()
