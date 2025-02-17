from db.connection import execute_query, create_connection
from utils.loguru_config import loguru_logger

def create_tables():
    """
    Creates all necessary tables for the application.
    This implementation uses raw SQL queries, making it vulnerable to SQL Injection.
    """
    queries = [
        """
        CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(36) PRIMARY KEY,  # Unique ID for each user
            full_name VARCHAR(255) NOT NULL,  # User's full name
            username VARCHAR(255) NOT NULL,  # Username for user login
            email VARCHAR(255) NOT NULL,  # User's email address
            phone_number VARCHAR(20),  # User's phone number
            raw_pass VARCHAR(255),  # User's raw password (not stored securely)
            hashed_password VARCHAR(255) NOT NULL,  # Hashed password for security
            salt VARCHAR(255) NOT NULL,  # Salt used for hashing the password
            password_history TEXT,  # Stores the password history
            is_active BOOLEAN DEFAULT TRUE,  # Whether the user is active
            is_logged_in BOOLEAN DEFAULT FALSE,  # Whether the user is currently logged in
            current_token VARCHAR(255) DEFAULT NULL,  # Current authentication token for the user
            last_login DATETIME DEFAULT CURRENT_TIMESTAMP,  # Timestamp of the last login
            failed_attempts INT DEFAULT 0,  # Count of failed login attempts
            gender VARCHAR(50)  # User's gender
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS customers (
            id VARCHAR(50) PRIMARY KEY,  # Unique customer ID
            first_name VARCHAR(255) NOT NULL,  # Customer's first name
            last_name VARCHAR(255) NOT NULL,  # Customer's last name
            phone_number VARCHAR(255) NOT NULL,  # Customer's phone number
            email_address VARCHAR(100) NOT NULL,  # Customer's email address
            address TEXT,  # Customer's address
            package_id VARCHAR(50),  # ID of the subscribed package
            gender VARCHAR(10)  # Customer's gender
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS packages (
            id VARCHAR(50) PRIMARY KEY,  # Unique package ID
            package_name VARCHAR(50) UNIQUE NOT NULL,  # Name of the package
            description TEXT,  # Description of the package
            monthly_price INT NOT NULL,  # Monthly price of the package
            subscriber_count INT DEFAULT 0  # Count of current subscribers to the package
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,  # Auto-incrementing ID for each log
            user_id VARCHAR(36) NOT NULL,  # ID of the user performing the action
            action TEXT NOT NULL,  # Description of the action
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP  # Timestamp when the action occurred
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS contact_submissions (
            id VARCHAR(36) PRIMARY KEY,  # Unique ID for each contact submission
            name VARCHAR(255) NOT NULL,  # Name of the person submitting the contact form
            email VARCHAR(255) NOT NULL,  # Email address of the submitter
            message TEXT NOT NULL,  # The message submitted
            submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP  # Timestamp of submission
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS password_resets (
            id VARCHAR(36) PRIMARY KEY,  # Unique ID for each reset entry
            user_id VARCHAR(36) NOT NULL,  # User ID for whom the password reset was requested
            reset_token VARCHAR(255) UNIQUE NOT NULL,  # Unique reset token
            token_expiry DATETIME NOT NULL,  # Expiry time for the reset token
            used BOOLEAN DEFAULT FALSE  # Whether the reset token has been used
        );
        """
    ]

    db_connection = create_connection()
    if db_connection:
        try:
            for query in queries:
                # Ensure query execution
                cursor = db_connection.cursor()
                cursor.execute(query)  # Execute each table creation query
                db_connection.commit()  # Commit the changes to the database
                loguru_logger.info("Table Created successfully!")  # Log success message
        except Exception as e:
            loguru_logger.error(f"Table Creation failed! ERROR --> {e}")  # Log any error encountered during creation
        finally:
            loguru_logger.info("Closing the DB connection..")  # Log closure of the database connection
            db_connection.close()  # Close the database connection


# Uncomment the following line to create tables when running the script
# if __name__ == "__main__":
#     create_tables()
