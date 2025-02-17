import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
from utils.loguru_config import loguru_logger
import os

# Load environment variables
load_dotenv()

# Database configuration from .env file
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 3306))  # Default MySQL port
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "vulnerable_db")


def create_connection():
    """
    Creates a connection to the MySQL database.
    Returns the connection object if successful, otherwise None.
    """
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        if connection.is_connected():
            loguru_logger.info("Connection to MySQL DB created successfully!")  # Log successful connection
            return connection
    except Error as e:
        loguru_logger.info(f"Connection to MySQL DB failed, ERROR --> {e}")  # Log failure if connection fails
        return None


def execute_query(connection, query, multi=False):
    """
    Executes a given SQL query on the database.
    :param connection: The database connection object.
    :param query: The SQL query to execute.
    :param multi: Boolean indicating whether to execute as a multi-statement query.
    """
    try:
        cursor = connection.cursor(dictionary=True)
        loguru_logger.info(f"Executing query: {query}")
        results = []

        if multi:
            for result in cursor.execute(query, multi=True):
                if result.with_rows:
                    results.extend(result.fetchall())
        else:
            cursor.execute(query)
            if cursor.with_rows:
                results = cursor.fetchall()

        connection.commit()
        loguru_logger.info("Query executed successfully!")
        return results
    except Exception as e:
        connection.rollback()
        loguru_logger.error(f"Error executing query: {e}")
        raise
    finally:
        # Ensure all unread results are consumed or cursor is closed
        while cursor.nextset():
            pass
        cursor.close()


def fetch_results(connection, query, multi=False):
    """
    Executes a SELECT query and fetches the results.
    :param connection: The database connection object.
    :param query: The SELECT query to execute.
    :param multi: Boolean indicating whether to execute as a multi-statement query.
    """
    try:
        loguru_logger.info("Fetching data from DB...")
        results = execute_query(connection, query, multi=multi)
        loguru_logger.info("Fetching data from DB - success!")
        return results
    except Exception as e:
        loguru_logger.warning(f"Fetching data from DB - failed! ---- ERROR --> {e}")
        return []
