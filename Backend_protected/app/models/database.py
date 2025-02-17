from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker
from decouple import config  # Import directly from decouple
from ..utils.loguru_config import logger

# Load the DATABASE_URL from .env
DATABASE_URL = config("DATABASE_URL")  # Fetch database URL from environment

# Database engine initialization
engine = create_engine(DATABASE_URL)  # Create SQLAlchemy engine to interact with the database
metadata = MetaData()  # Metadata object to store schema information

# Session factory for database operations
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)  # Factory to create database sessions

def get_db():
    """
    Provide a database session and ensure proper closure.
    Yields:
        db (Session): Active database session.
    """
    logger.debug("Initializing database session.")  # Log the start of the session initialization
    db = SessionLocal()  # Create a new session
    try:
        yield db  # Yield the session for usage
        logger.debug("Database session yielded successfully.")  # Log successful yield
    except Exception as e:
        logger.error(f"Error occurred during database session: {e}")  # Log any error that occurs during the session
        raise
    finally:
        db.close()  # Ensure session is closed after use
        logger.debug("Database session closed.")  # Log when the session is closed

def load_models():
    """
    Dynamically loads all database models.
    This ensures that all table schemas are recognized and can be created.
    """
    try:
        from .tables import (
            User,
            Customer,
            Package,
            AuditLog,
            PasswordReset,
            ContactSubmission
        )  # Import the table models to be mapped to database
        logger.info("Models loaded successfully.")  # Log success when models are loaded
    except Exception as e:
        logger.error(f"Failed to load models: {e}")  # Log error if model loading fails
        raise
