from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .models.database import engine, load_models
from .models.tables import Base
from .utils.populate import populate_all_tables
from .routes.users import router as users_router
from .routes.packages import router as packages_router
from .routes.customers import router as customers_router
from .routes.audit_logs import router as audit_logs_router
from .routes.landing_page import router as landing_page_router
from .routes.contact_us import router as contact_us_router
from .utils.loguru_config import logger
import time  # For introducing the delay
from decouple import config  # For loading environment variables


# Title: Application Initialization and Route Registration

def create_application() -> FastAPI:
    """
    Create and configure the FastAPI application.

    This function sets up the application, registers routes, and adds metadata.
    :return: Configured FastAPI application instance.
    """
    logger.info("Initializing FastAPI application...")

    # Update OpenAPI title and description
    application = FastAPI(
        title="Protected Backend - Communication LTD API",
        version="1.0.0",
        description="This API serves as the protected backend for managing Communication LTD operations, with added security measures including SQL injection and XSS protection.",
    )

    # Include routers for all routes
    application.include_router(users_router, prefix="/users", tags=["Users"])
    application.include_router(packages_router, prefix="/packages", tags=["Packages"])
    application.include_router(customers_router, prefix="/customers", tags=["Customers"])
    application.include_router(audit_logs_router, prefix="/audit-logs", tags=["Audit Logs"])
    application.include_router(landing_page_router, tags=["Landing Pages"])
    application.include_router(contact_us_router, tags=["Contact Us"])

    # Add CORS middleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],  # Adjust origins as needed
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    logger.info("CORS middleware successfully added.")

    logger.info("Routes successfully registered.")
    return application


# Title: Database Initialization

def initialize_database():
    """
    Initialize the database by loading models, creating tables, and populating initial data.

    This function ensures the database is ready for use by the application.
    """
    try:
        logger.info("Starting database initialization...")
        load_models()
        Base.metadata.create_all(bind=engine)
        populate_all_tables()  # This will populate package data into the database
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise


# Title: Main Application Entry Point

try:
    logger.info("Starting application setup...")

    # Load the delay time from the .env file
    db_connection_delay = int(config("DB_CONNECTION_DELAY", default=15))  # Delay time in seconds

    # Introducing a delay to ensure the database is ready before the application starts
    logger.info(f"Waiting for {db_connection_delay} seconds for the database to initialize...")
    time.sleep(db_connection_delay)

    initialize_database()
    app = create_application()
    logger.info("Application setup completed successfully.")
except Exception as e:
    logger.critical(f"Failed to start the application: {e}")
    raise
