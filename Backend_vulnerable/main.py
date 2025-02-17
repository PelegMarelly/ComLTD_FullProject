from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes.users import router as users_router
from app.routes.customers import router as customers_router
from app.routes.packages import router as packages_router
from app.routes.other_routes import router as other_routes_router
from db.models import create_tables
from utils.loguru_config import loguru_logger
from utils.populate import populate_all_tables
import time
from decouple import config  # To load from .env


# Initialize FastAPI app with custom title and description for OpenAPI
app = FastAPI(
    title="Communication LTD - Vulnerable API",  # Custom title for the API
    description="This is the vulnerable version of the backend for demonstration purposes.",  # Custom description
    version="1.0.0",  # Version of the API
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Adjust origins as needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
loguru_logger.info("CORS middleware successfully added.")

# Include routes
app.include_router(users_router, prefix="/users")
app.include_router(customers_router, prefix="/customers")
app.include_router(packages_router, prefix="/packages")
app.include_router(other_routes_router, prefix="")

# Time delay for table creation and population function
def create_tables_on_startup(delay_time: int = 25):
    """
    Create necessary tables in the database on server startup with an initial delay.
    The default delay time is 25 seconds but can be adjusted via the argument.
    """
    # Add a delay of `delay_time` seconds
    loguru_logger.info(f"Waiting for {delay_time} seconds for the database to initialize...")
    time.sleep(delay_time)
    try:
        create_tables()
        loguru_logger.info("Waiting for 3 seconds before populating tables...")
        time.sleep(3)
    except Exception as e:
        loguru_logger.error(f"Failed to create tables after delay. Error: {e}")

    populate_all_tables()

# FastAPI startup event
@app.on_event("startup")
def startup_event():
    """
    FastAPI startup event.
    """
    loguru_logger.info("Starting up the application...")
    
    # Load the delay time from .env and use it for startup delay
    db_connection_delay = int(config("DB_CONNECTION_DELAY", default=25))  # Default to 25 seconds if not set in .env
    create_tables_on_startup(db_connection_delay)  # Call table creation with the delay time from .env

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=11000)
