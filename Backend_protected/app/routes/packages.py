from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from pydantic import BaseModel
from ..models.tables import Package, generate_package_id
from ..models.database import get_db
from ..utils.loguru_config import logger
from ..utils.audit_log import create_audit_log_entry
from ..utils.attack_detectors import sanitize_input, prevent_sql_injection

# Title: Package Management Routes

router = APIRouter()

# Title: Models

class PackageCreate(BaseModel):
    """
    Model for creating a new package.
    """
    user_id: str  # ID of the user creating the package
    package_name: str  # Name of the package
    description: str  # Description of the package
    monthly_price: float  # Monthly price of the package

class PackageUpdateRequest(BaseModel):
    """
    Model for updating an existing package.
    """
    user_id: str  # ID of the user requesting the update
    package_name: str = None  # New package name (optional)
    description: str = None  # New description (optional)
    monthly_price: float = None  # New monthly price (optional)

class PackageResponse(BaseModel):
    """
    Response model for returning package details.
    """
    id: str  # Package ID
    package_name: str  # Package name
    description: str  # Package description
    monthly_price: float  # Monthly price

    class Config:
        orm_mode = True  # Ensure compatibility with SQLAlchemy models

class UserRequest(BaseModel):
    """
    Model for receiving user ID in requests.
    """
    user_id: str  # ID of the user

# Title: Package Endpoints

@router.get("/", response_model=list[PackageResponse])
def get_packages(db: Session = Depends(get_db)):
    """
    Fetch all available packages from the database.

    :param db: Database session.
    :return: List of all packages.
    """
    logger.info("Fetching all packages.")
    try:
        # Fetch all packages from the database
        packages = db.query(Package).all()
        if not packages:
            logger.warning("No packages found.")
            raise HTTPException(status_code=404, detail="No packages found.")

        # Log the number of packages retrieved
        logger.debug(f"Fetched {len(packages)} packages.")
        return packages  # Return the list of packages

    except HTTPException:
        raise  # Re-raise the HTTPException if caught
    except Exception as e:
        # Log and handle unexpected errors
        logger.exception(f"Error fetching packages: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")  # Return a server error
