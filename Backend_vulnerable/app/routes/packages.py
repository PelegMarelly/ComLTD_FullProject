from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from db.connection import create_connection, execute_query, fetch_results
from utils.loguru_config import loguru_logger
from utils.audit_log import create_audit_log_entry

router = APIRouter()

def sanitize_query(query: str) -> str:
    """
    Sanitizes an SQL query by removing everything after /* or --.
    This function removes SQL comments to prevent injection of malicious SQL commands 
    through user input. It is important to note that this is not a secure method to 
    prevent SQL injection, and further improvements are required for proper query sanitization.
    """
    query = query.split("/*")[0]  # Removes anything after "/*"
    query = query.split("--")[0]  # Removes anything after "--"
    return query.strip()

# Define a Pydantic model to represent the response data for a package
class PackageResponse(BaseModel):
    id: str
    package_name: str
    description: str
    monthly_price: int

@router.get("/", response_model=list[PackageResponse])
def get_packages():
    """
    Fetch all available packages from the database. Vulnerable to SQL Injection.

    This endpoint does not properly sanitize user input, allowing an attacker to inject 
    malicious SQL commands into the query.
    
    :return: List of all packages.
    """
    loguru_logger.info("Fetching all packages.")  # Log the action of fetching packages
    create_audit_log_entry("unknown", "Attempted to fetch all packages")  # Log audit entry for the action

    # Create a connection to the database
    connection = create_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")  # Raise error if the connection fails

    try:
        # Vulnerable SQL query
        query = "SELECT id, package_name, description, monthly_price FROM packages"
        query = sanitize_query(query)  # Sanitize the query (though not a secure method for preventing SQL injection)
        packages = fetch_results(connection, query)  # Execute the query and fetch results

        # Check if any packages were found
        if not packages:
            loguru_logger.warning("No packages found.")  # Log warning if no packages are found
            create_audit_log_entry("unknown", "No packages found during fetch attempt")  # Log audit entry for no results
            raise HTTPException(status_code=404, detail="No packages found.")  # Raise error if no packages are found

        loguru_logger.debug(f"Fetched {len(packages)} packages.")  # Log debug message for the number of packages retrieved
        create_audit_log_entry("unknown", f"Fetched {len(packages)} packages successfully")  # Log audit entry for successful fetch
        return packages  # Return the list of packages

    except Exception as e:
        # Log error if an exception occurs
        create_audit_log_entry("unknown", f"Error occurred while fetching packages: {e}")
        loguru_logger.error(f"Error fetching packages: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")  # Raise server error

    finally:
        connection.close()  # Ensure the connection is closed
