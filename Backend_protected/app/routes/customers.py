from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from ..models.tables import Customer, Package
from ..models.database import get_db
from ..utils.loguru_config import logger
from ..utils.audit_log import create_audit_log_entry
from ..utils.attack_detectors import contains_xss, sanitize_input, prevent_sql_injection
import uuid


router = APIRouter()

# Pydantic model to validate the input data when creating a customer
class CustomerCreate(BaseModel):
    """
    Model to create a new customer with necessary details.
    It validates the input customer data when a new customer is created.
    """
    user_id: str
    first_name: str
    last_name: str
    phone_number: str
    email_address: EmailStr
    address: str
    package_id: str
    gender: str

# Pydantic model to update the customer data
class CustomerUpdate(BaseModel):
    """
    Model to update the existing customer data.
    Fields are optional to allow partial updates.
    """
    user_id: str
    first_name: str = None
    last_name: str = None
    phone_number: str = None
    email_address: EmailStr = None
    address: str = None
    package_id: str = None
    gender: str = None

# Request model for the user_id
class UserRequest(BaseModel):
    """
    Model for user ID to track the user making the request.
    """
    user_id: str

# Response model for the customer details
class CustomerResponse(BaseModel):
    """
    Model to structure the customer data when sending the response back.
    """
    id: str
    first_name: str
    last_name: str
    phone_number: str
    email_address: str
    address: Optional[str]
    package_id: str
    gender: str

    class Config:
        orm_mode = True  # This tells Pydantic to treat SQLAlchemy models as dictionaries for response

# Response model for search results
class CustomerSearchResponse(BaseModel):
    """
    Model to return search results for customers.
    """
    status: str
    message: str
    customers: List[CustomerResponse]

# Pydantic model for the search query input
class SearchQuery(BaseModel):
    """
    Model to structure the search query for customer data.
    """
    query: str

# Helper function to generate a unique customer ID based on the number of existing customers
#def generate_customer_id(session):
#   """
#  Generate a unique customer ID in the format 'cust-<number>' based on the total number of customers.
#    """
#    count = session.query(Customer).count()
#    return f"cust-{count + 1}"

# Function to validate the input data for XSS vulnerabilities
def validate_input(customer: CustomerCreate) -> bool:
    """
    Validate input customer data to check for potential XSS vulnerabilities.
    Returns False if any field contains XSS, else returns True.
    """
    input_fields = [
        customer.user_id,
        customer.first_name,
        customer.last_name,
        customer.phone_number,
        customer.email_address,
        customer.address,
        customer.package_id,
        customer.gender,
    ]

    for field_name, field_value in customer.__dict__.items():
        if contains_xss(field_value):
            logger.warning(f"XSS detected in field '{field_name}': {field_value}")
            return False
    return True

# Endpoint to create a new customer
@router.post("/")
def create_customer(customer: CustomerCreate, db: Session = Depends(get_db)):
    """
    Endpoint to create a new customer in the database.
    """
    logger.info(f"Creating customer for user: {customer.user_id}")
    
    try:
        # Validate input for XSS and SQL Injection immediately
        if not validate_input(customer):
            logger.warning("Potential XSS or SQL Injection detected in customer creation.")
            raise HTTPException(status_code=400, detail="Invalid input detected.")

        # Sanitize inputs and check for SQL Injection during sanitization
        sanitized_user_id = prevent_sql_injection(customer.user_id)
        sanitized_first_name = prevent_sql_injection(customer.first_name)
        sanitized_last_name = prevent_sql_injection(customer.last_name)
        sanitized_phone_number = prevent_sql_injection(customer.phone_number)
        sanitized_email_address = prevent_sql_injection(customer.email_address)
        sanitized_address = prevent_sql_injection(customer.address)
        sanitized_package_id = prevent_sql_injection(customer.package_id)
        sanitized_gender = prevent_sql_injection(customer.gender)

        # Check if any sanitization modified the input, raise an error if true
        if (
            sanitized_user_id != customer.user_id or
            sanitized_first_name != customer.first_name or
            sanitized_last_name != customer.last_name or
            sanitized_phone_number != customer.phone_number or
            sanitized_email_address != customer.email_address or
            sanitized_address != customer.address or
            sanitized_package_id != customer.package_id or
            sanitized_gender != customer.gender
        ):
            logger.warning("Potential SQL Injection detected after sanitization.")
            raise HTTPException(status_code=400, detail="Invalid input detected.")

        # Check if the provided package ID exists
        package = db.query(Package).filter(Package.id == sanitized_package_id).first()
        if not package:
            logger.warning(f"Package not found: {sanitized_package_id}")
            raise HTTPException(status_code=404, detail="Package not found.")

        # Generate a unique customer ID
        new_customer_id = str(uuid.uuid4())

        # Create the new customer record
        new_customer = Customer(
            id=new_customer_id,
            first_name=sanitized_first_name,
            last_name=sanitized_last_name,
            phone_number=sanitized_phone_number,
            email_address=sanitized_email_address,
            address=sanitized_address,
            package_id=sanitized_package_id,
            gender=sanitized_gender
        )
        db.add(new_customer)

        # Update the subscriber count for the package
        package.subscriber_count += 1

        # Commit the changes to the database
        db.commit()
        db.refresh(new_customer)

        # Create an audit log entry for customer creation
        create_audit_log_entry(user_id=sanitized_user_id, action=f"Created customer {new_customer_id}", db=db)
        logger.info(f"Customer created successfully: {new_customer_id}")

        # Return the response
        return {
            "status": "success",
            "id": new_customer.id,
            "first_name": new_customer.first_name,
            "last_name": new_customer.last_name,
            "package_id": new_customer.package_id,
            "message": "Customer created successfully"
        }

    except HTTPException as http_exc:
        raise http_exc  # Raise HTTP exceptions immediately

    except Exception as exc:
        db.rollback()  # Rollback the transaction in case of errors
        logger.error(f"An error occurred during customer creation: {exc}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Endpoint to search customers based on a query string
@router.post("/search", response_model=CustomerSearchResponse)
def search_customers(search: SearchQuery, db: Session = Depends(get_db)):
    """
    Endpoint to search customers by a query string sent in the request body.
    """
    query = search.query
    logger.info(f"Searching customers with query: {query}")

    try:
        # Check if the query is empty
        if not query.strip():
            logger.info("Empty query string received. Returning no results.")
            return {"status": "success", "customers": [], "message": "No results found."}

        # Sanitize the query to prevent SQL injection
        sanitized_query = prevent_sql_injection(query)

        # Query the database for customers matching the query
        customers = db.query(Customer).filter(
            (Customer.first_name.ilike(f"{sanitized_query}%")) |
            (Customer.last_name.ilike(f"{sanitized_query}%")) |
            (Customer.phone_number.ilike(f"{sanitized_query}%")) |
            (Customer.email_address.ilike(f"{sanitized_query}%")) |
            (Customer.address.ilike(f"{sanitized_query}%")) |
            (Customer.package_id.ilike(f"{sanitized_query}%"))
        ).all()

        if not customers:
            logger.info("No customers found matching the query.")
            return {"status": "success", "customers": [], "message": "No results found."}

        # Return the list of matching customers
        logger.info(f"Found {len(customers)} customers matching the query.")
        return {
            "status": "success",
            "customers": [
                CustomerResponse(
                    id=customer.id,
                    first_name=customer.first_name,
                    last_name=customer.last_name,
                    phone_number=customer.phone_number,
                    email_address=customer.email_address,
                    address=customer.address,
                    package_id=customer.package_id,
                    gender=customer.gender,
                )
                for customer in customers
            ],
            "message": "Customers retrieved successfully",
        }

    except Exception as exc:
        logger.error(f"An error occurred during customer search: {exc}")
        raise HTTPException(status_code=500, detail="Internal server error")
