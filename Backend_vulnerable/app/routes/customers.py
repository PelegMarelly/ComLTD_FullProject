from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from db.connection import create_connection, execute_query, fetch_results
from utils.loguru_config import loguru_logger
from utils.audit_log import create_audit_log_entry
from datetime import datetime
import uuid 

# Define a new router for handling customer-related routes
router = APIRouter()

def sanitize_query(query: str) -> str:
    """
    Sanitizes an SQL query by removing everything after /* or --.
    This is an attempt to mitigate some SQL injection risks, but it's not foolproof.
    """
    query = query.split("/*")[0]
    query = query.split("--")[0]
    return query.strip()

# Pydantic model for creating a new customer
class CustomerCreate(BaseModel):
    user_id: str
    first_name: str
    last_name: str
    phone_number: str
    email_address: str
    address: str
    package_id: str
    gender: str

# Pydantic model for search queries
class SearchQuery(BaseModel):
    query: str

# Pydantic model for customer response
class CustomerResponse(BaseModel):
    id: str
    first_name: str
    last_name: str
    phone_number: str
    email_address: str
    address: str
    package_id: str
    gender: str


@router.post("/")
def create_customer(customer: CustomerCreate):
    """
    Add a new customer to the database. Vulnerable to XSS and SQL Injection attacks.
    Creates a new customer with default values, then updates the fields based on user input.
    :param customer: CustomerCreate containing details about the new customer.
    :return: A success message with the customer's details.
    """
    
    # Log the action of attempting to create a new customer
    create_audit_log_entry(customer.user_id, "Attempted to create a new customer")
    
    loguru_logger.info(f"Creating customer for user: {customer.user_id}")

    connection = create_connection()  # Create a database connection
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        # Generate a unique ID for the customer using UUID
        customer_id = str(uuid.uuid4())

        # Insert customer with default values to initialize the record in the database
        query = f"""
        INSERT INTO customers (id, first_name, last_name, phone_number, email_address, address, package_id, gender)
        VALUES (
            '{customer_id}',
            'Default First',
            'Default Last',
            '0000000000',
            'default@example.com',
            'Default Address',
            'default_package',
            'Other'
        );
        """
        query = sanitize_query(query)  # Sanitize the query to remove possible malicious content
        loguru_logger.info(f"Executing query: {query}")
        execute_query(connection, query)  # Execute the query in the database
        create_audit_log_entry(customer.user_id, f"Default customer created with ID: {customer_id}")

        # Update fields with user-provided input
        updates = [
            f"UPDATE customers SET first_name = '{customer.first_name}' WHERE id = '{customer_id}';",
            f"UPDATE customers SET last_name = '{customer.last_name}' WHERE id = '{customer_id}';",
            f"UPDATE customers SET phone_number = '{customer.phone_number}' WHERE id = '{customer_id}';",
            f"UPDATE customers SET email_address = '{customer.email_address}' WHERE id = '{customer_id}';",
            f"UPDATE customers SET address = '{customer.address}' WHERE id = '{customer_id}';",
            f"UPDATE customers SET package_id = '{customer.package_id}' WHERE id = '{customer_id}';",
            f"UPDATE customers SET gender = '{customer.gender}' WHERE id = '{customer_id}';"
        ]

        for update in updates:
            try:
                update = sanitize_query(update)  # Sanitize the update query
                loguru_logger.info(f"Executing query: {update}")
                create_audit_log_entry(customer.user_id, f"Field updated successfully: {update}") 
                execute_query(connection, update)  # Execute each update query
            except Exception as e:
                loguru_logger.error(f"Error executing query: {update} - {e}")
                
        # Log that the customer was successfully created and return the response
        create_audit_log_entry(customer.user_id, f"Customer created successfully with ID: {customer_id}")
        loguru_logger.info(f"Customer created successfully: {customer_id}")
        
        return {
            "status": "success",
            "id": customer_id,
            "first_name": customer.first_name,
            "last_name": customer.last_name,
            "message": "Customer created successfully"
        }

    except Exception as e:
        # Rollback transaction in case of an error
        connection.rollback()
        create_audit_log_entry(customer.user_id, f"Error creating customer: {e}")
        loguru_logger.error(f"An error occurred during customer creation: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    finally:
        connection.close()  # Close the database connection after operation is complete



@router.post("/search")
def search_customers(search: SearchQuery):
    """
    Vulnerable endpoint to search customers by a query string.
    Allows SQL Injection with flexibility for information retrieval.
    This endpoint allows searching by multiple fields like name, phone, email, etc.
    """
    create_audit_log_entry("unknown", f"Search initiated with query: {search.query.strip()}")
    
    query = search.query.strip()  # Trim whitespace from the query
    if not query:  # If query is empty, return error
        loguru_logger.warning("Empty query received. Aborting search.")
        return {"status": "error", "message": "Query cannot be empty"}

    loguru_logger.info(f"Searching customers with query: {query}")

    connection = create_connection()  # Create a database connection
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        # Sanitize the query to remove any potential harmful SQL injection attempts
        sanitized_query = sanitize_query(query)
        sql_query = f"""
        SELECT id, first_name, last_name, phone_number, email_address, address, package_id, gender
        FROM customers
        WHERE first_name LIKE '{sanitized_query}%' OR
              last_name LIKE '{sanitized_query}%' OR
              phone_number LIKE '{sanitized_query}%' OR
              email_address LIKE '{sanitized_query}%' OR
              address LIKE '{sanitized_query}%' OR
              package_id LIKE '{sanitized_query}%'
        """
        loguru_logger.info(f"Executing query: {sql_query}")

        # Execute the SQL query and fetch results
        customers = fetch_results(connection, sql_query)

        if not customers:
            create_audit_log_entry("unknown", f"No customers found for query: {query}")
            loguru_logger.info("No customers found matching the query.")
            return {"status": "success", "customers": [], "message": "No results found."}

        # Return the matching customers
        loguru_logger.info(f"Found {len(customers)} customers matching the query.")
        create_audit_log_entry("unknown", f"Found {len(customers)} customers for query: {query}")
        
        return {
            "status": "success",
            "customers": [
                {
                    "id": customer["id"],
                    "first_name": customer["first_name"],
                    "last_name": customer["last_name"],
                    "phone_number": customer["phone_number"],
                    "email_address": customer["email_address"],
                    "address": customer["address"],
                    "package_id": customer["package_id"],
                    "gender": customer["gender"],
                }
                for customer in customers
            ],
            "message": "Customers retrieved successfully",
        }

    except Exception as exc:
        loguru_logger.error(f"An error occurred during customer search: {exc}")
        create_audit_log_entry("unknown", f"Error during search: {exc}")  # Log error during search
        raise HTTPException(status_code=500, detail="Internal server error")

    finally:
        connection.close()  # Close the database connection after operation is complete
