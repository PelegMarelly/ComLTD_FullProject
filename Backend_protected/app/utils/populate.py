import json
import uuid
from pathlib import Path
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError
from ..models.database import engine
from ..models.tables import Package, User, Customer
from ..utils.loguru_config import loguru_logger as logger
from ..utils.validators import hash_password, validate_password, update_password_history



def load_packages_from_file(file_path="app/utils/init_packages_data.json"):
    """
    Load package data from a JSON file.
    This function reads the package data from a JSON file and returns it as a list of dictionaries.

    :param file_path: Path to the JSON file containing package data.
    :return: List of package dictionaries if successful, empty list if the file is not found or invalid.
    """
    try:
        if not Path(file_path).exists():
            logger.error(f"File not found: {file_path}")  # Log error if file does not exist
            return []
        with open(file_path, "r") as file:
            packages = json.load(file)  # Parse the JSON file into Python objects
            logger.info(f"Successfully loaded {len(packages)} packages from file.")
            return packages
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON file {file_path}: {e}")  # Log if the file cannot be parsed
        return []




def populate_packages(file_path="app/utils/init_packages_data.json"):
    """
    Populate the 'packages' table with data from a JSON file if not already present.
    This function checks if the package data is already in the database. If not, it adds the data.

    :param file_path: Path to the JSON file containing package data.
    """
    # Load packages data from the specified file
    packages = load_packages_from_file(file_path)
    if not packages:
        logger.warning("No packages to populate. Exiting.")  # Log if no packages are loaded
        return

    # Create a session for interacting with the database
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    try:
        logger.info("Starting to populate the 'packages' table.")

        # Get the last package ID to create a new unique ID for the next package
        last_package = session.query(Package).order_by(Package.id.desc()).first()
        last_id = int(last_package.id.split('-')[1]) if last_package else 0  # Parse last ID for continuation

        with session.no_autoflush:
            # Iterate through each package in the loaded data
            for package in packages:
                # Check if the package already exists in the database
                existing_package = session.query(Package).filter_by(package_name=package["package_name"]).first()
                if existing_package:
                    logger.info(f"Package '{package['package_name']}' already exists. Skipping.")
                    continue  # Skip if package is already present in the database

                # Create a new unique package ID
                last_id += 1
                package_id = f"pak-{last_id}"  # Format new package ID

                # Create a new Package object
                new_package = Package(
                    id=package_id,
                    package_name=package["package_name"],
                    description=package["description"],
                    monthly_price=package["monthly_price"],
                )
                session.add(new_package)  # Add the new package to the session
                logger.info(f"Added new package: {package['package_name']} with ID: {package_id}.")

        session.commit()  # Commit the transaction to the database
        logger.info("Successfully populated the 'packages' table.")
    except SQLAlchemyError as e:
        session.rollback()  # Rollback in case of error to maintain database consistency
        logger.error(f"Failed to populate the 'packages' table: {e}")
    finally:
        session.close()  # Ensure the session is properly closed
        logger.debug("Database session closed.")



def populate_users(session: Session, users_data: list):
    """
    Populate the 'users' table with initial data, ensuring password security.

    :param session: Database session object.
    :param users_data: List of dictionaries containing user data.
    """
    try:
        for user in users_data:
            existing_user = session.query(User).filter(User.username == user["username"]).first()
            if existing_user:
                logger.info(f"User '{user['username']}' already exists. Skipping.")
                continue

            user_id = str(uuid.uuid4())  # Generate a temporary ID for validation

            # Generate secure password hash and salt
            salt, hashed_password = hash_password(user["password"])

            new_user = User(
                id=user_id,
                full_name=user["full_name"],
                username=user["username"],
                email=user["email"],
                phone_number=user.get("phone_number"),
                hashed_password=hashed_password,
                salt=salt,
                password_history=json.dumps([]),
                failed_attempts=0,
                is_active=True,
                is_logged_in=False,
                current_token=None,
                last_login=None,
                gender=user.get("gender")
            )

            session.add(new_user)
            session.commit()

            # Update password history
            update_password_history(new_user.id, user["password"], session)

            logger.info(f"Inserted new user: {user['username']}")

        logger.info("Successfully populated 'users' table.")
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Failed to populate 'users' table: {e}")

def populate_customers(session: Session, customers_data: list):
    """
    Populate the 'customers' table with initial data.

    :param session: Database session object.
    :param customers_data: List of dictionaries containing customer data.
    """
    try:
        for customer in customers_data:
            existing_customer = session.query(Customer).filter(Customer.email_address == customer["email_address"]).first()
            if existing_customer:
                logger.info(f"Customer '{customer['email_address']}' already exists. Skipping.")
                continue

            # Ensure package_id exists
            package_exists = session.query(Package).filter(Package.id == customer["package_id"]).first()
            if not package_exists:
                logger.warning(f"Package ID '{customer['package_id']}' not found. Skipping customer {customer['email_address']}.")
                continue
            
            new_customer = Customer(
                id=str(uuid.uuid4()),
                first_name=customer["first_name"],
                last_name=customer["last_name"],
                phone_number=customer["phone_number"],
                email_address=customer["email_address"],
                address=customer.get("address"),
                package_id=customer["package_id"],
                gender=customer["gender"]
            )

            session.add(new_customer)
            logger.info(f"Inserted new customer: {customer['email_address']}")

        session.commit()
        logger.info("Successfully populated 'customers' table.")
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Failed to populate 'customers' table: {e}")


def populate_all_tables():
    """
    Populate all tables with initial data.
    """
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    try:
        # User data
        users_data = [
            {
                "full_name": "Elon Musk",
                "username": "elonmusk",
                "email": "elon.musk@example.com",
                "phone_number": "555-123-4567",
                "password": "Tesla@2025",
                "gender": "Male"
            },
            {
                "full_name": "Ariana Grande",
                "username": "arianagrande",
                "email": "ariana.grande@example.com",
                "phone_number": "555-987-6543",
                "password": "ThankUNext@2025",
                "gender": "Female"
            },
            {
                "full_name": "Chris Hemsworth",
                "username": "chrishemsworth",
                "email": "chris.hemsworth@example.com",
                "phone_number": "555-234-5678",
                "password": "Thor@Asgard2025",
                "gender": "Male"
            },
            {
                "full_name": "Emma Watson",
                "username": "emmawatson",
                "email": "emma.watson@example.com",
                "phone_number": "555-345-6789",
                "password": "Hermione@Magic2025",
                "gender": "Female"
            },
            {
                "full_name": "Taylor Swift",
                "username": "taylorswift13",
                "email": "taylor.swift@example.com",
                "phone_number": "555-456-7890",
                "password": "LoveStory@2025",
                "gender": "Female"
            }
        ]

        # Customer data
        customers_data = [
            {
                "first_name": "Emma",
                "last_name": "Watson",
                "phone_number": "555-123-4567",
                "email_address": "emma.watson@example.com",
                "address": "12, King's Road, London, UK",
                "package_id": "pak-3",
                "gender": "Female"
            },
            {
                "first_name": "Robert",
                "last_name": "Downey Jr.",
                "phone_number": "555-234-5678",
                "email_address": "robert.downey@example.com",
                "address": "33, Sunset Blvd, Los Angeles, CA, USA",
                "package_id": "pak-2",
                "gender": "Male"
            },
            {
                "first_name": "Scarlett",
                "last_name": "Johansson",
                "phone_number": "555-345-6789",
                "email_address": "scarlett.johansson@example.com",
                "address": "44, Park Avenue, New York, NY, USA",
                "package_id": "pak-1",
                "gender": "Female"
            },
            {
                "first_name": "Chris",
                "last_name": "Hemsworth",
                "phone_number": "555-456-7890",
                "email_address": "chris.hemsworth@example.com",
                "address": "55, Oak Street, Sydney, Australia",
                "package_id": "pak-4",
                "gender": "Male"
            },
            {
                "first_name": "Zendaya",
                "last_name": "Coleman",
                "phone_number": "555-567-8901",
                "email_address": "zendaya.coleman@example.com",
                "address": "66, Beverly Hills, California, USA",
                "package_id": "pak-1",
                "gender": "Female"
            }
        ]

        # Populate tables
        populate_packages()
        populate_users(session, users_data)
        populate_customers(session, customers_data)

    except Exception as e:
        logger.error(f"Failed to populate tables: {e}")
    finally:
        session.close()
        logger.info("Database session closed.")


