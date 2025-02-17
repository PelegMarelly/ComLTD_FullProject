import json
from pathlib import Path
from db.connection import create_connection
from utils.loguru_config import loguru_logger as logger
from utils.password_utils import hash_password, validate_password

def load_data_from_file(file_path):
    """
    Load data from a JSON file.
    :param file_path: Path to the JSON file.
    :return: List of dictionaries with data.
    """
    try:
        if not Path(file_path).exists():
            logger.error(f"File not found: {file_path}")
            return []
        with open(file_path, "r") as file:
            data = json.load(file)
            logger.info(f"Successfully loaded {len(data)} records from {file_path}.")
            return data
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON file {file_path}: {e}")
        return []


def populate_table(connection, table_name, data, unique_column):
    """
    Populate a database table with data if the entries are not already present.
    :param connection: Database connection object.
    :param table_name: Name of the table to populate.
    :param data: List of dictionaries with data to populate.
    :param unique_column: Column to check for uniqueness before insertion.
    """
    if not data:
        logger.warning(f"No data to populate for table '{table_name}'. Exiting.")
        return

    try:
        cursor = connection.cursor()
        for record in data:
            # Check if the record already exists
            unique_value = record[unique_column]
            query = f"SELECT COUNT(*) FROM {table_name} WHERE {unique_column} = '{unique_value}'"
            cursor.execute(query)
            exists = cursor.fetchone()[0]

            if exists:
                logger.info(
                    f"Record with {unique_column}='{unique_value}' already exists in table '{table_name}'. Skipping.")
                continue

            # For the 'users' table, validate the password if present
            if table_name == "users":
                if 'password' in record:
                    password = record['password']
                    # Validate the password
                    if not validate_password(password, record['id']):
                        logger.warning(f"Password validation failed for user {record['id']}. Skipping record.")
                        continue  # Skip the record if the password is invalid

                    # Hash the password and generate the salt
                    salt, hashed_password = hash_password(password)
                    record['hashed_password'] = hashed_password
                    record['salt'] = salt
                    del record['password']  # Remove the password field from the record

            # Insert the new record
            columns = ", ".join(record.keys())
            values = "', '".join(str(v).replace("'", "''") for v in record.values())  # Escape single quotes in values

            insert_query = f"INSERT INTO {table_name} ({columns}) VALUES ('{values}')"
            cursor.execute(insert_query)
            logger.info(f"Inserted new record into '{table_name}': {record}")

        connection.commit()
        logger.info(f"Successfully populated the '{table_name}' table.")
    except Exception as e:
        connection.rollback()
        logger.error(f"Failed to populate table '{table_name}': {e}")
    finally:
        cursor.close()


def populate_all_tables():
    """
    Populate all tables with initial data.
    """
    connection = create_connection()
    if not connection:
        logger.error("Failed to connect to the database. Exiting population process.")
        return

    try:
        # Populate the 'packages' table with initial data
        packages_data = load_data_from_file("utils/init_packages_data.json")
        populate_table(connection, "packages", packages_data, "package_name")

        # Populate the 'users' table with example data (including password validation)
        users_data = [
            {
                "id": "user-1",
                "full_name": "Elon Musk",
                "username": "elonmusk",
                "email": "elon.musk@example.com",
                "phone_number": "555-123-4567",
                "password": "Tesla@2025",
                "gender": "Male"
            },
            {
                "id": "user-2",
                "full_name": "Ariana Grande",
                "username": "arianagrande",
                "email": "ariana.grande@example.com",
                "phone_number": "555-987-6543",
                "password": "ThankUNext@2025",
                "gender": "Female"
            },
            {
                "id": "user-3",
                "full_name": "Chris Hemsworth",
                "username": "chrishemsworth",
                "email": "chris.hemsworth@example.com",
                "phone_number": "555-234-5678",
                "password": "Thor@Asgard2025",
                "gender": "Male"
            },
            {
                "id": "user-4",
                "full_name": "Emma Watson",
                "username": "emmawatson",
                "email": "emma.watson@example.com",
                "phone_number": "555-345-6789",
                "password": "Hermione@Magic2025",
                "gender": "Female"
            },
            {
                "id": "user-5",
                "full_name": "Taylor Swift",
                "username": "taylorswift13",
                "email": "taylor.swift@example.com",
                "phone_number": "555-456-7890",
                "password": "LoveStory@2025",
                "gender": "Female"
            }
        ]

        populate_table(connection, "users", users_data, "username")

        # Populate the 'customers' table with example data
        customers_data = [
            {
                "id": "cust-1",
                "first_name": "Emma",
                "last_name": "Watson",
                "phone_number": "555-123-4567",
                "email_address": "emma.watson@example.com",
                "address": "12, King's Road, London, UK",
                "package_id": "pak-3",
                "gender": "Female"
            },
            {
                "id": "cust-2",
                "first_name": "Robert",
                "last_name": "Downey Jr.",
                "phone_number": "555-234-5678",
                "email_address": "robert.downey@example.com",
                "address": "33, Sunset Blvd, Los Angeles, CA, USA",
                "package_id": "pak-2",
                "gender": "Male"
            },
            {
                "id": "cust-3",
                "first_name": "Scarlett",
                "last_name": "Johansson",
                "phone_number": "555-345-6789",
                "email_address": "scarlett.johansson@example.com",
                "address": "44, Park Avenue, New York, NY, USA",
                "package_id": "pak-1",
                "gender": "Female"
            },
            {
                "id": "cust-4",
                "first_name": "Chris",
                "last_name": "Hemsworth",
                "phone_number": "555-456-7890",
                "email_address": "chris.hemsworth@example.com",
                "address": "55, Oak Street, Sydney, Australia",
                "package_id": "pak-4",
                "gender": "Male"
            },
            {
                "id": "cust-5",
                "first_name": "Zendaya",
                "last_name": "Coleman",
                "phone_number": "555-567-8901",
                "email_address": "zendaya.coleman@example.com",
                "address": "66, Beverly Hills, California, USA",
                "package_id": "pak-1",
                "gender": "Female"
            }
        ]

        populate_table(connection, "customers", customers_data, "email_address")

    except Exception as e:
        logger.error(f"Failed to populate tables: {e}")
    finally:
        connection.close()
        logger.info("Database connection closed.")
