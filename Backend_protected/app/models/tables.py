from sqlalchemy import Column, String, Integer, Text, Boolean, ForeignKey, DateTime, Enum
from sqlalchemy.orm import relationship
from uuid import uuid4
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from enum import Enum as PyEnum
from ..utils.loguru_config import logger
from sqlalchemy.sql import func
from sqlalchemy.orm.session import Session

# Title: Database Models and Relationships

# Base for tables
def generate_package_id(session: Session):
    """
    Generate a unique package ID in the format 'pak-<number>'.

    :param session: SQLAlchemy session.
    :return: Generated package ID.
    """
    count = session.query(Package).count()  # Get the count of existing packages
    return f"pak-{count + 1}"  # Return the new package ID

Base = declarative_base()  # Create the base class for all models

# Title: Enumerations

# Enum for Gender
class Gender(PyEnum):
    """
    Enum for representing gender values.
    """
    MALE = "Male"
    FEMALE = "Female"
    OTHER = "Other"

# Title: Database Tables

# User Table
class User(Base):
    """
    Table for storing user information.

    Attributes:
        id: Primary key, UUID.
        full_name: Full name of the user.
        username: Unique username.
        email: Unique email address.
        phone_number: User's phone number.
        hashed_password: Securely hashed password.
        is_active: Status of the user's account.
        is_logged_in: Indicates if the user is currently logged in.
        current_token: Active authentication token.
        last_login: Timestamp of the last login.
        gender: Gender of the user.
    """
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))  # UUID primary key
    full_name = Column(String(255), nullable=False)  # User's full name
    username = Column(String(255), unique=True, nullable=False)  # Unique username
    email = Column(String(255), unique=True, nullable=False)  # Unique email address
    phone_number = Column(String(20), nullable=True)  # Phone number (optional)
    hashed_password = Column(String(255), nullable=False)  # Hashed password for security
    salt = Column(String(255), nullable=False)  # Salt for password hashing
    password_history = Column(Text, nullable=True)  # Password history stored in JSON format
    failed_attempts = Column(Integer, default=0)  # Tracks failed login attempts
    is_active = Column(Boolean, default=True)  # Account status (active/inactive)
    is_logged_in = Column(Boolean, default=False)  # Indicates whether the user is logged in
    current_token = Column(String(255), nullable=True)  # Active token for authentication
    last_login = Column(DateTime, nullable=True, default=datetime.utcnow)  # Timestamp of the last login
    gender = Column(Enum(Gender), nullable=True)  # User's gender (using Enum for predefined values)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logger.debug(f"User model initialized: {self.username}, Email: {self.email}")

# Customer Table
class Customer(Base):
    """
    Table for storing customer information.

    Attributes:
        id: Primary key, unique customer ID.
        first_name: First name of the customer.
        last_name: Last name of the customer.
        phone_number: Contact number.
        email_address: Unique email address.
        address: Optional address details.
        package_id: Foreign key linking to a package.
        gender: Gender of the customer.
    """
    __tablename__ = "customers"

    id = Column(String(50), primary_key=True)  # Customer's unique ID
    first_name = Column(String(50), nullable=False)  # Customer's first name
    last_name = Column(String(50), nullable=False)  # Customer's last name
    phone_number = Column(String(15), nullable=False)  # Customer's phone number
    email_address = Column(String(100), nullable=False, unique=True)  # Unique email address
    address = Column(Text, nullable=True)  # Customer's address (optional)
    package_id = Column(String(50), ForeignKey("packages.id"), nullable=False)  # Foreign key to package
    gender = Column(String(10), nullable=False)  # Gender of the customer

    package = relationship("Package", back_populates="customers")  # Relationship with Package table

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logger.debug(f"Customer model initialized: {self.first_name} {self.last_name}, Email: {self.email_address}")

# Packages Table
class Package(Base):
    """
    Table for storing package details.

    Attributes:
        id: Primary key, unique package ID.
        package_name: Name of the package.
        description: Optional package description.
        monthly_price: Price of the package per month.
        subscriber_count: Number of customers subscribed to the package.
    """
    __tablename__ = "packages"

    id = Column(String(50), primary_key=True)  # Package's unique ID
    package_name = Column(String(50), nullable=False, unique=True)  # Package name
    description = Column(Text, nullable=True)  # Package description (optional)
    monthly_price = Column(Integer, nullable=False)  # Price of the package per month
    subscriber_count = Column(Integer, default=0)  # Number of customers subscribed to the package

    customers = relationship("Customer", back_populates="package")  # Relationship with Customer table

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logger.debug(f"Package model initialized: {self.package_name}, Price: {self.monthly_price}")

# Audit Logs Table
class AuditLog(Base):
    """
    Table for tracking user actions.

    Attributes:
        id: Primary key, auto-incremented ID.
        user_id: Foreign key linking to the user.
        action: Description of the user action.
        timestamp: Timestamp of the action.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)  # Auto-incremented primary key
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)  # Foreign key linking to User table
    action = Column(Text, nullable=False)  # Description of the action
    timestamp = Column(DateTime, default=datetime.utcnow)  # Timestamp of the action

    user = relationship("User", back_populates="audit_logs")  # Relationship with User table

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logger.debug(f"AuditLog initialized for User ID: {self.user_id}, Action: {self.action}")

# Contact Form Submissions Table
class ContactSubmission(Base):
    """
    Table for storing contact form submissions.

    Attributes:
        id: Primary key, UUID.
        name: Name of the submitter.
        email: Email address of the submitter.
        message: Message content.
        submitted_at: Timestamp of submission.
    """
    __tablename__ = "contact_submissions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))  # UUID primary key
    name = Column(String(255), nullable=False)  # Submitter's name
    email = Column(String(255), nullable=False)  # Submitter's email
    message = Column(Text, nullable=False)  # Submitted message
    submitted_at = Column(DateTime, default=datetime.utcnow)  # Timestamp of submission

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logger.debug(f"ContactSubmission initialized: Name: {self.name}, Email: {self.email}")

# Password Reset Table
class PasswordReset(Base):
    """
    Table for managing password reset requests.

    Attributes:
        id: Primary key, UUID.
        user_id: Foreign key linking to the user.
        reset_token: Unique token for password reset.
        token_expiry: Expiry time of the token.
        used: Indicates if the token has been used.
    """
    __tablename__ = "password_resets"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))  # UUID primary key
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)  # Foreign key linking to User table
    reset_token = Column(String(255), nullable=False, unique=True)  # Unique token for password reset
    token_expiry = Column(DateTime, nullable=False)  # Expiry date of the reset token
    used = Column(Boolean, default=False)  # Whether the token has been used

    user = relationship("User", back_populates="password_resets")  # Relationship with User table

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logger.debug(f"PasswordReset model initialized for User ID: {self.user_id}")

# Relationships

# Relationship on the User Table
User.audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")  # User to AuditLog relationship
User.password_resets = relationship(
    "PasswordReset",
    order_by=PasswordReset.id,
    back_populates="user",
    cascade="all, delete-orphan"
)  # User to PasswordReset relationship