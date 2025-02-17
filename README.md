
# ComLTD Web Application Project

## Overview
This project is a full-stack web application developed for a fictional communication company, **ComLTD**, which markets internet data packages. The application demonstrates secure and vulnerable implementations of backend systems, showcasing how to mitigate attacks like SQL Injection and XSS. It includes functionalities such as user registration, login, password recovery, and managing customer information.

## Project Structure
- **Frontend**: Built with ReactJS, providing an interactive and dynamic user experience.
- **Backend**: Developed using FastAPI in Python with two versions:
  - **Protected Backend**: Implements security measures against SQL Injection and XSS using SQLAlchemy and input sanitization.
  - **Vulnerable Backend**: Lacks security measures to demonstrate vulnerabilities.
- **Database**: MySQL relational database for storing user, customer, and package data.
- **Docker**: Used for containerization, ensuring consistent environments across development and deployment.

## Features
### User Management
- **Register**: User registration with validation and email verification.
- **Login**: Authenticate users with email/username and password.
- **Password Recovery**: Email-based token verification for resetting passwords.

### Customer Management
- Add, update, and delete customers with details like name, email, phone, and chosen package.

### Security Demonstrations
- **SQL Injection**: Demonstrated on registration, login, and customer search endpoints.
- **XSS (Stored and Reflected)**: Demonstrated on user inputs in the registration and customer management forms.

### Additional Pages
- **Packages Page**: View available data packages.
- **About Us Page**: Company details.
- **Contact Us Page**: Email-based communication form.

## Technologies Used
- **Frontend**: ReactJS, HTML, CSS
- **Backend**: FastAPI, Python, SQLAlchemy (protected backend), MySQL-Connector (vulnerable backend)
- **Database**: MySQL
- **Containerization**: Docker with Docker Compose

## Installation and Usage
1. **Clone the repository**:
   ```bash
   git clone https://github.com/ItayVazana1/ComLTD_FullProject.git
   cd ComLTD_FullProject
   ```

2. **Set up environment variables**:
   - Edit `.env` files in the backend and frontend directories to configure settings like database credentials and API URLs.

3. **Build and run the project**:
   
   Windows:
   ```bash
   docker-compose up --build
   ```
   Linux:
   ```bash
   docker compose up -d
   ```

4. **Access the application**:
   - **Frontend**: [http://localhost:3000](http://localhost:3000)
   - **Protected Backend**: [http://localhost:10000](http://localhost:10000)
   - **Vulnerable Backend**: [http://localhost:11000](http://localhost:11000)

## Testing Scenarios
### SQL Injection
- **Register**: Inject malicious SQL commands in the username or email fields.
- **Login**: Bypass authentication using SQL injection.
- **Search Customer**: Retrieve unauthorized data via injected queries.

### XSS
- **Register**: Inject scripts into input fields, stored in the database.
- **Add New Customer**: Inject malicious scripts into customer data fields.

### Security Measures (Protected Backend)
- Input sanitization with SQLAlchemy and regex-based filtering.
- Use of parameterized queries and prepared statements.
- Immediate rejection of suspicious input with detailed logging.

## File Structure
```
ComLTD_FullProject/
├── frontend/              # ReactJS-based user interface
├── backend_protected/     # Secure backend implementation
├── backend_vulnerable/    # Vulnerable backend implementation
├── docker-compose.yml     # Docker setup
└── init.sql               # initialization of the DB
```

## Authors
- [Itay Vazana](https://github.com/ItayVazana1)
- [Mor Dvash](https://github.com/MorDvash)
- [Peleg Marelly](https://github.com/PelegMarelly)
- [Maayan Huss](https://github.com/MaayanHuss)

## License
This project is open-source and available under the [MIT License](LICENSE).
