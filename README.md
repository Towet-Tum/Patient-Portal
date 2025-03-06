
# Patient Portal Management System

The Patient Portal Management System is a robust web application designed to streamline healthcare management. It provides secure access for patients, doctors, and administrators to manage appointments, payments, notifications, lab results, and more—all through a set of RESTful API endpoints.

# Features

1 User Authentication: Secure registration, login, token management (obtain & refresh), password reset, and logout functionalities.

2 Role-Based Access: Manage users, roles, and permissions.

3 Profile Management: Maintain detailed profiles for patients and doctors.

4 Appointment Scheduling: Create, update, and view appointments.

5 Payment Integration: Process and track payments.

6 Notifications & Messaging: Real-time alerts and secure messaging between users.

7 Medical Records: Upload and manage prescriptions and lab results.

8 Audit & Integration Logs: Track system activity and integrations for compliance and troubleshooting.

# Architecture & Technology Stack

1 Backend: Python, Django, Django REST Framework

2 Authentication: JSON Web Tokens (JWT) for secure API access (leveraging endpoints like token/obtain_pair and token/refresh)

3 Database: PostgreSQL 

4 Logging: Custom integration and audit logs to monitor system events

5 Deployment: Docker-ready for containerized deployments (optional)

# Installation & Setup

## Clone the Repository

    git clone https://github.com/Towet-Tum/Patient-Portal.git
    cd patient-portal-management

## Create a Virtual Environment

    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate

## Install Dependencies

    pip install -r requirements.txt

## Apply Migrations
    python manage.py makemigrations
    python manage.py migrate

## Create a Superuser

    python manage.py createsuperuser

## Run the Development Server

    python manage.py runserver

Visit http://localhost:8000/admin/ to access the admin panel.
Configuration


## Environment Variables:

    Create a .env file (or configure your environment) with variables such as SECRET_KEY, DATABASE_URL, and any API keys required for third-party integrations.

    Settings:
    Update the settings.py as needed for production—ensure DEBUG=False and configure allowed hosts.

# API Endpoints

The application provides the following endpoints. Each endpoint supports standard HTTP methods (GET, POST, PUT/PATCH, DELETE) as appropriate.
## Authentication & User Management

### Token Management
    POST /token/ – Obtain a new JWT pair. (Name: token_obtain_pair)
    POST /token/refresh/ – Refresh an expired JWT token. (Name: token_refresh)

### User Registration & Login
    POST /register/ – Register a new user account. (Name: user-register)
    POST /login/ – Authenticate user and obtain a token pair. (Alias to token obtain) (Name: token_obtain_pair)
    POST /logout/ – Invalidate the current token and log out the user. (Name: user-logout)

### Password Recovery
    POST /forgot-password/ – Request a password reset.
    POST /reset-password/ – Reset password using token.

### User CRUD
    GET, POST /users/ – List all users or create a new user. (Name: user-list-create)
    GET, PUT, PATCH, DELETE /users/<int:pk>/ – Retrieve, update, or delete a specific user. (Name: user-detail)

## Profiles & Roles

### Roles
    GET, POST /roles/ – List roles or create a new role. (Name: role-list-create)
    GET, PUT, PATCH, DELETE /roles/<int:pk>/ – Manage a specific role. (Name: role-detail)
### User Roles
    GET, POST /userroles/ – List or assign roles to users. (Name: userrole-list-create)
    GET, PUT, PATCH, DELETE /userroles/<int:pk>/ – Manage a specific user-role relationship. (Name: userrole-detail)
### Patient Profiles
    GET, POST /patients/ – List all patient profiles or create a new one. (Name: patientprofile-list-create)
    GET, PUT, PATCH, DELETE /patients/<int:pk>/ – Retrieve or modify a specific patient profile. (Name: patientprofile-detail)
### Doctor Profiles
    GET, POST /doctors/ – List all doctor profiles or create a new one. (Name: doctorprofile-list-create)
    GET, PUT, PATCH, DELETE /doctors/<int:pk>/ – Retrieve or modify a specific doctor profile. (Name: doctorprofile-detail)

## Healthcare Management

### Appointments
    GET, POST /appointments/ – List or create appointments. (Name: appointment-list-create)
    GET, PUT, PATCH, DELETE /appointments/<int:pk>/ – Retrieve or update a specific appointment. (Name: appointment-detail)
### Payments
    GET, POST /payments/ – List payments or process a new payment. (Name: payment-list-create)
    GET, PUT, PATCH, DELETE /payments/<int:pk>/ – Manage a specific payment. (Name: payment-detail)
### Prescriptions
    GET, POST /prescriptions/ – List or create prescriptions. (Name: prescription-list-create)
    GET, PUT, PATCH, DELETE /prescriptions/<int:pk>/ – Manage a specific prescription. (Name: prescription-detail)
### Lab Results
    GET, POST /labresults/ – List or upload lab results. (Name: labresult-list-create)
    GET, PUT, PATCH, DELETE /labresults/<int:pk>/ – Manage a specific lab result. (Name: labresult-detail)

## System Logging & Notifications

### Notifications
    GET, POST /notifications/ – List or create notifications. (Name: notification-list-create)
    GET, PUT, PATCH, DELETE /notifications/<int:pk>/ – Manage a specific notification. (Name: notification-detail)
### Messages
    GET, POST /messages/ – List or create messages. (Name: message-list-create)
    GET, PUT, PATCH, DELETE /messages/<int:pk>/ – Manage a specific message. (Name: message-detail)
### Integration Logs
    GET, POST /integrationlogs/ – Log or retrieve integration events. (Name: integrationlog-list-create)
    GET, PUT, PATCH, DELETE /integrationlogs/<int:pk>/ – Manage a specific integration log. (Name: integrationlog-detail)
### Audit Logs
    GET, POST /auditlogs/ – List or record audit events. (Name: auditlog-list-create)
    GET, PUT, PATCH, DELETE /auditlogs/<int:pk>/ – Manage a specific audit log. (Name: auditlog-detail)

## Usage Examples
### Authenticating & Obtaining a JWT Token

    curl -X POST http://localhost:8000/token/ \
    -H "Content-Type: application/json" \
    -d '{"username": "your_username", "password": "your_password"}'

### Creating a Patient Profile

    curl -X POST http://localhost:8000/patients/ \
    -H "Authorization: Bearer <your_jwt_token>" \
    -H "Content-Type: application/json" \
    -d '{"first_name": "John", "last_name": "Doe", "date_of_birth": "1980-01-01", "medical_history": "None"}'

### Scheduling an Appointment

    curl -X POST http://localhost:8000/appointments/ \
    -H "Authorization: Bearer <your_jwt_token>" \
    -H "Content-Type: application/json" \
    -d '{"patient": 1, "doctor": 2, "appointment_date": "2025-04-01T10:00:00Z", "notes": "Regular check-up"}'

## Testing

### Unit & Integration Tests:
    Run tests using Django’s testing framework:

        python manage.py test

### API Testing:
    Use tools like Postman or curl to test endpoints. Ensure you include authentication tokens in the header when required.

## Contributing


Contributions are welcome! Please follow these steps to contribute:

    Fork the repository.
    Create a feature branch (git checkout -b feature/my-new-feature).
    Commit your changes and push to your fork.
    Open a pull request with a clear description of your changes.

Ensure your code adheres to the project’s coding standards and passes all tests.
License


## This project is licensed under the MIT License.

