# Employee Records Management System (CRUD)
A secure web application for administrators to manage employee records with full CRUD (Create, Read, Update, Delete) operations, authentication, and data validation.

# Features
🔐 Secure Authentication - JWT-based login system with password hashing

👥 Employee Management - Complete CRUD operations for employee records

✅ Data Validation - Both client-side and server-side validation

🛡️ Security - Protected endpoints and SQL injection prevention

📱 Responsive Design - Works on desktop and mobile devices

💾 Database Integration - SQLite database with proper schema design

# Tech Stack
- Frontend: HTML5, CSS3, JavaScript (ES6+)
- Backend: Python with Flask framework
- Database: SQLite with SQLAlchemy ORM
- Authentication: JWT (JSON Web Tokens)
- Security: bcrypt for password hashing

# Installation & Setup
- Clone the repository:
  git clone https://github.com/your-username/employee-management-system.git
  cd employee-management-system

- Install Python dependencies:
  pip install flask flask-sqlalchemy flask-bcrypt flask-jwt-extended

- Run the application:
  python app.py

# Default Login Credentials
Username: admin
Password: admin123

# Features in Detail
- Add new employees with validated data
- Edit existing employee information
- Delete employee records with confirmation
- Department-based filtering
- Salary information management
- Responsive table design for all screen sizes
- Secure authentication with token expiration


This application demonstrates proper full-stack development practices with attention to security, validation, and user experience.
