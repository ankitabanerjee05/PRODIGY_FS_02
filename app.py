# server.py
import http.server
import socketserver
import json
import sqlite3
import jwt
import datetime
import re
from urllib.parse import urlparse, parse_qs
from http import HTTPStatus
from functools import wraps

# Secret key for JWT (change this in production!)
SECRET_KEY = "your-secret-key-here"
JWT_ALGORITHM = "HS256"

# Database setup
def init_db():
    conn = sqlite3.connect('employees.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create employees table
    c.execute('''CREATE TABLE IF NOT EXISTS employees
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  department TEXT NOT NULL,
                  position TEXT NOT NULL,
                  salary REAL NOT NULL,
                  date_hired DATE NOT NULL,
                  status TEXT DEFAULT 'Active',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create default admin user if not exists
    c.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if c.fetchone()[0] == 0:
        # In a real application, use proper password hashing like bcrypt
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                  ('admin', 'admin123'))  # Change this in production!
    
    conn.commit()
    conn.close()

# Password hashing (simplified for example purposes)
def hash_password(password):
    # In a real application, use a proper hashing algorithm like bcrypt
    return password  # This is just for demonstration!

def verify_password(stored_hash, password):
    # In a real application, use a proper verification function
    return stored_hash == password  # This is just for demonstration!

# JWT token functions
def create_token(user_id):
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
        'iat': datetime.datetime.utcnow(),
        'sub': user_id
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Authentication decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        self = args[0]
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Authorization required'}).encode())
            return
        
        token = auth_header.split(' ')[1]
        user_id = verify_token(token)
        if not user_id:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Invalid token'}).encode())
            return
        
        return f(*args, **kwargs)
    return decorated

# HTTP Request Handler
class EmployeeHandler(http.server.SimpleHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
    
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()
    
    def do_POST(self):
        if self.path == '/login':
            self.handle_login()
        elif self.path == '/employees':
            self.handle_create_employee()
        else:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Endpoint not found'}).encode())
    
    def do_GET(self):
        if self.path == '/employees':
            self.handle_get_employees()
        else:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Endpoint not found'}).encode())
    
    def do_PUT(self):
        if self.path.startswith('/employees/'):
            employee_id = self.path.split('/')[-1]
            self.handle_update_employee(employee_id)
        else:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Endpoint not found'}).encode())
    
    def do_DELETE(self):
        if self.path.startswith('/employees/'):
            employee_id = self.path.split('/')[-1]
            self.handle_delete_employee(employee_id)
        else:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Endpoint not found'}).encode())
    
    def handle_login(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode())
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Username and password are required'}).encode())
            return
        
        conn = sqlite3.connect('employees.db')
        c = conn.cursor()
        c.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and verify_password(user[1], password):
            token = create_token(user[0])
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'token': token,
                'user': {
                    'id': user[0],
                    'username': username
                }
            }).encode())
        else:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Invalid credentials'}).encode())
    
    @requires_auth
    def handle_get_employees(self):
        conn = sqlite3.connect('employees.db')
        c = conn.cursor()
        c.execute("SELECT * FROM employees ORDER BY created_at DESC")
        employees = []
        for row in c.fetchall():
            employees.append({
                'id': row[0],
                'name': row[1],
                'email': row[2],
                'department': row[3],
                'position': row[4],
                'salary': row[5],
                'date_hired': row[6],
                'status': row[7],
                'created_at': row[8],
                'updated_at': row[9]
            })
        conn.close()
        
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(employees).encode())
    
    @requires_auth
    def handle_create_employee(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode())
        
        # Validation
        errors = self.validate_employee_data(data)
        if errors:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(errors).encode())
            return
        
        # Check if email already exists
        conn = sqlite3.connect('employees.db')
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM employees WHERE email = ?", (data['email'],))
        if c.fetchone()[0] > 0:
            conn.close()
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'email': 'Email already exists'}).encode())
            return
        
        # Insert new employee
        c.execute('''INSERT INTO employees 
                    (name, email, department, position, salary, date_hired, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                 (data['name'], data['email'], data['department'], data['position'],
                  data['salary'], data['date_hired'], data.get('status', 'Active')))
        conn.commit()
        conn.close()
        
        self.send_response(HTTPStatus.CREATED)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'message': 'Employee created successfully'}).encode())
    
    @requires_auth
    def handle_update_employee(self, employee_id):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode())
        
        # Validation
        errors = self.validate_employee_data(data, employee_id)
        if errors:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(errors).encode())
            return
        
        conn = sqlite3.connect('employees.db')
        c = conn.cursor()
        
        # Check if email already exists (excluding current employee)
        c.execute("SELECT COUNT(*) FROM employees WHERE email = ? AND id != ?", 
                 (data['email'], employee_id))
        if c.fetchone()[0] > 0:
            conn.close()
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'email': 'Email already exists'}).encode())
            return
        
        # Update employee
        c.execute('''UPDATE employees 
                    SET name = ?, email = ?, department = ?, position = ?, 
                    salary = ?, date_hired = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?''',
                 (data['name'], data['email'], data['department'], data['position'],
                  data['salary'], data['date_hired'], data.get('status', 'Active'), employee_id))
        
        if c.rowcount == 0:
            conn.close()
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Employee not found'}).encode())
            return
        
        conn.commit()
        conn.close()
        
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'message': 'Employee updated successfully'}).encode())
    
    @requires_auth
    def handle_delete_employee(self, employee_id):
        conn = sqlite3.connect('employees.db')
        c = conn.cursor()
        c.execute("DELETE FROM employees WHERE id = ?", (employee_id,))
        
        if c.rowcount == 0:
            conn.close()
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Employee not found'}).encode())
            return
        
        conn.commit()
        conn.close()
        
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'message': 'Employee deleted successfully'}).encode())
    
    def validate_employee_data(self, data, employee_id=None):
        errors = {}
        
        # Name validation
        if not data.get('name') or len(data['name'].strip()) < 2:
            errors['name'] = 'Name must be at least 2 characters long'
        
        # Email validation
        if not data.get('email'):
            errors['email'] = 'Email is required'
        else:
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_regex, data['email']):
                errors['email'] = 'Please enter a valid email address'
        
        # Department validation
        if not data.get('department'):
            errors['department'] = 'Department is required'
        
        # Position validation
        if not data.get('position') or len(data['position'].strip()) < 2:
            errors['position'] = 'Position must be at least 2 characters long'
        
        # Salary validation
        if not data.get('salary'):
            errors['salary'] = 'Salary is required'
        else:
            try:
                salary = float(data['salary'])
                if salary <= 0:
                    errors['salary'] = 'Salary must be greater than 0'
            except ValueError:
                errors['salary'] = 'Salary must be a valid number'
        
        # Date hired validation
        if not data.get('date_hired'):
            errors['date_hired'] = 'Date hired is required'
        else:
            try:
                hired_date = datetime.datetime.strptime(data['date_hired'], '%Y-%m-%d').date()
                if hired_date > datetime.date.today():
                    errors['date_hired'] = 'Date hired cannot be in the future'
            except ValueError:
                errors['date_hired'] = 'Please enter a valid date in YYYY-MM-DD format'
        
        return errors

# Initialize database
init_db()

# Start server
PORT = 8000
with socketserver.TCPServer(("", PORT), EmployeeHandler) as httpd:
    print(f"Server running at http://localhost:{PORT}")
    print("Use Ctrl+C to stop the server")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.shutdown()