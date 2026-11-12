# Secure Login System

A beginner-friendly secure login web application built using Python Flask, bcrypt password hashing, and SQLite.

## Features

- User Registration and Login
- Password Hashing using bcrypt
- Input Validation
- SQL Injection Protection
- Session Management
- Secure Logout
- CSRF Protection
- Login Rate Limiting
- Protected Dashboard

## Technologies Used

- Python
- Flask
- Flask-Bcrypt
- Flask-SQLAlchemy
- SQLite
- Flask-WTF
- Flask-Limiter

## Project Structure

```text
Secure-Login-System/
│
├── app.py
├── requirements.txt
└── README.md
```

## Installation

**Step 1: Install Python**

Install Python 3.10 or above.

**Step 2: Install Required Libraries**

Open Command Prompt in your project folder and run:

```bash
py -m pip install -r requirements.txt
```

**Step 3: Set Secret Key**

Windows Command Prompt:

```cmd
set SECRET_KEY=your-long-random-secret-key
```

**Step 4: Run the Application**

```bash
py app.py
```

**Step 5: Open in Browser**

```text
http://127.0.0.1:5000
```

## How It Works

1. Users create an account with a username, email, and password.
2. Passwords are hashed using bcrypt before database storage.
3. Users log in using their registered email and password.
4. SQLAlchemy ORM helps protect database queries against SQL injection.
5. Sessions maintain login status.
6. The dashboard is accessible only to logged-in users.
7. Logout clears the user's session.

## Security Features

- bcrypt password hashing
- Input validation
- SQL injection protection through ORM queries
- CSRF protection
- Session-based authentication
- Login rate limiting
- HTTP security headers

## Expected Outcome

A secure login system that protects user accounts using password hashing, input validation, session management, and basic security measures.

## Future Enhancements

- Two-Factor Authentication (2FA)
- Email verification
- Password reset functionality
- User profile management
- Admin dashboard

## Important Note

This is an educational project. Before using it in production, configure HTTPS, a strong secret key, a production web server, and additional account security controls. Never upload real passwords, secret keys, or private user data to GitHub.

## Author

Secure Login System – Python Cybersecurity Mini Project
