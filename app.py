import os
import re
from datetime import timedelta

from flask import Flask, flash, redirect, render_template_string, request, session, url_for
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

# -------------------- App configuration --------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-this-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///secure_login.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Enable secure cookies when deployed behind HTTPS.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=[])


# -------------------- Database model --------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)


# -------------------- HTML templates --------------------
BASE_STYLE = """
<style>
body{font-family:Arial,sans-serif;background:#f3f5f9;margin:0;color:#202938}
main{max-width:430px;margin:55px auto;background:white;padding:28px;border-radius:14px;
box-shadow:0 8px 28px #17203318}
h1{margin-top:0;font-size:25px}label{display:block;margin:14px 0 6px}
input{box-sizing:border-box;width:100%;padding:11px;border:1px solid #cbd2dc;border-radius:7px}
button{width:100%;margin-top:18px;padding:12px;background:#174ea6;color:white;border:0;
border-radius:7px;font-weight:bold;cursor:pointer}
a{color:#174ea6}.message{padding:10px;background:#eef5ff;border-radius:7px;margin:10px 0}
.small{font-size:13px;color:#596579}.nav{display:flex;gap:15px;margin-bottom:20px}
</style>
"""

REGISTER_PAGE = """
<!doctype html><html><head><meta charset="utf-8"><title>Create account</title>""" + BASE_STYLE + """</head>
<body><main><h1>Create account</h1>
{% with messages = get_flashed_messages() %}{% for message in messages %}<div class="message">{{ message }}</div>{% endfor %}{% endwith %}
<form method="post">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label>Username</label><input name="username" required minlength="3" maxlength="30" autocomplete="username">
<label>Email</label><input type="email" name="email" required maxlength="254" autocomplete="email">
<label>Password</label><input type="password" name="password" required minlength="10" autocomplete="new-password">
<p class="small">Use at least 10 characters. A longer, unique passphrase is recommended.</p>
<button type="submit">Register</button></form>
<p>Already registered? <a href="{{ url_for('login') }}">Log in</a></p></main></body></html>
"""

LOGIN_PAGE = """
<!doctype html><html><head><meta charset="utf-8"><title>Login</title>""" + BASE_STYLE + """</head>
<body><main><h1>Secure Login</h1>
{% with messages = get_flashed_messages() %}{% for message in messages %}<div class="message">{{ message }}</div>{% endfor %}{% endwith %}
<form method="post">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label>Email</label><input type="email" name="email" required autocomplete="email">
<label>Password</label><input type="password" name="password" required autocomplete="current-password">
<button type="submit">Log in</button></form>
<p>New here? <a href="{{ url_for('register') }}">Create an account</a></p></main></body></html>
"""

DASHBOARD_PAGE = """
<!doctype html><html><head><meta charset="utf-8"><title>Dashboard</title>""" + BASE_STYLE + """</head>
<body><main><h1>Welcome, {{ user.username }}!</h1>
<p>You are logged in. This page is protected by a session check.</p>
<div class="nav"><a href="{{ url_for('dashboard') }}">Dashboard</a></div>
<form method="post" action="{{ url_for('logout') }}">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<button type="submit">Log out</button></form></main></body></html>
"""


# -------------------- Helpers --------------------
def valid_email(email):
    return bool(re.fullmatch(r"[^\\s@]+@[^\\s@]+\\.[^\\s@]+", email))


def logged_in_user():
    user_id = session.get("user_id")
    return db.session.get(User, user_id) if user_id else None


# -------------------- Routes --------------------
@app.route("/")
def home():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            flash("Username must be 3-30 characters: letters, numbers, or underscore.")
            return redirect(url_for("register"))
        if len(email) > 254 or not valid_email(email):
            flash("Enter a valid email address.")
            return redirect(url_for("register"))
        if len(password) < 10:
            flash("Password must contain at least 10 characters.")
            return redirect(url_for("register"))

        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        user = User(username=username, email=email, password_hash=password_hash)
        try:
            db.session.add(user)
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("That username or email may already be registered.")
            return redirect(url_for("register"))

        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))

    return render_template_string(REGISTER_PAGE)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = db.session.query(User).filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id
            session.permanent = True
            return redirect(url_for("dashboard"))

        # Same message for unknown email and incorrect password.
        flash("Invalid email or password.")

    return render_template_string(LOGIN_PAGE)


@app.route("/dashboard")
def dashboard():
    user = logged_in_user()
    if user is None:
        session.clear()
        return redirect(url_for("login"))
    return render_template_string(DASHBOARD_PAGE, user=user)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))


# -------------------- Basic security headers --------------------
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    return response


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    # Local development only. Use a production WSGI server for deployment.
    app.run(host="127.0.0.1", port=5000, debug=False)
