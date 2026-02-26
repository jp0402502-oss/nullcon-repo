#!/usr/bin/env python3
"""
Vulnerable Flask Application #2 - FOR EDUCATIONAL PURPOSES ONLY
This application contains intentional security vulnerabilities
DO NOT deploy this in production!
"""

import os
import re
import jwt
import logging
import tempfile
import xml.etree.ElementTree as ET
from flask import (
    Flask, request, redirect, make_response,
    session, send_from_directory, jsonify
)
import requests
import sqlite3

app = Flask(__name__)

# VULNERABILITY 1: Weak / predictable secret key used for session signing
app.secret_key = 'abc'

# VULNERABILITY 2: Logging sensitive information
logging.basicConfig(level=logging.DEBUG, filename='app.log')
logger = logging.getLogger(__name__)

DATABASE = 'app.db'

JWT_SECRET = 'super-secret'  # VULNERABILITY 3: Weak JWT secret


def init_db():
    """Initialize the database"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        title TEXT,
        content TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user'
    )''')
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password', 'admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'guest', 'guest', 'user')")
    c.execute("INSERT OR IGNORE INTO notes VALUES (1, 1, 'Admin Secret', 'The vault code is 9921')")
    c.execute("INSERT OR IGNORE INTO notes VALUES (2, 2, 'Guest Note', 'Nothing special here')")
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# VULNERABILITY 4: XML External Entity (XXE) Injection
# ---------------------------------------------------------------------------
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    """Parse user-supplied XML — vulnerable to XXE."""
    xml_data = request.data
    # Using a parser that allows entity expansion by default
    try:
        tree = ET.fromstring(xml_data)
        return f"Parsed root tag: {tree.tag}, text: {tree.text}"
    except ET.ParseError as e:
        return f"XML parse error: {e}", 400


# ---------------------------------------------------------------------------
# VULNERABILITY 5: Server-Side Request Forgery (SSRF)
# ---------------------------------------------------------------------------
@app.route('/fetch_url')
def fetch_url():
    """Fetch a URL provided by the user — no allow-list, enables SSRF."""
    url = request.args.get('url', '')
    if not url:
        return "Provide a ?url= parameter", 400
    # No validation — attacker can reach internal services
    try:
        resp = requests.get(url, timeout=5)
        logger.info("Fetched URL %s for user (response length %d)", url, len(resp.text))
        return resp.text
    except Exception as e:
        return f"Error fetching URL: {e}", 500


# ---------------------------------------------------------------------------
# VULNERABILITY 6: Insecure JWT – algorithm confusion / none algorithm
# ---------------------------------------------------------------------------
@app.route('/jwt/generate')
def generate_token():
    """Generate a JWT for the given user."""
    username = request.args.get('user', 'guest')
    token = jwt.encode({'user': username, 'role': 'user'}, JWT_SECRET, algorithm='HS256')
    return jsonify({'token': token})


@app.route('/jwt/verify')
def verify_token():
    """Verify a JWT — accepts 'none' algorithm, enabling bypass."""
    token = request.args.get('token', '')
    try:
        # VULNERABLE: algorithms list includes "none"
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256', 'none'])
        return jsonify({'payload': payload})
    except jwt.InvalidTokenError as e:
        return jsonify({'error': str(e)}), 401


# ---------------------------------------------------------------------------
# VULNERABILITY 7: Open Redirect
# ---------------------------------------------------------------------------
@app.route('/redirect')
def open_redirect():
    """Redirect the user to a URL — no validation, allows open redirect."""
    target = request.args.get('next', '/')
    # Attacker can set ?next=https://evil.com
    return redirect(target)


# ---------------------------------------------------------------------------
# VULNERABILITY 8: Insecure Direct Object Reference (IDOR)
# ---------------------------------------------------------------------------
@app.route('/note/<int:note_id>')
def view_note(note_id):
    """View a note by ID — no ownership check (IDOR)."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT title, content FROM notes WHERE id = ?", (note_id,))
    note = c.fetchone()
    conn.close()
    if note:
        return f"<h2>{note[0]}</h2><p>{note[1]}</p>"
    return "Note not found", 404


# ---------------------------------------------------------------------------
# VULNERABILITY 9: Mass Assignment / Over-posting
# ---------------------------------------------------------------------------
@app.route('/profile/update', methods=['POST'])
def update_profile():
    """Update user profile — blindly trusts all incoming fields."""
    user_id = request.form.get('user_id')
    if not user_id:
        return "Missing user_id", 400

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    # Attacker can supply role=admin to escalate privileges
    for field in ('username', 'password', 'role'):
        value = request.form.get(field)
        if value:
            c.execute(f"UPDATE users SET {field} = ? WHERE id = ?", (value, user_id))
    conn.commit()
    conn.close()
    return "Profile updated"


# ---------------------------------------------------------------------------
# VULNERABILITY 10: Regex Denial of Service (ReDoS)
# ---------------------------------------------------------------------------
@app.route('/validate_email')
def validate_email():
    """Validate an email using a catastrophic backtracking regex."""
    email = request.args.get('email', '')
    # Evil regex — exponential backtracking on crafted input
    pattern = r'^([a-zA-Z0-9_.+-]+)+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return f"{email} is valid"
    return f"{email} is invalid"


# ---------------------------------------------------------------------------
# VULNERABILITY 11: Sensitive data in cookies without Secure / HttpOnly flags
# ---------------------------------------------------------------------------
@app.route('/set_session')
def set_session():
    """Set an auth cookie with no Secure or HttpOnly flags."""
    username = request.args.get('user', 'guest')
    resp = make_response(f"Session set for {username}")
    # Missing Secure, HttpOnly, SameSite flags
    resp.set_cookie('auth_token', f'user={username}|role=user', max_age=3600)
    # Logging the sensitive cookie value
    logger.info("Set auth cookie for user: %s", username)
    return resp


# ---------------------------------------------------------------------------
# VULNERABILITY 12: Directory listing / unrestricted file upload
# ---------------------------------------------------------------------------
UPLOAD_FOLDER = tempfile.mkdtemp()
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Upload any file — no type/size restrictions, stored with original name."""
    if request.method == 'POST':
        f = request.files.get('file')
        if not f:
            return "No file provided", 400
        # VULNERABLE: no filename sanitisation, no extension check, no size limit
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
        f.save(save_path)
        logger.info("File uploaded: %s", save_path)
        return f"File saved to {save_path}"

    return '''
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file"><br>
            <input type="submit" value="Upload">
        </form>
    '''


@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    """Serve uploaded files — no auth, potential path traversal."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ---------------------------------------------------------------------------
# VULNERABILITY 13: Race Condition in balance transfer
# ---------------------------------------------------------------------------
balances = {'alice': 100, 'bob': 100}  # in-memory, no locking


@app.route('/transfer', methods=['POST'])
def transfer():
    """Transfer funds between accounts — no locking, TOCTOU race condition."""
    sender = request.form.get('from', '')
    receiver = request.form.get('to', '')
    amount = int(request.form.get('amount', 0))

    if sender not in balances or receiver not in balances:
        return "Unknown account", 400

    # Check-then-act without any lock
    if balances[sender] >= amount:
        balances[sender] -= amount
        balances[receiver] += amount
        return f"Transferred {amount} from {sender} to {receiver}"
    return "Insufficient funds", 400


# ---------------------------------------------------------------------------
# VULNERABILITY 14: Unvalidated HTTP header injection (Host header)
# ---------------------------------------------------------------------------
@app.route('/reset_password')
def reset_password():
    """Send a password-reset link — trusts Host header, enabling header injection."""
    email = request.args.get('email', '')
    # Trusting the Host header lets an attacker craft a malicious reset link
    host = request.headers.get('Host', 'localhost')
    reset_link = f"http://{host}/do_reset?email={email}&token=abc123"
    logger.info("Password reset link generated: %s", reset_link)
    return f"Password reset link sent to {email}: <a href='{reset_link}'>{reset_link}</a>"


# ---------------------------------------------------------------------------
# VULNERABILITY 15: Cleartext password storage & comparison
# ---------------------------------------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user — stores password in cleartext."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Storing plaintext password
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists", 409
        finally:
            conn.close()

        # Logging sensitive credentials
        logger.info("New user registered — username: %s, password: %s", username, password)
        return f"User {username} registered successfully"

    return '''
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Register">
        </form>
    '''


# ---------------------------------------------------------------------------
# VULNERABILITY 16: Lack of rate limiting on auth endpoint
# ---------------------------------------------------------------------------
@app.route('/api/login', methods=['POST'])
def api_login():
    """API login — no rate limiting, brute-force friendly."""
    data = request.get_json(force=True)
    username = data.get('username', '')
    password = data.get('password', '')

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = c.fetchone()
    conn.close()

    if user:
        token = jwt.encode({'user': username, 'role': user[3]}, JWT_SECRET, algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401


# ---------------------------------------------------------------------------
# Home page
# ---------------------------------------------------------------------------
@app.route('/')
def home():
    return '''
        <h1>Vulnerable Application #2</h1>
        <ul>
            <li><a href="/parse_xml">XML Parser (XXE)</a></li>
            <li><a href="/fetch_url?url=http://example.com">Fetch URL (SSRF)</a></li>
            <li><a href="/jwt/generate?user=guest">Generate JWT</a></li>
            <li><a href="/redirect?next=https://example.com">Open Redirect</a></li>
            <li><a href="/note/1">View Note (IDOR)</a></li>
            <li><a href="/validate_email?email=test@test.com">Validate Email (ReDoS)</a></li>
            <li><a href="/set_session?user=guest">Set Session Cookie</a></li>
            <li><a href="/upload">File Upload</a></li>
            <li><a href="/reset_password?email=admin@example.com">Reset Password (Host Header Injection)</a></li>
            <li><a href="/register">Register (Cleartext Password)</a></li>
        </ul>
    '''


if __name__ == '__main__':
    init_db()
    # VULNERABILITY 17: Debug mode in production, binding to all interfaces
    app.run(debug=True, host='0.0.0.0', port=5001)
