#!/usr/bin/env python3
"""
Vulnerable Flask Application - FOR EDUCATIONAL PURPOSES ONLY
This application contains intentional security vulnerabilities
DO NOT deploy this in production!
"""

import os
import pickle
import sqlite3
import subprocess
from flask import Flask, request, render_template_string, send_file
import hashlib
import yaml

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded credentials
DATABASE = 'users.db'
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'  # Hardcoded password
SECRET_KEY = 'my-secret-key-12345'  # Hardcoded secret key
API_KEY = 'sk-1234567890abcdef'  # Hardcoded API key
AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'  # Hardcoded AWS key
AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

app.secret_key = SECRET_KEY

def init_db():
    """Initialize a vulnerable database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            secret_data TEXT
        )
    ''')
    # Insert some test data
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@example.com')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password', 'user@example.com')")
    cursor.execute("INSERT OR IGNORE INTO secrets VALUES (1, 1, 'Secret admin data')")
    conn.commit()
    conn.close()

# VULNERABILITY 2: SQL Injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # SQL Injection vulnerability - no parameterization
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            return f"Welcome {user[1]}! Your email is {user[3]}"
        else:
            return "Invalid credentials"

    return '''
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

# VULNERABILITY 3: Cross-Site Scripting (XSS)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # XSS vulnerability - no escaping
    return render_template_string(f'''
        <h1>Search Results for: {query}</h1>
        <p>You searched for: {query}</p>
    ''')

# VULNERABILITY 4: Command Injection
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        host = request.form['host']
        # Command injection vulnerability
        result = subprocess.check_output(f'ping -c 1 {host}', shell=True)
        return f'<pre>{result.decode()}</pre>'

    return '''
        <form method="post">
            Host to ping: <input name="host"><br>
            <input type="submit" value="Ping">
        </form>
    '''

# VULNERABILITY 5: Path Traversal
@app.route('/download')
def download():
    filename = request.args.get('file', '')
    # Path traversal vulnerability - no validation
    return send_file(filename)

# VULNERABILITY 6: Insecure Deserialization
@app.route('/load_profile', methods=['POST'])
def load_profile():
    data = request.form['data']
    # Insecure deserialization with pickle
    profile = pickle.loads(data.encode('latin1'))
    return f'Profile loaded: {profile}'

# VULNERABILITY 7: Weak Cryptography
@app.route('/hash_password')
def hash_password():
    password = request.args.get('password', '')
    # Using weak MD5 hash
    hashed = hashlib.md5(password.encode()).hexdigest()
    return f'Hashed password (MD5): {hashed}'

# VULNERABILITY 8: YAML Deserialization (unsafe)
@app.route('/parse_config', methods=['POST'])
def parse_config():
    config_data = request.form['config']
    # Unsafe YAML parsing
    config = yaml.load(config_data, Loader=yaml.Loader)
    return f'Config parsed: {config}'

# VULNERABILITY 9: Debug mode enabled
@app.route('/debug_info')
def debug_info():
    return f'''
        <h1>Debug Information</h1>
        <p>Environment variables: {dict(os.environ)}</p>
        <p>Secret Key: {app.secret_key}</p>
        <p>AWS Key: {AWS_ACCESS_KEY}</p>
    '''

# VULNERABILITY 10: No authentication required
@app.route('/admin/delete_user/<user_id>')
def delete_user(user_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id={user_id}")
    conn.commit()
    conn.close()
    return f'User {user_id} deleted'

# VULNERABILITY 11: Information disclosure
@app.route('/error')
def cause_error():
    # This will show full stack trace
    x = 1 / 0
    return "This won't be reached"

@app.route('/')
def home():
    return '''
        <h1>Vulnerable Application</h1>
        <ul>
            <li><a href="/login">Login (SQL Injection)</a></li>
            <li><a href="/search?q=test">Search (XSS)</a></li>
            <li><a href="/ping">Ping (Command Injection)</a></li>
            <li><a href="/download?file=app.py">Download (Path Traversal)</a></li>
            <li><a href="/hash_password?password=test">Hash Password (Weak Crypto)</a></li>
            <li><a href="/debug_info">Debug Info (Information Disclosure)</a></li>
        </ul>
    '''

if __name__ == '__main__':
    init_db()
    # VULNERABILITY 12: Debug mode in production
    app.run(debug=True, host='0.0.0.0', port=5000)
