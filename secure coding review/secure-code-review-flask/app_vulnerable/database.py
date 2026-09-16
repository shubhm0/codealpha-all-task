import sqlite3
import hashlib
import os

# # VULN-05: Hardcoded Database Path
# Storing the database path as a hardcoded relative string directly in source code
DB_FILE = "teamnotes.db"

def get_db_connection():
    """Establishes and returns a SQLite database connection."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    """
    Hashes a password for storage or comparison.
    
    # VULN-04: Insecure Cryptographic Password Hashing
    Using unsalted MD5 algorithm to hash user passwords. MD5 is fast, vulnerable
    to collision attacks, and can be easily reversed using precomputed rainbow tables.
    """
    return hashlib.md5(password.encode('utf-8')).hexdigest()

def init_db():
    """Initializes the database schema and seeds initial test data."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            bio TEXT DEFAULT ''
        )
    ''')
    
    # Create notes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            attachment TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    
    # Seed initial test data if table is empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Admin account (MD5 for 'admin123')
        admin_pass = hash_password("admin123")
        cursor.execute(
            "INSERT INTO users (username, password, role, bio) VALUES (?, ?, ?, ?)",
            ('admin', admin_pass, 'admin', 'System administrator profile. Managed by IT team.')
        )
        
        # Standard user account (MD5 for 'password123')
        alice_pass = hash_password("password123")
        cursor.execute(
            "INSERT INTO users (username, password, role, bio) VALUES (?, ?, ?, ?)",
            ('alice', alice_pass, 'user', 'Software developer interested in security.')
        )
        
        # Second user (MD5 for 'welcome123')
        bob_pass = hash_password("welcome123")
        cursor.execute(
            "INSERT INTO users (username, password, role, bio) VALUES (?, ?, ?, ?)",
            ('bob', bob_pass, 'user', 'Project manager for the engineering team.')
        )
        
        conn.commit()
        
        # Add sample notes
        cursor.execute(
            "INSERT INTO notes (user_id, title, content, attachment) VALUES (?, ?, ?, ?)",
            (1, 'System Maintenance Notice', 'Server reboot scheduled for midnight UTC.', '')
        )
        cursor.execute(
            "INSERT INTO notes (user_id, title, content, attachment) VALUES (?, ?, ?, ?)",
            (2, 'Project Architecture Draft', 'Remember to review the Flask backend specs.', '')
        )
        cursor.execute(
            "INSERT INTO notes (user_id, title, content, attachment) VALUES (?, ?, ?, ?)",
            (3, 'Q3 Roadmap Overview', 'Target launch for new feature set is October 15th.', '')
        )
        conn.commit()
        
    conn.close()

def authenticate_user(username, password):
    """
    Validates user credentials against the database.
    
    # VULN-01: SQL Injection via String Interpolation
    The input parameters `username` and `password_hash` are formatted directly into the SQL string.
    An attacker can supply input like `admin' --` to bypass authentication completely without knowing the password.
    """
    password_hash = hash_password(password)
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Vulnerable SQL query construction using f-strings
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        return user
    except sqlite3.OperationalError as e:
        conn.close()
        raise e

def search_notes(query_string):
    """
    Searches notes by title or content matching query_string.
    
    # VULN-01: SQL Injection in Search Feature
    String concatenation is used to insert search terms directly into SQL query text.
    Payloads such as `' UNION SELECT 1,username,password,role,'' FROM users --` allow extracting secret user data.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Vulnerable search query construction
    query = f"SELECT notes.*, users.username FROM notes JOIN users ON notes.user_id = users.id WHERE title LIKE '%{query_string}%' OR content LIKE '%{query_string}%'"
    
    try:
        cursor.execute(query)
        notes = cursor.fetchall()
        conn.close()
        return notes
    except sqlite3.OperationalError as e:
        conn.close()
        raise e

def get_user_by_username(username):
    """Fetches user record by username."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    """Fetches user record by user ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(username, password, bio=""):
    """Registers a new user into the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Uses MD5 hashing (# VULN-04)
    hashed_pass = hash_password(password)
    cursor.execute(
        "INSERT INTO users (username, password, role, bio) VALUES (?, ?, 'user', ?)",
        (username, hashed_pass, bio)
    )
    conn.commit()
    conn.close()

def get_user_notes(user_id):
    """Retrieves all notes created by a specific user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    notes = cursor.fetchall()
    conn.close()
    return notes

def get_all_notes():
    """Retrieves all notes in the application."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT notes.*, users.username FROM notes JOIN users ON notes.user_id = users.id ORDER BY created_at DESC")
    notes = cursor.fetchall()
    conn.close()
    return notes

def get_note_by_id(note_id):
    """
    Retrieves a single note by its database primary key.
    Note: Function caller must verify authorization, but often fails to do so (# VULN-02).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT notes.*, users.username FROM notes JOIN users ON notes.user_id = users.id WHERE notes.id = ?", (note_id,))
    note = cursor.fetchone()
    conn.close()
    return note

def create_note(user_id, title, content, attachment=""):
    """Creates a new note for a user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO notes (user_id, title, content, attachment) VALUES (?, ?, ?, ?)",
        (user_id, title, content, attachment)
    )
    conn.commit()
    conn.close()

def delete_note_by_id(note_id):
    """Deletes a note by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    conn.commit()
    conn.close()

def update_user_bio(user_id, bio):
    """Updates user profile bio."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user_id))
    conn.commit()
    conn.close()

def update_user_password(user_id, new_password):
    """Updates user password."""
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed = hash_password(new_password)
    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
    conn.commit()
    conn.close()

def get_all_users():
    """Retrieves all registered users for admin view."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, bio FROM users")
    users = cursor.fetchall()
    conn.close()
    return users
