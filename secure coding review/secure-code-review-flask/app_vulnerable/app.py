import os
import base64
import pickle
import traceback
from flask import Flask, render_template, render_template_string, request, redirect, url_for, session, send_file, flash, make_response
import database

# Initialize Flask App
app = Flask(__name__)

# # VULN-05: Hardcoded SECRET_KEY in source code
# Storing sensitive secrets directly in code repositories allows unauthorized access if source code leaks.
app.config['SECRET_KEY'] = 'super-secret-hardcoded-key-12345'

# Upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# # VULN-13: Insecure Session Cookie Flags
# Disabling HttpOnly allows JavaScript access to session cookies (vulnerable to XSS theft).
# Disabling Secure allows session cookies over unencrypted HTTP.
# Setting SameSite to None permits cross-site requests (vulnerable to CSRF).
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'None'


# Initialize database table structures
database.init_db()


# # VULN-10: Insecure Deserialization via pickle Cookie Handling
# Custom request hook that reads a base64-encoded cookie and deserializes it with Python's `pickle`.
# An attacker can supply a malicious pickled payload to achieve Arbitrary Code Execution (RCE).
@app.before_request
def load_custom_session():
    custom_session_cookie = request.cookies.get('user_session_state')
    if custom_session_cookie:
        try:
            # Unsafe deserialization using pickle.loads()
            raw_bytes = base64.b64decode(custom_session_cookie)
            session['custom_state'] = pickle.loads(raw_bytes)
        except Exception:
            pass


@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    # # VULN-12: Missing CSRF protection on login form
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        try:
            # Calls database function containing SQL injection (# VULN-01)
            user = database.authenticate_user(username, password)
            if user:
                session['user'] = {
                    'id': user['id'],
                    'username': user['username'],
                    'role': user['role']
                }
                flash(f"Welcome back, {user['username']}!", "success")
                
                response = make_response(redirect(url_for('dashboard')))
                
                # Set custom state cookie using pickle encoding (# VULN-10 helper)
                state_data = {'user': user['username'], 'role': user['role']}
                encoded_state = base64.b64encode(pickle.dumps(state_data)).decode('utf-8')
                response.set_cookie('user_session_state', encoded_state)
                return response
            else:
                flash("Invalid credentials!", "error")
        except Exception as e:
            # Exposes database errors to template (# VULN-11 helper)
            flash(f"Database error during authentication: {str(e)}", "error")
            
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    # # VULN-12: Missing CSRF protection on registration form
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        bio = request.form.get('bio', '')
        
        if database.get_user_by_username(username):
            flash("Username already exists!", "error")
        else:
            # Password saved with unsalted MD5 (# VULN-04)
            database.create_user(username, password, bio)
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))
            
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('user_session_state')
    flash("Logged out successfully.", "info")
    return response


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = session['user']
    notes = database.get_all_notes()
    return render_template('dashboard.html', user=current_user, notes=notes)


@app.route('/search')
def search():
    """
    Search route for finding notes.
    """
    if 'user' not in session:
        return redirect(url_for('login'))
        
    query = request.args.get('q', '')
    notes = []
    error = None
    
    if query:
        try:
            # Calls database search function vulnerable to SQL Injection (# VULN-01)
            notes = database.search_notes(query)
        except Exception as e:
            error = f"SQL syntax error: {str(e)}"
            
    # Note: Search query is passed to template where it is rendered with | safe (# VULN-06)
    return render_template('dashboard.html', user=session['user'], notes=notes, query=query, error=error)


@app.route('/note/<int:note_id>')
def view_note(note_id):
    """
    # VULN-02: Broken Access Control / Insecure Direct Object Reference (IDOR)
    Fetches note by note_id directly from DB and displays it to ANY authenticated user.
    Does NOT check if note['user_id'] == session['user']['id'].
    Any user can view private notes of other users simply by changing the URL parameter.
    """
    if 'user' not in session:
        return redirect(url_for('login'))
        
    note = database.get_note_by_id(note_id)
    if not note:
        flash("Note not found!", "error")
        return redirect(url_for('dashboard'))
        
    return render_template('note.html', user=session['user'], note=note)


@app.route('/note/new', methods=['GET', 'POST'])
def new_note():
    # # VULN-12: Missing CSRF protection on note creation POST route
    if 'user' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        title = request.form.get('title', '')
        content = request.form.get('content', '')
        attachment_filename = ""
        
        # File upload handling (# VULN-09)
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file and file.filename != '':
                # # VULN-09: Unrestricted File Upload
                # No validation on file extensions, MIME types, or file sizes.
                # Filename is not sanitized using werkzeug secure_filename.
                attachment_filename = file.filename
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], attachment_filename)
                file.save(filepath)
                
        database.create_note(session['user']['id'], title, content, attachment_filename)
        flash("Note created successfully!", "success")
        return redirect(url_for('dashboard'))
        
    return render_template('note_new.html', user=session['user'])


@app.route('/note/delete/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    """
    # VULN-02: Broken Access Control / IDOR on Note Deletion
    # VULN-12: Missing CSRF protection on state-changing deletion
    Deletes note specified by ID without validating that the logged-in user owns the note.
    """
    if 'user' not in session:
        return redirect(url_for('login'))
        
    # Deletes note without ownership check!
    database.delete_note_by_id(note_id)
    flash(f"Note #{note_id} deleted successfully.", "success")
    return redirect(url_for('dashboard'))


@app.route('/profile/<username>')
def profile(username):
    """
    # VULN-07: Server-Side Template Injection (SSTI)
    Profile page fetches the user bio from database and formats it directly into a Jinja2 template string
    before evaluating it with `render_template_string()`.
    An attacker can put `{{7*7}}` or `{{config}}` in their bio to execute code server-side.
    """
    if 'user' not in session:
        return redirect(url_for('login'))
        
    target_user = database.get_user_by_username(username)
    if not target_user:
        flash("User not found!", "error")
        return redirect(url_for('dashboard'))
        
    user_bio = target_user['bio'] or "No bio provided."
    
    # Vulnerable SSTI construction: string formatting user input into raw Jinja template code
    template_str = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Profile - {username}</title></head>
    <body style="font-family: sans-serif; margin: 2rem;">
        <a href="/dashboard">&larr; Back to Dashboard</a>
        <h2>User Profile: {target_user['username']}</h2>
        <p><strong>Role:</strong> {target_user['role']}</p>
        <div style="background: #f4f4f4; padding: 1rem; border-radius: 4px;">
            <h3>Bio:</h3>
            <p>{user_bio}</p>
        </div>
    </body>
    </html>
    """
    
    return render_template_string(template_str)


@app.route('/profile/update', methods=['POST'])
def update_profile():
    # # VULN-12: Missing CSRF protection
    if 'user' not in session:
        return redirect(url_for('login'))
        
    bio = request.form.get('bio', '')
    database.update_user_bio(session['user']['id'], bio)
    flash("Profile bio updated!", "success")
    return redirect(url_for('profile', username=session['user']['username']))


@app.route('/download')
def download_file():
    """
    # VULN-08: Path Traversal / Unsanitized File Path Input
    The parameter `file` is passed directly into `os.path.join(UPLOAD_FOLDER, filename)`
    without validating against directory traversal sequences like `../../app.py` or `/etc/passwd`.
    """
    if 'user' not in session:
        return redirect(url_for('login'))
        
    filename = request.args.get('file', '')
    if not filename:
        flash("No file specified!", "error")
        return redirect(url_for('dashboard'))
        
    # Path Traversal vulnerability: no secure_filename or path boundary check
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        flash(f"Download failed: {str(e)}", "error")
        return redirect(url_for('dashboard'))


@app.route('/admin')
def admin_panel():
    """
    # VULN-03: Missing Authorization / Broken Function Level Access Control
    The route checks if a user is logged in, but NEVER checks if `session['user']['role'] == 'admin'`.
    Any regular logged-in user can access `/admin` and view all registered users and notes.
    """
    if 'user' not in session:
        return redirect(url_for('login'))
        
    # Note: Missing role authorization check!
    users = database.get_all_users()
    notes = database.get_all_notes()
    return render_template('admin.html', user=session['user'], all_users=users, all_notes=notes)


# # VULN-11: Verbose Stack Traces & Debug Exception Handler
# Returning unhandled exception messages and complete tracebacks directly to HTTP client response.
@app.errorhandler(Exception)
def handle_exception(e):
    # Pass through HTTP errors
    if hasattr(e, 'code'):
        return str(e), e.code
    
    # Verbose stack trace leakage
    error_traceback = traceback.format_exc()
    response_body = f"""
    <h1>500 Internal Server Error</h1>
    <p>An error occurred in TeamNotes application:</p>
    <pre style="background: #222; color: #ff6b6b; padding: 1rem; border-radius: 4px;">{error_traceback}</pre>
    """
    return response_body, 500


if __name__ == '__main__':
    # # VULN-11: Debug Mode Enabled in Production Server Startup
    # Running Flask with debug=True enables the interactive Werkzeug debugger in browser console.
    print("[*] Starting TeamNotes (Vulnerable Target Application)...")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
