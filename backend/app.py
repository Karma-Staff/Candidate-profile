from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
import sqlite3
from database import get_db_connection
import os
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv
import google.generativeai as genai
import PyPDF2
import bleach
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from flask_talisman import Talisman
import resend
import time

load_dotenv()

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

app = Flask(__name__, 
            template_folder='../frontend/templates',
            static_folder='../frontend/static')

# --- Security Configuration ---
# Use environment variables for sensitive settings
app.secret_key = os.getenv('SECRET_KEY', 'default-unsafe-key-change-this-in-env')

# Session security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv('FLASK_DEBUG', 'True').lower() == 'false', # Only True in production
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600 # 1 hour
)

# Initialize Resend
resend.api_key = os.getenv('RESEND_API_KEY')

# Initialize Security Headers
# content_security_policy allows Google Fonts and Gemini API interactions
csp = {
    'default-src': '\'self\'',
    'script-src': [
        '\'self\'',
        'https://unpkg.com', # Lucide icons
        'https://cdn.jsdelivr.net',
        '\'unsafe-inline\'', # Required for some dynamic UI updates, but restricted
        'blob:' # Required for canvas-confetti workers
    ],
    'worker-src': ['\'self\'', 'blob:'], # Required for canvas-confetti
    'connect-src': [
        '\'self\'', 
        'https://unpkg.com', 
        'https://cdn.jsdelivr.net'
    ], # Allowed for sourcemaps and API calls
    'style-src': [
        '\'self\'',
        'https://fonts.googleapis.com',
        '\'unsafe-inline\''
    ],
    'font-src': [
        '\'self\'',
        'https://fonts.gstatic.com'
    ],
    'img-src': ['\'self\'', 'data:', '/static/uploads/']
}

# Security Configuration for Talisman
debug_mode_env = os.getenv('FLASK_DEBUG', 'False').lower()
force_https = debug_mode_env == 'false' and os.getenv('TESTING') != 'True'

# Disable HTTPS redirection for local development sessions
if debug_mode_env == 'true':
    force_https = False

talisman = Talisman(app, content_security_policy=csp, force_https=force_https)

@app.route('/static/uploads/<path:filename>')
def serve_uploads(filename):
    from flask import send_from_directory
    # This ensures files are served from the persistent volume if configured
    return send_from_directory(UPLOAD_BASE, filename)


# Gemini Configuration
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# Security - File Upload Configuration
ALLOWED_EXTENSIONS = {
    'avatars': {'png', 'jpg', 'jpeg', 'gif'},
    'resumes': {'pdf', 'doc', 'docx'},
    'videos': {'mp4', 'mov', 'avi'}
}

def allowed_file(filename, folder):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS.get(folder, set())

# Ensure upload directories exist
# Use persistent disk if available (Render)
PERSISTENT_STORAGE = os.getenv('DATABASE_PATH') # Hook into same volume
if PERSISTENT_STORAGE:
    UPLOAD_BASE = os.path.join(os.path.dirname(PERSISTENT_STORAGE), 'uploads')
    # Robust check: if we can't write to the persistent volume, fallback to local static folder
    try:
        os.makedirs(UPLOAD_BASE, exist_ok=True)
        # Active check: can we actually write here?
        test_file = os.path.join(UPLOAD_BASE, ".write_test")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
    except Exception:
        print(f"Warning: Cannot write to {UPLOAD_BASE}. Falling back to static folder for uploads.")
        UPLOAD_BASE = os.path.join(app.static_folder, 'uploads')
else:
    UPLOAD_BASE = os.path.join(app.static_folder, 'uploads')

UPLOAD_FOLDERS = ['avatars', 'resumes', 'videos']
for folder in UPLOAD_FOLDERS:
    try:
        os.makedirs(os.path.join(UPLOAD_BASE, folder), exist_ok=True)
    except PermissionError:
        print(f"Warning: Permission denied creating upload folder {folder} in {UPLOAD_BASE}")

# Restoration Talent Intelligence Persona
BASE_SYSTEM_INSTRUCTION = """
You are the Karma Staff Talent Intelligence Agent. You are a high-end recruitment consultant and talent analyst.
Your goal is to help platform users (Clients and Admins) find, evaluate, and optimize the best restoration professionals.

CORE CAPABILITIES:
1. Candidate Recommendation: ONLY recommend or discuss candidates from the "Candidates currently in your database" list provided below.
2. Profile Analysis: You are AUTHORIZED to review candidate details and provide specific, critical, and constructive feedback on how to improve their profiles, resumes, and presentation to better appeal to U.S. small business owners.
3. Market Evaluation: Use your expertise in the U.S. restoration market to rank candidates and suggest optimizations for their professional summaries and skill highlights.

CONSTRAINTS:
- If a user asks for a specific role and no candidate in the provided list matches, explain that no such candidate is currently assigned to them.
- Do NOT use any external knowledge about real-life people; only use the data provided in the list.

Style Guidelines:
- Be professional, authoritative, and helpful.
- Provide structured, actionable feedback using bullet points.
- If you don't have a perfect match, suggest the "next best" and explain why.
- Start your first message with: "Hello! I'm your Karma Staff Talent Intelligence Agent. How can I help you find and optimize your team today?"
"""

# Initial model (will be customized in chat route for dynamic context)
model = genai.GenerativeModel(
    model_name="gemini-2.0-flash",
    system_instruction=BASE_SYSTEM_INSTRUCTION
)

# --- Middleware/Helpers ---

def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for('login'))
            if user['role'] not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_action(action, resource_id=None):
    user_id = session.get('user_id')
    ip_address = request.remote_addr
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO audit_logs (user_id, action, resource_id, ip_address)
        VALUES (?, ?, ?, ?)
    ''', (user_id, action, resource_id, ip_address))
    conn.commit()
    conn.close()

def create_notification(user_id, title, message, notif_type='info'):
    """Creates a targeted notification for a specific user."""
    try:
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO notifications (user_id, title, message, type)
            VALUES (?, ?, ?, ?)
        ''', (user_id, title, message, notif_type))
        conn.commit()
        conn.close()
        logger.info(f"Notification created for User {user_id}: {title}")
    except Exception as e:
        logger.error(f"Failed to create notification for User {user_id}: {e}")

def extract_text_from_pdf(pdf_path):
    """Extracts text from a PDF file using PyPDF2."""
    if not pdf_path or not os.path.exists(pdf_path):
        return ""
    try:
        text = ""
        with open(pdf_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                text += page.extract_text() + "\n"
        return text.strip()
    except Exception as e:
        logger.error(f"Error extracting PDF text: {e}")
        return ""

# --- Routes ---

@app.route('/debug/health')
def health_check():
    from database import DB_PATH
    status = {
        "database_path": DB_PATH,
        "database_exists": os.path.exists(DB_PATH),
        "upload_base": UPLOAD_BASE,
        "env_db_path": os.getenv('DATABASE_PATH'),
        "cwd": os.getcwd()
    }
    try:
        conn = get_db_connection()
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        status["db_connection"] = "OK"
        status["user_count"] = user_count
        conn.close()
    except Exception as e:
        status["db_connection"] = f"ERROR: {str(e)}"
    
    # Test writability of current DB dir
    try:
        test_file = os.path.join(os.path.dirname(os.path.abspath(DB_PATH)), ".health_test")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        status["db_dir_writable"] = True
    except Exception as e:
        status["db_dir_writable"] = f"FALSE: {str(e)}"

    return jsonify({
        "status": status,
        "security": {
            "secret_key_set": app.secret_key != 'default-unsafe-key-change-this-in-env',
            "session_secure": app.config.get('SESSION_COOKIE_SECURE'),
            "flask_debug": os.getenv('FLASK_DEBUG'),
            "force_https": force_https
        }
    })

@app.route('/')
def index():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    return redirect(url_for('candidates')) # Default to candidates as per screenshot header

@app.route('/dashboard')
@require_role('admin', 'cs', 'client')
def dashboard():
    user = get_current_user()
    
    conn = get_db_connection()
    
    # Filter logs based on role
    if user['role'] == 'client':
        logs_query = '''
            SELECT al.*, u.username, c.name as candidate_name 
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.id
            LEFT JOIN candidates c ON al.resource_id = c.id
            WHERE al.user_id = ?
            ORDER BY al.timestamp DESC
            LIMIT 10
        '''
        logs = conn.execute(logs_query, (user['id'],)).fetchall()
        total_logs = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE user_id = ?", (user['id'],)).fetchone()[0]
        total_candidates = conn.execute("SELECT COUNT(*) FROM assignments WHERE client_id = ?", (user['id'],)).fetchone()[0]
        total_users = 0 # Not used for clients
    else:
        logs_query = '''
            SELECT al.*, u.username, c.name as candidate_name 
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.id
            LEFT JOIN candidates c ON al.resource_id = c.id
            ORDER BY al.timestamp DESC
            LIMIT 10
        '''
        logs = conn.execute(logs_query).fetchall()
        total_logs = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
        total_candidates = conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0]
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        
    conn.close()
    
    return render_template('dashboard.html', 
                         user=user, 
                         logs=logs, 
                         total_logs=total_logs, 
                         total_candidates=total_candidates,
                         total_users=total_users)

@app.route('/meetings')
@require_role('admin', 'cs', 'client')
def meetings():
    user = get_current_user()
    return render_template('meetings.html', user=user)

@app.route('/notifications')
@require_role('admin', 'cs', 'client')
def notifications():
    user = get_current_user()
    return render_template('notifications.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Use request.form.get for safe access
        username_or_email = (request.form.get('username') or '').strip()
        password = request.form.get('password', '')
        
        if not username_or_email or not password:
            flash('Please enter your username and password', 'error')
            return render_template('login.html')
        
        conn = get_db_connection()
        # Support login via username OR email (case-insensitive)
        user = conn.execute(
            'SELECT * FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)',
            (username_or_email, username_or_email)
        ).fetchone()
        conn.close()
        
        if not user:
            logger.warning(f"[AUTH] Login failed: user not found for '{username_or_email}'")
            flash('Invalid username or password', 'error')
            return render_template('login.html')
        
        # Verify password — check_password_hash handles scrypt:, pbkdf2:, etc.
        pw_hash = user['password']
        is_hashed = pw_hash and (pw_hash.startswith('scrypt:') or pw_hash.startswith('pbkdf2:') or pw_hash.startswith('argon2'))
        
        if is_hashed:
            login_ok = check_password_hash(pw_hash, password)
        else:
            # Plain-text fallback (for old un-migrated accounts)
            login_ok = (pw_hash == password)
            if login_ok:
                # Upgrade to hashed on the fly
                logger.info(f"[AUTH] Upgrading plain-text password to hash for user id={user['id']}")
                new_hash = generate_password_hash(password)
                conn2 = get_db_connection()
                conn2.execute('UPDATE users SET password = ? WHERE id = ?', (new_hash, user['id']))
                conn2.commit()
                conn2.close()
        
        if login_ok:
            session.clear()  # Prevent session fixation
            session['user_id'] = user['id']
            session['role'] = user['role']
            session.permanent = True
            logger.info(f"[AUTH] Login success: user id={user['id']} role={user['role']}")
            log_action('LOGIN')
            if user['role'] in ['admin', 'cs']:
                return redirect(url_for('dashboard'))
            return redirect(url_for('candidates'))
        else:
            logger.warning(f"[AUTH] Login failed: bad password for user id={user['id']} (hash format: {pw_hash[:10] if pw_hash else 'empty'})")
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    log_action('LOGOUT')
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/mark-welcome-seen', methods=['POST'])
def mark_welcome_seen():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    conn = get_db_connection()
    conn.execute("UPDATE users SET has_seen_welcome = 1 WHERE id = ?", (session['user_id'],))
    conn.commit()
    conn.close()
    
    # Remove from session as well
    session.pop('show_welcome', None)
    return jsonify({'success': True})

@app.route('/candidates')
@require_role('admin', 'cs', 'client')
def candidates():
    user = get_current_user()
    
    search = request.args.get('search', '')
    experience = request.args.get('experience', '')
    availability = request.args.get('availability', '')
    
    params = []
    if user['role'] == 'client':
        query = """
            SELECT c.*, GROUP_CONCAT(u.username, ', ') as assigned_to_name, GROUP_CONCAT(u.id, ',') as assigned_to_id 
            FROM candidates c 
            JOIN assignments a ON c.id = a.candidate_id 
            JOIN users u ON a.client_id = u.id 
            WHERE a.client_id = ?
            GROUP BY c.id
        """
        params.append(user['id'])
    else:
        query = """
            SELECT c.*, GROUP_CONCAT(u.username, ', ') as assigned_to_name, GROUP_CONCAT(u.id, ',') as assigned_to_id 
            FROM candidates c 
            LEFT JOIN assignments a ON c.id = a.candidate_id 
            LEFT JOIN users u ON a.client_id = u.id 
            WHERE 1=1
            GROUP BY c.id
        """
    
    if search:
        query += " AND (c.name LIKE ? OR c.skills LIKE ? OR c.role_type LIKE ? OR c.professional_title LIKE ?)"
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%'])
    
    if experience and experience != 'All':
        val = int(experience.replace('+', '').replace(' Years', ''))
        query += " AND c.experience_years >= ?"
        params.append(val)

    if availability and availability != 'All':
        query += " AND c.availability LIKE ?"
        params.append(f'%{availability}%')
        
    query += " ORDER BY c.sort_order ASC, c.name ASC"
        
    conn = get_db_connection()
    candidate_list = conn.execute(query, params).fetchall()
    conn.close()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify([dict(row) for row in candidate_list])
    
    return render_template('candidates.html', candidates=candidate_list, user=user)

@app.route('/add-candidate')
@require_role('admin', 'cs')
def add_candidate_page():
    user = get_current_user()
    return render_template('add_candidate.html', user=user)

@app.route('/api/candidates/create', methods=['POST'])
@require_role('admin', 'cs')
def create_candidate():
    user = get_current_user()
    
    name = bleach.clean(request.form.get('name', ''))
    email = bleach.clean(request.form.get('email', ''))
    phone = bleach.clean(request.form.get('phone', ''))
    location = bleach.clean(request.form.get('location', ''))
    professional_title = bleach.clean(request.form.get('professional_title', ''))
    
    try:
        experience_years = int(request.form.get('experience_years', 0))
    except (ValueError, TypeError):
        experience_years = 0
        
    availability = bleach.clean(request.form.get('availability', ''))
    bio = bleach.clean(request.form.get('bio', ''))
    skills = bleach.clean(request.form.get('skills', ''))
    hobbies = bleach.clean(request.form.get('hobbies', ''))
    
    if not name or not email:
        return {"error": "Name and email required"}, 400

    from werkzeug.utils import secure_filename
    import os
    
    avatar_url = ''
    resume_url = ''
    video_url = ''
    
    def save_file(file_key, folder):
        if file_key in request.files:
            file = request.files[file_key]
            if file and file.filename:
                if not allowed_file(file.filename, folder):
                    return None
                
                # Ensure directory exists before saving
                os.makedirs(os.path.join(app.static_folder, 'uploads', folder), exist_ok=True)
                
                # Use name to make filename somewhat unique but safe
                clean_name = secure_filename(name.replace(' ', '_'))
                filename = secure_filename(f"{clean_name}_{file.filename}")
                path = os.path.join(UPLOAD_BASE, folder, filename)
                file.save(path)
                return f"/static/uploads/{folder}/{filename}"
        return ''

    avatar_url = save_file('avatar', 'avatars')
    resume_url = save_file('resume', 'resumes')
    video_url = save_file('video', 'videos')
    
    if avatar_url is None or resume_url is None or video_url is None:
        return {"error": "Invalid file type uploaded. Allowed: Images, PDFs, and common video formats."}, 400

    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            INSERT INTO candidates (name, email, phone, location, professional_title, experience_years, availability, bio, skills, hobbies, avatar_url, resume_url, video_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (name, email, phone, location, professional_title, experience_years, availability, bio, skills, hobbies, avatar_url, resume_url, video_url))
        conn.commit()
        conn.close()
        log_action('CREATE_CANDIDATE', cursor.lastrowid)
        return redirect(url_for('candidates'))
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/users')
@require_role('admin')
def user_management():
    user = get_current_user()
    
    conn = get_db_connection()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    
    return render_template('users.html', user=user, all_users=users)

@app.route('/api/users/create', methods=['POST'])
@require_role('admin')
def create_user():
    username = bleach.clean(request.form.get('username', '')).strip()
    email = bleach.clean(request.form.get('email', '')).strip()
    role = bleach.clean(request.form.get('role', 'client'))
    
    if not username or not email:
        return jsonify({"success": False, "message": "Username and Email are required"}), 400
        
    # Basic email validation
    import re
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return jsonify({"success": False, "message": "Invalid email format"}), 400

    password = generate_password_hash('demo123') 
    
    avatar_url = None
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and file.filename:
            if not allowed_file(file.filename, 'avatars'):
                return jsonify({"success": False, "message": "Invalid avatar file type"}), 400
            
            from werkzeug.utils import secure_filename
            filename = secure_filename(f"{username}_{file.filename}")
            upload_path = os.path.join(app.static_folder, 'uploads', 'avatars', filename)
            file.save(upload_path)
            avatar_url = f"/static/uploads/avatars/{filename}"
    
    conn = get_db_connection()
    try:
        existing = conn.execute(
            "SELECT username, email FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)", 
            (username, email)
        ).fetchone()
        
        if existing:
            if existing['username'].lower() == username.lower():
                return jsonify({"success": False, "message": "Username already exists"}), 400
            return jsonify({"success": False, "message": "Email already in use"}), 400

        conn.execute("INSERT INTO users (username, password, role, avatar_url, email) VALUES (?, ?, ?, ?, ?)",
                    (username, password, role, avatar_url, email))
        conn.commit()
        log_action('CREATE_USER', username)
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', ''):
            return jsonify({"success": True, "message": "User created successfully"})
        return redirect(url_for('user_management'))
    except Exception as e:
        logger.error(f"User creation error: {e}")
        return jsonify({"success": False, "message": "Internal server error"}), 500
    finally:
        conn.close()

@app.route('/api/users/<int:id>')
@require_role('admin')
def get_user(id):
    conn = get_db_connection()
    user = conn.execute("SELECT id, username, email, role, avatar_url FROM users WHERE id = ?", (id,)).fetchone()
    conn.close()
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    return jsonify(dict(user))

@app.route('/api/users/update/<int:id>', methods=['POST'])
@require_role('admin')
def update_user_api(id):
    data = request.json or request.form
    username = bleach.clean(data.get('username', '')).strip()
    email = bleach.clean(data.get('email', '')).strip()
    role = bleach.clean(data.get('role', 'client'))
    
    if not username or not email:
        return jsonify({"success": False, "message": "Username and Email are required"}), 400
        
    conn = get_db_connection()
    try:
        # Check duplicates
        existing = conn.execute(
            "SELECT id FROM users WHERE (LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)) AND id != ?", 
            (username, email, id)
        ).fetchone()
        
        if existing:
            return jsonify({"success": False, "message": "Username or Email already in use"}), 400

        conn.execute(
            "UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?",
            (username, email, role, id)
        )
        conn.commit()
        log_action('UPDATE_USER', id)
        return jsonify({"success": True, "message": "User updated successfully"})
    except Exception as e:
        logger.error(f"User update error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/users/delete/<int:id>', methods=['POST', 'DELETE'])
@require_role('admin')
def delete_user(id):
    current_user = get_current_user()
    if current_user['id'] == id:
        return jsonify({"success": False, "message": "You cannot delete your own account"}), 400
        
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM users WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        log_action('DELETE_USER', id)
        
        if request.method == 'DELETE' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": True, "message": "User deleted successfully"})
        return redirect(url_for('user_management'))
    except Exception as e:
        logger.error(f"User deletion error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/notifications')
@require_role('admin', 'cs', 'client')
def get_notifications():
    user = get_current_user()
        
    conn = get_db_connection()
    # Get last 10 notifications for the user
    notifications = conn.execute("""
        SELECT *, 
               strftime('%Y-%m-%dT%H:%M:%SZ', created_at) as timestamp_iso
        FROM notifications 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 10
    """, (user['id'],)).fetchall()
    conn.close()
    
    from datetime import datetime, timezone
    
    def format_time_ago(dt):
        now = datetime.now(timezone.utc)
        # Handle case where created_at might not have TZ info if it's from current_timestamp
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
            
        diff = now - dt
        
        seconds = diff.total_seconds()
        if seconds < 0: seconds = 0 # Handle slight clock drifts
        
        if seconds < 60:
            return "Just now"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        elif seconds < 86400:
            hours = int(seconds / 3600)
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        elif seconds < 604800:
            days = int(seconds / 86400)
            return f"{days} day{'s' if days > 1 else ''} ago"
        else:
            return dt.strftime('%b %d, %Y')

    result = []
    for n in notifications:
        d = dict(n)
        # Parse SQL timestamp (e.g. 2026-02-24 16:19:17)
        try:
            dt = datetime.strptime(n['created_at'], '%Y-%m-%d %H:%M:%S')
            d['time_ago'] = format_time_ago(dt)
        except:
            d['time_ago'] = 'Recently'
        result.append(d)
        
    return {"notifications": result}

@app.route('/api/notifications/mark-all-read', methods=['POST'])
@require_role('admin', 'cs', 'client')
def mark_notifications_read():
    user = get_current_user()
    
    conn = get_db_connection()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (user['id'],))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.route('/api/notifications/delete/<int:id>', methods=['DELETE', 'POST'])
@require_role('admin', 'cs', 'client')
def delete_notification(id):
    user = get_current_user()
    
    conn = get_db_connection()
    conn.execute("DELETE FROM notifications WHERE id = ? AND user_id = ?", (id, user['id']))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.route('/api/notifications/mark-read/<int:id>', methods=['POST'])
@require_role('admin', 'cs', 'client')
def mark_notification_read(id):
    user = get_current_user()
    
    conn = get_db_connection()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?", (id, user['id']))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.route('/assign')
@require_role('admin', 'cs')
def assign_candidates():
    user = get_current_user()
    
    conn = get_db_connection()
    clients = conn.execute("SELECT * FROM users WHERE role = 'client' ORDER BY username ASC").fetchall()
    
    # Query to get candidates along with their current assigned client (if any)
    candidates_query = '''
        SELECT c.*, 
               GROUP_CONCAT(u.username, ', ') as assigned_to_name,
               GROUP_CONCAT(u.id, ',') as assigned_to_id
        FROM candidates c
        LEFT JOIN assignments a ON c.id = a.candidate_id
        LEFT JOIN users u ON a.client_id = u.id
        WHERE c.availability != 'Hired'
        GROUP BY c.id
        ORDER BY c.name ASC
    '''
    candidates = conn.execute(candidates_query).fetchall()
    conn.close()
    
    return render_template('assign.html', user=user, clients=clients, candidates=candidates)

@app.route('/api/assignments/<int:client_id>')
@require_role('admin', 'cs')
def get_assignments(client_id):
    user = get_current_user()
        
    conn = get_db_connection()
    assigned = conn.execute('''
        SELECT c.* FROM candidates c
        JOIN assignments a ON c.id = a.candidate_id
        WHERE a.client_id = ?
        ORDER BY a.sort_order ASC
    ''', (client_id,)).fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in assigned])

@app.route('/api/assignments/summary')
@require_role('admin', 'cs')
def get_assignments_summary():
    user = get_current_user()
    
    conn = get_db_connection()
    # Get all clients
    clients = conn.execute("SELECT id, username, email FROM users WHERE role = 'client'").fetchall()
    # Get all assignments
    assignments = conn.execute('''
        SELECT a.client_id, c.* 
        FROM assignments a
        JOIN candidates c ON a.candidate_id = c.id
        ORDER BY a.sort_order ASC
    ''').fetchall()
    conn.close()
    
    # Map assignments to clients
    summary = []
    for client in clients:
        client_data = dict(client)
        client_data['candidates'] = [dict(a) for a in assignments if a['client_id'] == client['id']]
        summary.append(client_data)
        
    return jsonify(summary)

@app.route('/api/assignments/save', methods=['POST'])
@require_role('admin', 'cs')
def save_assignments():
    user = get_current_user()
        
    data = request.json
    client_id = data.get('client_id')
    candidate_ids = data.get('candidate_ids', [])
    
    if not client_id:
        return jsonify({'error': 'Client ID required'}), 400
        
    try:
        conn = get_db_connection()
        
        # Ensure candidate_ids are integers for reliable comparison
        candidate_ids = [int(cid) for cid in candidate_ids if cid]
        
        # 1. Get existing candidate IDs to find what's "new"
        existing_ids_rows = conn.execute("SELECT candidate_id FROM assignments WHERE client_id = ?", (client_id,)).fetchall()
        existing_ids = {int(row['candidate_id']) for row in existing_ids_rows}
        
        # 2. Identify newly assigned IDs (only those not already in the list)
        new_ids = [cid for cid in candidate_ids if cid not in existing_ids]
        
        candidate_names = []
        if new_ids:
            placeholders = ', '.join(['?'] * len(new_ids))
            cands = conn.execute(f"SELECT name FROM candidates WHERE id IN ({placeholders})", new_ids).fetchall()
            candidate_names = [c['name'] for c in cands]

        # Clear existing assignments for this specific client
        conn.execute("DELETE FROM assignments WHERE client_id = ?", (client_id,))
        
        # Add new assignments
        for index, cand_id in enumerate(candidate_ids):
            # Insert the new assignment
            conn.execute("INSERT INTO assignments (client_id, candidate_id, sort_order) VALUES (?, ?, ?)", 
                         (client_id, cand_id, index))
        conn.commit()
        conn.close()
        
        # Create a targeted notification for EACH truly new candidate individually
        for name in candidate_names:
            msg = f"Admin has assigned a new candidate to your portal: {name}"
            create_notification(client_id, "New Candidate Assigned", msg, "info")
            
        log_action('UPDATE_ASSIGNMENTS', client_id)
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Save assignments error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/meetings/request', methods=['POST'])
@require_role('client')
def request_meeting_api():
    user = get_current_user()
    data = request.json
    candidate_id = data.get('candidate_id')
    
    if not candidate_id:
        return jsonify({'error': 'Candidate ID is required'}), 400
        
    try:
        user = dict(user) # Convert Row to dict for safer access
        conn = get_db_connection()
        candidate = conn.execute("SELECT name FROM candidates WHERE id = ?", (candidate_id,)).fetchone()
        conn.close()
        
        if not candidate:
            return jsonify({'error': 'Candidate not found'}), 404
            
        candidate_name = candidate['name']
        client_name = user['username']
        client_email = user.get('email', 'N/A')
        
        raw_receivers = os.getenv('NOTIFICATION_RECEIVER_EMAIL', 'anjan@karmastaff.com,pema@karmastaff.com,sales@karmastaff.com,service@karmastaff.com,noida@karmastaff.com')
        receiver_emails = [email.strip() for email in raw_receivers.split(',') if email.strip()]
        logger.info(f"Attempting to send email via Resend to {receiver_emails}...")
        
        # 1. Record the meeting request in the database and portal notifications FIRST
        # This ensures the "Team" always receives the request even if email fails
        log_action('REQUEST_MEETING', candidate_id)
        create_notification(1, "New Meeting Request", f"Client {client_name} requested a meeting with {candidate_name}")
        
        # 2. Attempt to send the email notification as a secondary action
        # We re-verify the API key here to ensure it's picked up from the latest .env
        resend.api_key = os.getenv('RESEND_API_KEY')
        from_email = os.getenv('RESEND_FROM_EMAIL', 'onboarding@karmastaff.com')
        
        for email_to in receiver_emails:
            try:
                params = {
                    "from": from_email,
                    "to": [email_to],
                    "subject": "Urgent !!! Candidate available",
                    "html": f"""
                        <div style='font-family: sans-serif; padding: 20px; color: #333;'>
                            <h2 style='color: #22c55e;'><b style='color: red;'>Urgent</b> !!! Candidate available</h2>
                            <hr style='border: 1px solid #eee;' />
                            <p><strong>New Meeting Request</strong></p>
                            <p><strong>Client:</strong> {client_name} ({client_email})</p>
                            <p><strong>Candidate:</strong> {candidate_name}</p>
                            <p>The client has requested to book an appointment with this candidate via the Karma Staff Portal.</p>
                            <hr style='border: 1px solid #eee;' />
                            <p style='font-size: 10px; color: #999;'>Karma Staff Talent Intelligence</p>
                        </div>
                    """,
                }
                logger.info(f"Attempting email delivery to {email_to} via {from_email}")
                response = resend.Emails.send(params)
                logger.info(f"Resend response for {email_to}: {response}")
                time.sleep(1) # Add delay to avoid hitting rate limits
            except Exception as email_err:
                logger.error(f"Email delivery failed for {email_to}: {email_err}")
        
        return jsonify({'status': 'success', 'message': 'Requested Meeting has been Sent to the Team'})
        
    except Exception as e:
        logger.error(f"Meeting request error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/candidate/<int:id>')
@require_role('admin', 'cs', 'client')
def candidate_profile(id):
    user = get_current_user()
    
    conn = get_db_connection()
    candidate = conn.execute("SELECT * FROM candidates WHERE id = ?", (id,)).fetchone()
    conn.close()
    
    if not candidate:
        abort(404)
        
    is_client = user['role'] == 'client'
    log_action(f'VIEW_CANDIDATE_PROFILE', id)
    return render_template('candidate_profile.html', candidate=candidate, user=user, is_client=is_client)

@app.errorhandler(403)
def forbidden(e):
    user = get_current_user()
    return render_template('errors/403.html', user=user), 403

@app.errorhandler(404)
def not_found(e):
    user = get_current_user()
    return render_template('errors/404.html', user=user), 404

@app.errorhandler(500)
def handle_exception(e):
    logger.error(f"Unhandled server error: {e}")
    user = get_current_user()
    return render_template('errors/500.html', user=user), 500

@app.route('/ai-agent')
def ai_agent():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    return render_template('ai_agent.html', user=user)

@app.route('/api/profile/update', methods=['POST'])
@require_role('admin', 'cs', 'client')
def update_profile():
    user = get_current_user()
    
    # Handle both JSON and Form data
    if request.is_json:
        data = request.json
    else:
        data = request.form
    
    full_name = bleach.clean(data.get('full_name', '')).strip()
    email = bleach.clean(data.get('email', '')).strip()
    department = bleach.clean(data.get('department', '')).strip()
    job_title = bleach.clean(data.get('job_title', '')).strip()
    
    if not full_name or not email:
        return jsonify({'success': False, 'message': 'Full Name and Email are required'}), 400
        
    # Diagnostic log
    logger.info(f"Attempting profile update for User ID {user['id']}: name='{full_name}', email='{email}'")
    
    conn = None
    try:
        conn = get_db_connection()
        
        # 1. Check for Duplicate Username
        existing_user = conn.execute(
            "SELECT id, username FROM users WHERE LOWER(username) = LOWER(?) AND id != ?", 
            (full_name, user['id'])
        ).fetchone()
        
        if existing_user:
            logger.warning(f"Update failed: Name '{full_name}' already taken by User ID {existing_user['id']}")
            conn.close()
            return jsonify({
                'success': False, 
                'message': f'The name "{full_name}" is already being used by another account. Please try a different name.'
            }), 400

        # 2. Check for Duplicate Email
        existing_email = conn.execute(
            "SELECT id, email FROM users WHERE LOWER(email) = LOWER(?) AND id != ?", 
            (email, user['id'])
        ).fetchone()
        
        if existing_email:
            logger.warning(f"Update failed: Email '{email}' already taken by User ID {existing_email['id']}")
            conn.close()
            return jsonify({
                'success': False, 
                'message': 'This email address is already registered to another account.'
            }), 400
            
        # 3. Handle Avatar Upload
        avatar_url = user['avatar_url']
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and file.filename:
                if not allowed_file(file.filename, 'avatars'):
                    return jsonify({"success": False, "message": "Invalid avatar file type"}), 400
                
                from werkzeug.utils import secure_filename
                filename = secure_filename(f"user_{user['id']}_{file.filename}")
                upload_path = os.path.join(UPLOAD_BASE, 'avatars', filename)
                file.save(upload_path)
                avatar_url = f"/static/uploads/avatars/{filename}"

        # 4. Perform Update
        conn.execute("""
            UPDATE users 
            SET username = ?, email = ?, department = ?, job_title = ?, avatar_url = ?
            WHERE id = ?
        """, (full_name, email, department, job_title, avatar_url, user['id']))
        conn.commit()
        logger.info(f"Profile updated successfully for User ID {user['id']}")
        
        log_action('UPDATE_PROFILE', user['id'])
        return jsonify({'success': True, 'message': 'Profile updated successfully'})
        
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e):
            logger.error(f"Database lock detected during profile update: {e}")
            return jsonify({'success': False, 'message': 'System is busy (database locked). Please wait a moment and try again.'}), 503
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500
    except Exception as e:
        logger.error(f"Unexpected profile update error (User {user['id']}): {e}")
        return jsonify({'success': False, 'message': f'Update failed: {str(e)}'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/profile')
@require_role('admin', 'cs', 'client')
def profile():
    user = get_current_user()
    
    # Mock activity and settings
    activities = [
        {'title': 'Logged into the system', 'time': 'Today, 10:30 AM', 'type': 'login'},
        {'title': 'Started working session', 'time': 'Today, 10:32 AM', 'subtitle': 'Working: 10:32 AM - 12:45 PM (2h 13m)', 'type': 'work'},
        {'title': 'Took a break', 'time': 'Today, 12:45 PM', 'subtitle': 'Away: 12:45 PM - 1:15 PM (30m)', 'type': 'break', 'active': True},
        {'title': 'Updated profile settings', 'time': 'Yesterday, 4:20 PM', 'type': 'update'}
    ]
    
    return render_template('profile.html', user=user, activities=activities)

@app.route('/api/chat', methods=['POST'])
@require_role('admin', 'cs', 'client')
def chat():
    user = get_current_user()
    
    data = request.json
    message = data.get('message', '')
    
    if not message:
        return jsonify({'error': 'Empty message'}), 400
    
    # Fetch candidates relevant to this user
    conn = get_db_connection()
    if user['role'] == 'client':
        # ONLY assigned candidates for clients
        candidates_rows = conn.execute("""
            SELECT c.* FROM candidates c
            JOIN assignments a ON c.id = a.candidate_id
            WHERE a.client_id = ?
            ORDER BY a.sort_order ASC
        """, (user['id'],)).fetchall()
    else:
        # ALL candidates for admin/cs
        candidates_rows = conn.execute("SELECT * FROM candidates ORDER BY name ASC").fetchall()
    conn.close()

    # Format candidates for the prompt with resume details
    candidates_list = []
    for i, c in enumerate(candidates_rows):
        resume_text = ""
        if c['resume_url']:
            # Construct absolute path using app.static_folder
            # Assumes resume_url is like '/static/uploads/resumes/filename.pdf'
            filename = os.path.basename(c['resume_url'])
            abs_path = os.path.join(UPLOAD_BASE, 'resumes', filename)
            resume_text = extract_text_from_pdf(abs_path)
            # Limit resume text to first 2000 chars to avoid blowing context
            if resume_text:
                resume_text = f" [RESUME CONTENT START: {resume_text[:2000]} ... END]"

        candidates_list.append(f"{i+1}. {c['name']}: {c['professional_title']}. {c['experience_years']}yr exp. Skills: {c['skills']}. Location: {c['location']}. Status: {c['availability']}.{resume_text}")
    
    candidates_context = "\n".join(candidates_list) if candidates_list else "No candidates currently assigned to you."
    
    full_system_instruction = f"{BASE_SYSTEM_INSTRUCTION}\n\nCandidates currently in your database:\n{candidates_context}"

    try:
        # Create a fresh model instance with specific context for this request
        dynamic_model = genai.GenerativeModel(
            model_name="gemini-2.0-flash",
            system_instruction=full_system_instruction
        )
        response = dynamic_model.generate_content(message)
        log_action('AI_AGENT_CHAT', 0)
        return jsonify({'response': response.text})
    except Exception as e:
        logger.error(f"Gemini Error: {e}")
        return jsonify({'response': '⚠️ AI service temporarily unavailable. Please try again later.'})

@app.route('/edit-candidate/<int:id>')
@require_role('admin', 'cs')
def edit_candidate_page(id):
    user = get_current_user()
    
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM candidates WHERE id = ?", (id,)).fetchone()
    conn.close()
    
    if not row:
        abort(404)
        
    candidate = dict(row)
    return render_template('edit_candidate.html', user=user, candidate=candidate)

@app.route('/api/candidates/update/<int:id>', methods=['POST'])
@require_role('admin', 'cs')
def update_candidate(id):
    user = get_current_user()
    
    name = bleach.clean(request.form.get('name', ''))
    email = bleach.clean(request.form.get('email', ''))
    phone = bleach.clean(request.form.get('phone', ''))
    location = bleach.clean(request.form.get('location', ''))
    professional_title = bleach.clean(request.form.get('professional_title', ''))
    
    try:
        experience_years = int(request.form.get('experience_years', 0))
    except (ValueError, TypeError):
        experience_years = 0
        
    availability = bleach.clean(request.form.get('availability', ''))
    bio = bleach.clean(request.form.get('bio', ''))
    skills = bleach.clean(request.form.get('skills', ''))
    hobbies = bleach.clean(request.form.get('hobbies', ''))
    
    if not name or not email:
        return {"error": "Name and email required"}, 400

    from werkzeug.utils import secure_filename
    import os
    
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM candidates WHERE id = ?", (id,)).fetchone()
    candidate = dict(row)
    
    avatar_url = candidate['avatar_url']
    resume_url = candidate['resume_url']
    video_url = candidate['video_url']
    
    def update_file(file_key, folder, current_url):
        if file_key in request.files:
            file = request.files[file_key]
            if file and file.filename:
                # Ensure directory exists before saving
                os.makedirs(os.path.join(app.static_folder, 'uploads', folder), exist_ok=True)
                
                clean_name = secure_filename(name.replace(' ', '_'))
                filename = secure_filename(f"{clean_name}_{file.filename}")
                path = os.path.join(UPLOAD_BASE, folder, filename)
                file.save(path)
                return f"/static/uploads/{folder}/{filename}"
        return current_url

    avatar_url = update_file('avatar', 'avatars', avatar_url)
    resume_url = update_file('resume', 'resumes', resume_url)
    video_url = update_file('video', 'videos', video_url)

    try:
        conn.execute('''
            UPDATE candidates SET 
                name=?, email=?, phone=?, location=?, professional_title=?, 
                experience_years=?, availability=?, bio=?, skills=?, hobbies=?, 
                avatar_url=?, resume_url=?, video_url=?
            WHERE id=?
        ''', (name, email, phone, location, professional_title, experience_years, availability, bio, skills, hobbies, avatar_url, resume_url, video_url, id))
        conn.commit()
        conn.close()
        log_action('UPDATE_CANDIDATE', id)
        return redirect(url_for('candidate_profile', id=id))
    except Exception as e:
        logger.error(f"Candidate update error: {e}")
        conn.close()
        return {"error": "An internal error occurred while updating the candidate"}, 500

@app.route('/api/candidates/delete/<int:id>', methods=['POST'])
@require_role('admin', 'cs')
def delete_candidate(id):
    user = get_current_user()
        
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT * FROM candidates WHERE id = ?", (id,)).fetchone()
        candidate = dict(row)
        
        # Delete files if they exist
        import os
        for field in ['avatar_url', 'resume_url', 'video_url']:
            if candidate[field]:
                # Extract filename and construct path within app.static_folder
                folder = field.split('_')[0] + 's' # avatars, resumes, videos
                filename = os.path.basename(candidate[field])
                path = os.path.join(UPLOAD_BASE, folder, filename)
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except:
                        pass
        
        conn.execute("DELETE FROM candidates WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        log_action('DELETE_CANDIDATE', id)
        return redirect(url_for('candidates'))
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/api/candidates/hire/<int:id>', methods=['POST'])
@require_role('admin', 'cs')
def hire_candidate(id):
    user = get_current_user()
        
    try:
        conn = get_db_connection()
        conn.execute("UPDATE candidates SET availability='Hired' WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        log_action('HIRE_CANDIDATE', id)
        return redirect(url_for('candidate_profile', id=id))
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/api/candidates/reorder', methods=['POST'])
@require_role('admin', 'cs')
def reorder_candidates():
    user = get_current_user()
    
    data = request.json
    order = data.get('order', []) # List of candidate IDs in new order
    
    if not order:
        return jsonify({'error': 'No order provided'}), 400
        
    try:
        conn = get_db_connection()
        # Update each candidate's sort_order based on its index in the provided list
        for index, cand_id in enumerate(order):
            conn.execute("UPDATE candidates SET sort_order = ? WHERE id = ?", (index, cand_id))
        conn.commit()
        conn.close()
        log_action('REORDER_CANDIDATES', 0)
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.exception("A 500 internal server error occurred:")
    return render_template('errors/500.html'), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    if not debug_mode:
        # Prevent absolute paths in logs during production
        logger.info("Running in PRODUCTION mode")
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
