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

# Initialize Security Headers
# content_security_policy allows Google Fonts and Gemini API interactions
csp = {
    'default-src': '\'self\'',
    'script-src': [
        '\'self\'',
        'https://unpkg.com', # Lucide icons
        'https://cdn.jsdelivr.net',
        '\'unsafe-inline\'' # Required for some dynamic UI updates, but restricted
    ],
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

force_https = os.getenv('FLASK_DEBUG', 'True').lower() == 'false' and os.getenv('TESTING') != 'True'
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

@app.route('/')
def index():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    return redirect(url_for('candidates')) # Default to candidates as per screenshot header

@app.route('/admin-dashboard')
@require_role('admin', 'cs')
def admin_dashboard():
    user = get_current_user()
    
    conn = get_db_connection()
    logs = conn.execute('''
        SELECT al.*, u.username, c.name as candidate_name 
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        LEFT JOIN candidates c ON al.resource_id = c.id
        ORDER BY al.timestamp DESC
        LIMIT 10
    ''').fetchall()
    total_logs = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    conn.close()
    
    return render_template('dashboard.html', user=user, logs=logs, total_logs=total_logs)

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
                return redirect(url_for('admin_dashboard'))
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
        query = "SELECT c.* FROM candidates c JOIN assignments a ON c.id = a.candidate_id WHERE a.client_id = ?"
        params.append(user['id'])
    else:
        query = "SELECT * FROM candidates WHERE 1=1"
    
    if search:
        query += " AND (name LIKE ? OR skills LIKE ? OR role_type LIKE ? OR professional_title LIKE ?)"
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%'])
    
    if experience and experience != 'All':
        val = int(experience.replace('+', '').replace(' Years', ''))
        query += " AND experience_years >= ?"
        params.append(val)

    if availability and availability != 'All':
        query += " AND availability LIKE ?"
        params.append(f'%{availability}%')
        
    query += " ORDER BY sort_order ASC, name ASC"
        
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
    user = get_current_user()
    
    username = bleach.clean(request.form.get('username', ''))
    email = bleach.clean(request.form.get('email', ''))
    role = bleach.clean(request.form.get('role', 'client'))
    
    # In production, this should be generated or provided securely
    password = generate_password_hash('demo123') 
    
    if not username:
        return {"error": "Username required"}, 400
    if not email:
        return {"error": "Email address required"}, 400
        
    # Basic email validation
    import re
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return {"error": "Invalid email format"}, 400

    avatar_url = None
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and file.filename:
            if not allowed_file(file.filename, 'avatars'):
                return {"error": "Invalid avatar file type. Allowed: png, jpg, jpeg, gif"}, 400
            
            from werkzeug.utils import secure_filename
            import os
            filename = secure_filename(f"{username}_{file.filename}")
            upload_path = os.path.join(app.static_folder, 'uploads', 'avatars', filename)
            file.save(upload_path)
            avatar_url = f"/static/uploads/avatars/{filename}"
    
    conn = get_db_connection()
    try:
        # Check if username or email already exists
        existing = conn.execute(
            "SELECT username, email FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)", 
            (username, email)
        ).fetchone()
        
        if existing:
            if existing['username'].lower() == username.lower():
                return {"error": "Username already exists"}, 400
            if existing['email'] and existing['email'].lower() == email.lower():
                return {"error": "Email already in use"}, 400

        conn.execute("INSERT INTO users (username, password, role, avatar_url, email) VALUES (?, ?, ?, ?, ?)",
                    (username, password, role, avatar_url, email))
        conn.commit()
        log_action('CREATE_USER', username)
        return redirect(url_for('user_management'))
    except Exception as e:
        logger.error(f"User creation database error: {e}")
        return {"error": "An internal error occurred during user creation"}, 500
    finally:
        conn.close()

@app.route('/api/users/delete/<int:id>', methods=['POST'])
@require_role('admin')
def delete_user(id):
    user = get_current_user()
    if user['id'] == id:
        return {"error": "You cannot delete your own account"}, 400
        
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM users WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        log_action('DELETE_USER', id)
        return redirect(url_for('user_management'))
    except Exception as e:
        return {"error": str(e)}, 500

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
    
    # Simple "time ago" logic for demo purposes
    # In a real app we'd use a library or more robust SQL
    result = []
    for n in notifications:
        d = dict(n)
        d['time_ago'] = '6 hours ago' # Hardcoded as per image mock for now
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
    candidates = conn.execute("SELECT * FROM candidates WHERE availability != 'Hired' ORDER BY name ASC").fetchall()
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
        # Clear existing
        conn.execute("DELETE FROM assignments WHERE client_id = ?", (client_id,))
        # Add new
        for index, cand_id in enumerate(candidate_ids):
            conn.execute("INSERT INTO assignments (client_id, candidate_id, sort_order) VALUES (?, ?, ?)", 
                         (client_id, cand_id, index))
        conn.commit()
        conn.close()
        log_action('UPDATE_ASSIGNMENTS', client_id)
        return jsonify({'status': 'success'})
    except Exception as e:
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
