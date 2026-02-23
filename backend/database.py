import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_PATH = os.getenv("DATABASE_PATH", "platform.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def add_column_safely(cursor, table, column, type_def):
    """Safely adds a column to a table if it doesn't already exist."""
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {type_def}")
        print(f"Added column {column} to {table}")
    except sqlite3.OperationalError:
        # Column likely already exists
        pass

def init_db():
    global DB_PATH
    # Ensure we can write to the directory of DB_PATH
    parent_dir = os.path.dirname(DB_PATH)
    if parent_dir and parent_dir != "/":
        try:
            os.makedirs(parent_dir, exist_ok=True)
        except PermissionError:
            print(f"Warning: Cannot write to {parent_dir}. Falling back to local directory.")
            DB_PATH = os.path.basename(DB_PATH) # Fallback to current dir

    # If using a persistent disk path and the DB doesn't exist, check for seed
    if not os.path.exists(DB_PATH):
        seed_path = os.path.join(os.path.dirname(__file__), "seed_production.db")
        if os.path.exists(seed_path):
            import shutil
            try:
                print(f"Initializing database from seed: {seed_path} -> {DB_PATH}")
                shutil.copy(seed_path, DB_PATH)
            except Exception as e:
                print(f"Error seeding database: {e}. Starting fresh.")
        else:
            print(f"No database found at {DB_PATH} and no seed found at {seed_path}. Creating new.")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Create Users Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        avatar_url TEXT,
        has_seen_welcome INTEGER DEFAULT 0
    )
    ''')
    
    # Ensure missing columns exist (for safe migrations)
    add_column_safely(cursor, "users", "email", "TEXT UNIQUE")
    add_column_safely(cursor, "users", "avatar_url", "TEXT")
    add_column_safely(cursor, "users", "has_seen_welcome", "INTEGER DEFAULT 0")

    # Seed Users only if empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        print("Seeding initial users...")
        users = [
            ('admin', 'admin@restoration.com', generate_password_hash('demo123'), 'admin'),
            ('sarah', 'cs@restoration.com', generate_password_hash('demo123'), 'cs'),
            ('phil', 'phil@client.com', generate_password_hash('demo123'), 'client'),
            ('jimmy', 'jimmy@client.com', generate_password_hash('demo123'), 'client'),
            ('jyoti', 'jyoti@client.com', generate_password_hash('demo123'), 'client'),
            ('client1', 'client1@gmail.com', generate_password_hash('demo123'), 'client'),
            ('anjan', 'anjan@karmastaff.com', generate_password_hash('demo123'), 'client'),
            ('anjan theeng', 'anjan@client.com', generate_password_hash('demo123'), 'client')
        ]
        cursor.executemany("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)", users)

    # Create Candidates Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS candidates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT,
        location TEXT,
        professional_title TEXT,
        role_type TEXT,
        experience_years INTEGER DEFAULT 0,
        skills TEXT,
        hobbies TEXT,
        bio TEXT,
        availability TEXT DEFAULT 'Immediate Hire',
        personality_grade REAL DEFAULT 0.0,
        accent_grade REAL DEFAULT 0.0,
        technical_grade REAL DEFAULT 0.0,
        video_url TEXT,
        avatar_url TEXT,
        resume_url TEXT,
        status TEXT DEFAULT 'Active',
        sort_order INTEGER DEFAULT 0
    )
    ''')

    # Ensure missing columns exist
    add_column_safely(cursor, "candidates", "resume_url", "TEXT")
    add_column_safely(cursor, "candidates", "avatar_url", "TEXT")
    add_column_safely(cursor, "candidates", "video_url", "TEXT")
    add_column_safely(cursor, "candidates", "sort_order", "INTEGER DEFAULT 0")

    # Initialize sort_order for existing candidates if it's 0
    cursor.execute("UPDATE candidates SET sort_order = id WHERE sort_order = 0")

    # Seed Candidates only if empty
    cursor.execute("SELECT COUNT(*) FROM candidates")
    if cursor.fetchone()[0] == 0:
        print("Seeding initial candidates...")
        candidates = [
            ('Anjan Theeng', 'anjan.lamatamang@gmail.com', '555-0101', 'Noida, India', 'Restoration Expert', 'AI', 1, 'Customer relationship, Marketing, Revenue Management', 'Music, Tech', 'A passionate restoration professional.', 'Immediate Hire', 4.5, 4.8, 4.9, '', '/static/uploads/avatars/anjan.jpg', '/static/uploads/resumes/sample_resume.pdf', 'Active'),
            ('Anudeep Nautiyal', 'service@karmastaff.com', '555-0102', 'Dehradun, India', 'Restoration Office Admin', 'Restoration Office Admin', 3, 'Customer relationship, Marketing, Revenue Management', 'Sports', 'Experienced in office administration.', 'Immediate Hire', 4.9, 5.0, 4.7, '', '', '/static/uploads/resumes/sample_resume.pdf', 'Active'),
            ('Gagan Rana', 'service@karmastaff.com', '555-0103', 'Noida, India', 'Office Admin', 'Office Admin', 10, 'Customer relationship, Marketing, Revenue Management', 'Travel', 'Veteran in office management.', 'Immediate Hire', 4.2, 4.0, 4.5, '', '', '/static/uploads/resumes/sample_resume.pdf', 'Active'),
            ('Manya Arora', 'manya@example.com', '555-0104', 'Delhi, India', 'Admin Specialist', 'Admin', 3, 'Admin, Support', 'Art', 'Dedicated admin specialist.', 'Next Month', 4.0, 4.0, 4.0, '', '', '/static/uploads/resumes/sample_resume.pdf', 'Active'),
            ('Aman Vijetra', 'aman@example.com', '555-0105', 'Noida, India', 'Junior Admin', 'Admin', 0, 'Admin, Data Entry', 'Gaming', 'Aspiring admin professional.', 'Immediate', 3.5, 3.5, 3.5, '', '', '/static/uploads/resumes/sample_resume.pdf', 'Active')
        ]
        cursor.executemany('''
            INSERT INTO candidates (name, email, phone, location, professional_title, role_type, experience_years, skills, hobbies, bio, availability, personality_grade, accent_grade, technical_grade, video_url, avatar_url, resume_url, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', candidates)

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER,
        candidate_id INTEGER,
        sort_order INTEGER DEFAULT 0,
        FOREIGN KEY (client_id) REFERENCES users (id),
        FOREIGN KEY (candidate_id) REFERENCES candidates (id)
    )
    ''')

    # Ensure missing columns exist
    add_column_safely(cursor, "assignments", "sort_order", "INTEGER DEFAULT 0")

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        resource_id INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        message TEXT,
        type TEXT DEFAULT 'info',
        is_read INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    conn.commit()
    conn.close()
    print("Database check complete.")

if __name__ == "__main__":
    init_db()
