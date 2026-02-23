import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_PATH = "platform.db"
SEED_PATH = "seed_production.db"

def add_users(db_file):
    print(f"Adding users to {db_file}...")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    users = [
        ('Admin', 'admin@restoration.com', 'demo123', 'admin'),
        ('CSTeam', 'cs@restoration.com', 'demo123', 'cs'),
        ('Client1', 'client1@gmail.com', 'demo123', 'client')
    ]
    
    for username, email, password, role in users:
        hashed_pw = generate_password_hash(password)
        # Check if user exists by email
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        existing = cursor.fetchone()
        
        if existing:
            print(f"Updating existing user: {email}")
            cursor.execute("""
                UPDATE users 
                SET password = ?, role = ?, username = ?
                WHERE email = ?
            """, (hashed_pw, role, username, email))
        else:
            print(f"Creating new user: {email}")
            cursor.execute("""
                INSERT INTO users (username, email, password, role)
                VALUES (?, ?, ?, ?)
            """, (username, email, hashed_pw, role))
            
    conn.commit()
    conn.close()
    print("Done!")

if __name__ == "__main__":
    if os.path.exists(DB_PATH):
        add_users(DB_PATH)
    
    # Also update the seed database so it's ready for Render
    if os.path.exists(SEED_PATH):
        add_users(SEED_PATH)
    else:
        # If seed doesn't exist, create it from platform.db
        import shutil
        if os.path.exists(DB_PATH):
            print(f"Creating {SEED_PATH} from {DB_PATH}")
            shutil.copy(DB_PATH, SEED_PATH)
            add_users(SEED_PATH)
