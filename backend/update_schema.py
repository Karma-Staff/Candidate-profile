from database import get_db_connection

def update_schema_and_data():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Add email column if not exists
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
        print("Email column added to users table.")
    except Exception as e:
        print(f"Email column might already exist: {e}")
        
    # Update data
    updates = [
        ('Sarah Johnson', 'cs@restoration.com', 'cs'),
        ('PHIL', 'pca@puroclean.com', 'client'),
        ('jimmy', 'jimmy@gmail.com', 'client'),
        ('jyoticlient', 'jyoti@restoration.com', 'client')
    ]
    
    for username, email, role in updates:
        cursor.execute("UPDATE users SET email = ?, role = ? WHERE username = ?", (email, role, username))
        print(f"Updated user: {username} with email: {email} and role: {role}")
        
    conn.commit()
    conn.close()

if __name__ == "__main__":
    update_schema_and_data()
