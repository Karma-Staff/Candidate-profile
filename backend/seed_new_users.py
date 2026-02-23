from database import get_db_connection

def add_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    users = [
        ('Sarah Johnson', 'demo123', 'cs'),
        ('PHIL', 'demo123', 'client'),
        ('jimmy', 'demo123', 'client'),
        ('jyoticlient', 'demo123', 'client')
    ]
    
    for username, password, role in users:
        try:
            cursor.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
            print(f"Added/Verified user: {username}")
        except Exception as e:
            print(f"Error adding {username}: {e}")
            
    conn.commit()
    conn.close()

if __name__ == "__main__":
    add_users()
