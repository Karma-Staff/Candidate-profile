from database import get_db_connection

def create_notifications_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create notifications table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT DEFAULT 'info',
        is_read BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Optional: Seed a few notifications for testing (e.g., for 'anjan')
    # Find anjan ID
    cursor.execute("SELECT id FROM users WHERE username = 'anjan' OR email = 'anjan@karmastaff.com'")
    anjan = cursor.fetchone()
    if anjan:
        anjan_id = anjan['id']
        test_notifications = [
            (anjan_id, 'New meeting scheduled', 'A meeting with Gagan Rana has been scheduled on 2/20/2026 at 10:00 AM.', 'meeting'),
            (anjan_id, 'Candidate Updated', 'Manya Arora has updated their profile with new skill tags.', 'info')
        ]
        cursor.executemany("INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)", test_notifications)
        print(f"Added test notifications for user ID: {anjan_id}")
        
    conn.commit()
    conn.close()
    print("Notifications table created and seeded.")

if __name__ == "__main__":
    create_notifications_table()
