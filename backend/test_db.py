import sqlite3
import pprint
from database import get_db_connection

conn = get_db_connection()
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

cursor.execute("SELECT * FROM audit_logs WHERE action = 'REQUEST_MEETING' ORDER BY timestamp DESC LIMIT 5")
rows = cursor.fetchall()
print("Recent Request Meetings in DB:")
for r in rows:
    print(dict(r))

cursor.execute("SELECT * FROM notifications ORDER BY created_at DESC LIMIT 5")
rows = cursor.fetchall()
print("\nRecent Notifications in DB:")
for r in rows:
    print(dict(r))

conn.close()
