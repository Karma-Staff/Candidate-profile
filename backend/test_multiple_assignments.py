import os
os.environ['TESTING'] = 'True'
from app import app
from database import DB_PATH, init_db, get_db_connection

def run_test():
    with app.test_client() as client:
        # Login as Admin
        client.post('/login', data=dict(username='admin@restoration.com', password='demo123'))
        
        # Get users to find clients
        conn = get_db_connection()
        clients = conn.execute("SELECT id, username FROM users WHERE role = 'client'").fetchall()
        candidates = conn.execute("SELECT id, name FROM candidates").fetchall()
        
        if len(clients) < 2 or len(candidates) < 1:
            print("Not enough clients or candidates to test.")
            return

        client_1_id = clients[0]['id']
        client_2_id = clients[1]['id']
        candidate_id = candidates[0]['id']
        
        print(f"Testing Multiple Assignments")
        print(f"Client 1: {clients[0]['username']} (ID {client_1_id})")
        print(f"Client 2: {clients[1]['username']} (ID {client_2_id})")
        print(f"Candidate: {candidates[0]['name']} (ID {candidate_id})")
        
        # 1. Assign to Client 1
        res1 = client.post('/api/assignments/save', json={
            'client_id': client_1_id,
            'candidate_ids': [candidate_id]
        })
        print(f"Assigned to Client 1: {res1.status_code}")
        
        # 2. Assign to Client 2
        res2 = client.post('/api/assignments/save', json={
            'client_id': client_2_id,
            'candidate_ids': [candidate_id]
        })
        print(f"Assigned to Client 2: {res2.status_code}")
        
        # 3. Verify Assignments
        assignments = conn.execute("SELECT client_id, candidate_id FROM assignments WHERE candidate_id = ?", (candidate_id,)).fetchall()
        print(f"Database assignments for Candidate {candidate_id}: {[dict(a) for a in assignments]}")
        
        if len(assignments) == 2:
            print("SUCCESS: Candidate assigned to multiple clients in DB")
        else:
            print("FAILURE: Multiple assignments not saved")
            
        # 4. Verify /candidates API returns GROUP_CONCAT correctly
        res3 = client.get('/candidates', headers={'X-Requested-With': 'XMLHttpRequest'})
        c_list = res3.json
        c_data = next((c for c in c_list if c['id'] == candidate_id), None)
        if c_data:
            print(f"Assigned To Name from /candidates: {c_data.get('assigned_to_name')}")
            if ',' in c_data.get('assigned_to_name', ''):
                print("SUCCESS: /candidates API returns comma separated names")
            else:
                print("FAILURE: Group concat may not be working in /candidates")
                
        conn.close()

if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        init_db()
    
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-key'
    run_test()
