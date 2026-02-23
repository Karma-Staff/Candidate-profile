import unittest
import os
os.environ['TESTING'] = 'True'
from app import app
from database import DB_PATH, init_db
import os
import sqlite3

class PlatformTestCase(unittest.TestCase):
    def setUp(self):
        if not os.path.exists(DB_PATH):
            init_db()
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test-key'
        self.client = app.test_client()

    def test_login_success_new_theme(self):
        """Test login with the new Admin User name."""
        response = self.client.post('/login', data=dict(
            username='admin@restoration.com',
            password='demo123'
        ), follow_redirects=True)
        # Check for candidates page content (default after login)
        self.assertIn(b'Restore Talent Platform', response.data)
        # Check for horizontal header presence
        self.assertIn(b'nav-links', response.data)

    def test_user_management_access(self):
        """Verify Admin can access User Management."""
        self.client.post('/login', data=dict(
            username='admin@restoration.com',
            password='demo123'
        ))
        response = self.client.get('/users')
        self.assertIn(b'User Management', response.data)
        self.assertIn(b'cs@restoration.com', response.data)

    def test_assign_candidates_access(self):
        """Verify Admin/CS can access Assignment page."""
        self.client.post('/login', data=dict(
            username='cs@restoration.com',
            password='demo123'
        ))
        response = self.client.get('/assign')
        self.assertIn(b'Assign Candidates', response.data)
        self.assertIn(b'Gagan Rana', response.data)

    def test_pii_masking_dark_theme(self):
        """Verify sensitive data is hidden for clients."""
        self.client.post('/login', data=dict(
            username='client1@gmail.com',
            password='demo123'
        ))
        # View Gagan Rana (ID 3)
        response = self.client.get('/candidate/3')
        # Ensure email and specific phone numbers are NOT in the text
        self.assertNotIn(b'service@karmastaff.com', response.data)
        self.assertNotIn(b'555-0103', response.data)
        # Verify the circular avatar and 'Request Meeting' are present instead
        self.assertIn(b'Request Meeting', response.data)

    def test_client_portal_customization(self):
        """Verify client-specific navigation and meetings page."""
        self.client.post('/login', data=dict(
            username='client1@gmail.com',
            password='demo123'
        ))
        response = self.client.get('/candidates')
        self.assertIn(b'Recruiter AI', response.data) # Styled link text
        self.assertIn(b'Celebrate', response.data)
        self.assertNotIn(b'href="/admin-dashboard"', response.data)
        
        # Test Meetings Page
        response = self.client.get('/meetings')
        self.assertIn(b'No meetings scheduled yet', response.data)
        
        # Test Restricted Access
        response = self.client.get('/users')
        self.assertEqual(response.status_code, 403)

    def test_user_creation_validation(self):
        """Verify email validation and duplicate user prevention."""
        # 1. Login as admin
        self.client.post('/login', data=dict(
            username='admin@restoration.com',
            password='demo123'
        ))

        # 2. Test unique email
        response = self.client.post('/api/users/create', data=dict(
            username='NewUser',
            email='admin@restoration.com', # Duplicate email
            role='client'
        ), follow_redirects=True)
        self.assertIn(b'Email already in use', response.data)

        # 3. Test unique username
        response = self.client.post('/api/users/create', data=dict(
            username='admin', # Duplicate username
            email='new@example.com',
            role='client'
        ), follow_redirects=True)
        self.assertIn(b'Username already exists', response.data)

        # 4. Test invalid email format
        response = self.client.post('/api/users/create', data=dict(
            username='ValidName',
            email='invalid-email',
            role='client'
        ), follow_redirects=True)
        self.assertIn(b'Invalid email format', response.data)

        # 5. Success case
        self.client.post('/api/users/create', data=dict(
            username='TestUserSuccess',
            email='testsuccess@example.com',
            role='client'
        ))

        # 6. Verify login with new email
        self.client.get('/logout')
        response = self.client.post('/login', data=dict(
            username='testsuccess@example.com',
            password='demo123'
        ), follow_redirects=True)
        self.assertIn(b'Restore with Us', response.data)

if __name__ == '__main__':
    unittest.main()
