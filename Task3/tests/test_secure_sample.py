import sqlite3
import unittest
from secure_sample import authenticate, create_user, initialize_db

class SecureSampleTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        initialize_db(self.conn)
        create_user(self.conn, "rudra_test", "Test-Password-123!")

    def tearDown(self):
        self.conn.close()

    def test_correct_password(self):
        self.assertTrue(authenticate(self.conn, "rudra_test", "Test-Password-123!"))

    def test_wrong_password(self):
        self.assertFalse(authenticate(self.conn, "rudra_test", "Wrong-Password-123!"))

    def test_sql_metacharacters_are_not_a_query(self):
        self.assertFalse(authenticate(self.conn, "' OR '1'='1", "Test-Password-123!"))

    def test_invalid_username(self):
        self.assertFalse(authenticate(self.conn, "bad username", "Test-Password-123!"))

    def test_password_not_stored_plaintext(self):
        row = self.conn.execute(
            "SELECT password_salt, password_hash FROM users WHERE username = ?",
            ("rudra_test",),
        ).fetchone()
        self.assertNotEqual(row[1], b"Test-Password-123!")
        self.assertEqual(len(row[0]), 16)

    def test_short_password_rejected(self):
        with self.assertRaises(ValueError):
            create_user(self.conn, "another_user", "short")

if __name__ == "__main__":
    unittest.main()
