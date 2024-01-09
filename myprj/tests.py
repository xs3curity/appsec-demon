import unittest
from app import app


class FlaskAppTest(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.app = app.test_client()

    def test_list_files_route(self):
        response = self.app.get("/")
        self.assertEqual(response.status_code, 200)

    def test_read_file_route(self):
        response = self.app.get("/read_file?file=documents/test.txt")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"test", response.data)

    def test_nonexistent_file(self):
        response = self.app.get("/read_file?file=nonexistent.txt")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"File not found.")


if __name__ == "__main__":
    unittest.main()
