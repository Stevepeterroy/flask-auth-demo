import tempfile, unittest
from pathlib import Path
from app import create_app


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "isolated-test-only",
                "DATABASE": str(Path(self.tmp.name) / "auth"),
            }
        )
        self.c = self.app.test_client()

    def post(self, path, body):
        token = self.c.get("/api/session").json["csrf"]
        return self.c.post(path, json=body, headers={"X-CSRF-Token": token})

    def test_signup_login_logout(self):
        body = {"username": "learner", "password": "long-local-test-password"}
        self.assertEqual(self.post("/api/signup", body).status_code, 201)
        self.assertEqual(self.post("/api/signup", body).status_code, 409)
        self.assertEqual(
            self.post(
                "/api/login", {**body, "password": "incorrect-password"}
            ).status_code,
            401,
        )
        self.assertEqual(self.post("/api/login", body).status_code, 200)
        self.assertEqual(self.c.get("/api/session").json["username"], "learner")
        self.assertEqual(self.post("/api/logout", {}).status_code, 200)
        self.assertIsNone(self.c.get("/api/session").json["username"])

    def test_csrf_and_validation(self):
        self.assertEqual(self.c.post("/api/signup", json={}).status_code, 403)
        for body in [
            {},
            [],
            {"username": "bad space", "password": "x" * 12},
            {"username": "valid", "password": "short"},
        ]:
            self.assertEqual(self.post("/api/signup", body).status_code, 400)

    def test_same_origin_pages_and_assets(self):
        for path in ["/", "/signup.html", "/login.html", "/auth.js", "/style.css"]:
            with self.c.get(path) as response:
                self.assertEqual(response.status_code, 200)
