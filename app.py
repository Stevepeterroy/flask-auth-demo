"""Local authentication learning exercise, separate from the static portfolio."""

import os, re, secrets, sqlite3, time
from contextlib import closing
from pathlib import Path
from flask import Flask, request, jsonify, session, render_template, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.environ.get(
            "FLASK_DATABASE", str(Path(__file__).with_name("auth-demo.sqlite3"))
        ),
        MAX_CONTENT_LENGTH=16384,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )
    if config:
        app.config.update(config)
    with closing(sqlite3.connect(app.config["DATABASE"])) as db, db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL)"
        )
    attempts = {}

    @app.before_request
    def protect():
        if request.method == "POST" and request.path.startswith("/api/"):
            if not request.is_json:
                return jsonify(error="JSON required"), 415
            token = request.headers.get("X-CSRF-Token", "")
            if not token or not secrets.compare_digest(token, session.get("csrf", "")):
                return jsonify(error="Refresh the page and retry"), 403

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/signup.html")
    @app.get("/login.html")
    def auth_page():
        return send_from_directory(app.root_path, request.path.lstrip("/"))

    @app.get("/auth.js")
    @app.get("/style.css")
    def asset():
        return send_from_directory(app.root_path, request.path.lstrip("/"))

    @app.get("/api/session")
    def state():
        session.setdefault("csrf", secrets.token_urlsafe(32))
        response = jsonify(csrf=session["csrf"], username=session.get("username"))
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/api/signup")
    @app.post("/api/login")
    def authenticate():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="Expected an object"), 400
        username = body.get("username")
        password = body.get("password")
        if (
            not isinstance(username, str)
            or not re.fullmatch(r"[A-Za-z0-9_]{3,40}", username)
            or not isinstance(password, str)
            or not 12 <= len(password) <= 128
        ):
            return jsonify(
                error="Use a 3–40 character username (letters, numbers, _) and 12–128 character password"
            ), 400
        now = time.monotonic()
        key = (request.remote_addr, username.lower())
        for stale in [k for k, v in attempts.items() if now - v[0] > 300]:
            attempts.pop(stale, None)
        if len(attempts) > 10000:
            return jsonify(error="Busy; retry later"), 429
        count = attempts.get(key, (now, 0))
        if count[1] >= 10:
            return jsonify(error="Too many attempts; wait five minutes"), 429
        attempts[key] = (count[0], count[1] + 1)
        with closing(sqlite3.connect(app.config["DATABASE"])) as db, db:
            if request.path.endswith("signup"):
                try:
                    db.execute(
                        "INSERT INTO users(username,password) VALUES(?,?)",
                        (username, generate_password_hash(password)),
                    )
                except sqlite3.IntegrityError:
                    return jsonify(error="Username unavailable"), 409
                return jsonify(message="Account created"), 201
            row = db.execute(
                "SELECT password FROM users WHERE username=?", (username,)
            ).fetchone()
            # Always perform password hashing work for nonexistent accounts too.
            stored = row[0] if row else generate_password_hash("dummy-local-account")
            if not check_password_hash(stored, password) or not row:
                return jsonify(error="Invalid credentials"), 401
        session.clear()
        session.update(username=username, csrf=secrets.token_urlsafe(32))
        attempts.pop(key, None)
        return jsonify(message="Signed in", username=username)

    @app.post("/api/logout")
    def logout():
        session.clear()
        return jsonify(message="Signed out")

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5001, debug=False)
