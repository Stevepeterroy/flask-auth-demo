# Local Flask authentication exercise

The static personal portfolio in the parent is separate. These forms now use same-origin `/api/signup`, `/api/login` and `/api/logout` with hashed passwords, SQLite, signed HttpOnly/SameSite sessions, CSRF tokens, input bounds and local rate limiting.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -v
.venv/bin/python app.py
```

Open http://127.0.0.1:5001/signup.html. Use fictional accounts. A random session key is generated per process unless FLASK_SECRET_KEY is set; sessions expire on restart. No key is stored in source. This is a local learning exercise, not a production identity service; rate limiting is single-process and production requires TLS, a durable shared limiter, deployment review and password-reset/account-lifecycle features.
