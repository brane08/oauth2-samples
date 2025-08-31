import datetime

import jwt
from flask import Flask, request, redirect, render_template, make_response, Response

app = Flask(__name__)

SECRET_KEY = "XLxwEzxLmowhWCuOSzSQrm6GoI0PJFByD08n4XYs+f8XtZMh6ioy7fzzgmCRmjQK"
ALGORITHM = "HS256"

# Fake user DB
USERS = {"alice": "password123", "bob": "secret"}


def _build_token_cookie(service_url: str, username: str) -> Response:
    payload = {
        "sub": username,
        "roles": ["USER"],
        "iat": datetime.datetime.now(datetime.UTC),
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=30)
    }

    # Encode JWT
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    # Set cookie
    resp = make_response(redirect(service_url))
    resp.set_cookie("SSO_TOKEN", token, httponly=True, secure=False, samesite='Lax')
    return resp


def _build_simple_cookie(service_url: str, username: str) -> Response:
    # Set cookie
    resp = make_response(redirect(service_url))
    resp.set_cookie("SSO_TOKEN", username, httponly=True, secure=False, samesite='Lax')
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    service_url = request.args.get("redirect", "http://localhost:8078/")

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if USERS.get(username) == password:
            return _build_simple_cookie(service_url, username)
            # return _build_token_cookie(service_url, username)
        else:
            return render_template("login.html", error="Invalid username or password", redirect=service_url)

    return render_template("login.html", redirect=service_url)


@app.route("/validate")
def validate():
    token = request.cookies.get("SSO_TOKEN")
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"valid": True, "user": data["sub"], "roles": data.get("roles", [])}
    except Exception as e:
        return {"valid": False, "error": str(e)}, 401


if __name__ == "__main__":
    app.run(port=5000, debug=True)
