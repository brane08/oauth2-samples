import datetime
from pathlib import Path

import jwt
from flask import Flask, request, redirect, render_template, make_response, Response, send_from_directory

app = Flask(__name__)

SECRET_KEY = "XLxwEzxLmowhWCuOSzSQrm6GoI0PJFByD08n4XYs+f8XtZMh6ioy7fzzgmCRmjQK"
ALGORITHM = "HS256"
COOKIE_DOMAIN = "example.local"

# Fake user DB
USERS = {"user1": "password", "user2": "password"}


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
    resp.set_cookie("SSO_TOKEN", token, domain=COOKIE_DOMAIN, httponly=True, secure=True, samesite='Lax')
    return resp


def _build_simple_cookie(service_url: str, username: str) -> Response:
    # Set cookie
    resp = make_response(redirect(service_url))
    resp.set_cookie("SSO_TOKEN", username, domain=COOKIE_DOMAIN, httponly=True, secure=True, samesite='Lax')
    return resp


@app.route("/")
def index():
    return redirect("/login")


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(app.static_folder, "favicon.ico", mimetype="image/vnd.microsoft.icon")


@app.route("/login", methods=["GET", "POST"])
def login():
    service_url = request.args.get("redirect", "https://gateway.example.local:8078/mvc")

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
    certs = Path(__file__).resolve().parents[2] / "certs"
    app.run(port=5000, debug=True, ssl_context=(str(certs / "services.crt"), str(certs / "services.key")))
