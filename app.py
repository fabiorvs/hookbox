import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import parse_qsl

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", secrets.token_hex(32)),
    DATABASE=os.getenv("DATABASE_PATH", os.path.join(app.instance_path, "webhook-box.db")),
    MAX_CONTENT_LENGTH=int(os.getenv("MAX_REQUEST_BYTES", 1024 * 1024)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def db():
    if "db" not in g:
        os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection:
        connection.close()


def init_db():
    connection = db()
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            uuid TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            response_status INTEGER NOT NULL DEFAULT 200,
            response_body TEXT NOT NULL DEFAULT '{"received": true}',
            response_content_type TEXT NOT NULL DEFAULT 'application/json',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_id INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            query_string TEXT NOT NULL,
            headers TEXT NOT NULL,
            body BLOB,
            content_type TEXT,
            remote_addr TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_requests_endpoint_created
            ON requests(endpoint_id, id DESC);
    """)
    connection.commit()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def login_required(view):
    @wraps(view)
    def wrapped(**kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return view(**kwargs)
    return wrapped


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def require_csrf():
    if not secrets.compare_digest(session.get("csrf", ""), request.form.get("csrf", "")):
        abort(400, "Token CSRF inválido")


app.jinja_env.globals["csrf_token"] = csrf_token
app.jinja_env.filters["pretty_json"] = lambda value: json.dumps(json.loads(value), ensure_ascii=False, indent=2)
app.jinja_env.filters["header_lines"] = lambda value: "\n".join(
    f"{name}: {header_value}" for name, header_value in json.loads(value).items()
)


with app.app_context():
    init_db()


@app.get("/")
def index():
    return redirect(url_for("dashboard" if session.get("user_id") else "login"))


@app.route("/cadastro", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        require_csrf()
        name, email, password = request.form.get("name", "").strip(), request.form.get("email", "").strip(), request.form.get("password", "")
        if not name or "@" not in email or len(password) < 8:
            flash("Preencha o nome, um e-mail válido e uma senha com ao menos 8 caracteres.", "error")
        else:
            try:
                cursor = db().execute("INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)", (name, email, generate_password_hash(password), now()))
                db().commit()
                session.clear()
                session["user_id"] = cursor.lastrowid
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                flash("Este e-mail já está cadastrado.", "error")
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        require_csrf()
        user = db().execute("SELECT * FROM users WHERE email = ?", (request.form.get("email", "").strip(),)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session["user_id"] = user["id"]
            next_url = request.args.get("next", "")
            return redirect(next_url if next_url.startswith("/") and not next_url.startswith("//") else url_for("dashboard"))
        flash("E-mail ou senha inválidos.", "error")
    return render_template("auth.html", mode="login")


@app.post("/sair")
def logout():
    require_csrf()
    session.clear()
    return redirect(url_for("login"))


@app.get("/painel")
@login_required
def dashboard():
    endpoints = db().execute("""
        SELECT e.*, COUNT(r.id) request_count, MAX(r.created_at) last_request
        FROM endpoints e LEFT JOIN requests r ON r.endpoint_id=e.id
        WHERE e.user_id=? GROUP BY e.id ORDER BY e.id DESC
    """, (session["user_id"],)).fetchall()
    return render_template("dashboard.html", endpoints=endpoints, base_url=os.getenv("PUBLIC_BASE_URL", request.host_url.rstrip("/")))


@app.post("/endpoints")
@login_required
def create_endpoint():
    require_csrf()
    name = request.form.get("name", "").strip()[:80]
    if not name:
        flash("Dê um nome ao endpoint.", "error")
        return redirect(url_for("dashboard"))
    token = str(uuid.uuid4())
    cursor = db().execute("INSERT INTO endpoints(user_id,uuid,name,created_at) VALUES(?,?,?,?)", (session["user_id"], token, name, now()))
    db().commit()
    return redirect(url_for("endpoint_detail", endpoint_id=cursor.lastrowid))


def owned_endpoint(endpoint_id):
    endpoint = db().execute("SELECT * FROM endpoints WHERE id=? AND user_id=?", (endpoint_id, session["user_id"])).fetchone()
    if not endpoint:
        abort(404)
    return endpoint


@app.get("/endpoints/<int:endpoint_id>")
@login_required
def endpoint_detail(endpoint_id):
    endpoint = owned_endpoint(endpoint_id)
    rows = db().execute("SELECT * FROM requests WHERE endpoint_id=? ORDER BY id DESC LIMIT 100", (endpoint_id,)).fetchall()
    selected = rows[0] if rows else None
    selected_id = request.args.get("request", type=int)
    if selected_id:
        selected = db().execute("SELECT * FROM requests WHERE id=? AND endpoint_id=?", (selected_id, endpoint_id)).fetchone()
    detail = None
    if selected:
        body_text = bytes(selected["body"] or b"").decode("utf-8", "replace")
        rendered_body = body_text
        body_kind = "TEXT"
        try:
            rendered_body = json.dumps(json.loads(body_text), ensure_ascii=False, indent=2)
            body_kind = "JSON"
        except (json.JSONDecodeError, TypeError):
            pass
        headers = json.loads(selected["headers"])
        detail = {
            "body": rendered_body or "(vazio)",
            "body_kind": body_kind,
            "body_size": len(selected["body"] or b""),
            "headers": headers,
            "header_lines": "\n".join(f"{key}: {value}" for key, value in headers.items()),
            "query": parse_qsl(selected["query_string"], keep_blank_values=True),
        }
    return render_template("endpoint.html", endpoint=endpoint, requests=rows, selected=selected,
                           detail=detail, base_url=os.getenv("PUBLIC_BASE_URL", request.host_url.rstrip("/")))


@app.post("/endpoints/<int:endpoint_id>/config")
@login_required
def endpoint_config(endpoint_id):
    require_csrf(); owned_endpoint(endpoint_id)
    status = request.form.get("status", type=int)
    if not status or status < 100 or status > 599:
        flash("Status HTTP inválido.", "error")
    else:
        db().execute("UPDATE endpoints SET name=?,response_status=?,response_content_type=?,response_body=? WHERE id=?", (
            request.form.get("name", "Webhook")[:80], status, request.form.get("content_type", "text/plain")[:100], request.form.get("body", "")[:100000], endpoint_id))
        db().commit(); flash("Configuração salva.", "success")
    return redirect(url_for("endpoint_detail", endpoint_id=endpoint_id))


@app.post("/endpoints/<int:endpoint_id>/clear")
@login_required
def clear_requests(endpoint_id):
    require_csrf(); owned_endpoint(endpoint_id)
    db().execute("DELETE FROM requests WHERE endpoint_id=?", (endpoint_id,)); db().commit()
    flash("Histórico limpo.", "success")
    return redirect(url_for("endpoint_detail", endpoint_id=endpoint_id))


@app.post("/endpoints/<int:endpoint_id>/delete")
@login_required
def delete_endpoint(endpoint_id):
    require_csrf(); owned_endpoint(endpoint_id)
    db().execute("DELETE FROM endpoints WHERE id=?", (endpoint_id,)); db().commit()
    flash("Endpoint excluído.", "success")
    return redirect(url_for("dashboard"))


@app.route("/hook/<token>", defaults={"extra_path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@app.route("/hook/<token>/<path:extra_path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def receive(token, extra_path):
    endpoint = db().execute("SELECT * FROM endpoints WHERE uuid=?", (token,)).fetchone()
    if not endpoint:
        return jsonify(error="Webhook não encontrado"), 404
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    db().execute("""INSERT INTO requests(endpoint_id,method,path,query_string,headers,body,content_type,remote_addr,created_at)
        VALUES(?,?,?,?,?,?,?,?,?)""", (endpoint["id"], request.method, "/" + extra_path if extra_path else "/", request.query_string.decode("utf-8", "replace"),
        json.dumps(dict(request.headers), ensure_ascii=False), request.get_data(), request.content_type, forwarded or request.remote_addr, now()))
    db().commit()
    return app.response_class(endpoint["response_body"], status=endpoint["response_status"], content_type=endpoint["response_content_type"])


@app.get("/api/endpoints/<int:endpoint_id>/requests")
@login_required
def requests_api(endpoint_id):
    owned_endpoint(endpoint_id)
    after = request.args.get("after", 0, type=int)
    rows = db().execute("SELECT id,method,path,created_at,content_type,remote_addr FROM requests WHERE endpoint_id=? AND id>? ORDER BY id DESC LIMIT 100", (endpoint_id, after)).fetchall()
    return jsonify([dict(row) for row in rows])


@app.get("/health")
def health():
    db().execute("SELECT 1").fetchone()
    return jsonify(status="ok")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
