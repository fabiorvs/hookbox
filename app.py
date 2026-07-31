import json
import ipaddress
import os
import secrets
import shlex
import socket
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from http import HTTPStatus
from http.cookies import SimpleCookie
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlparse
from urllib.request import Request, urlopen

from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, session, stream_with_context, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", secrets.token_hex(32)),
    DATABASE=os.getenv("DATABASE_PATH", os.path.join(app.instance_path, "webhook-box.db")),
    MAX_CONTENT_LENGTH=int(os.getenv("MAX_REQUEST_BYTES", 1024 * 1024)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
    MAX_REQUESTS_PER_ENDPOINT=int(os.getenv("MAX_REQUESTS_PER_ENDPOINT", 500)),
    MAX_ENDPOINTS_PER_USER=int(os.getenv("MAX_ENDPOINTS_PER_USER", 25)),
    RETENTION_DAYS=int(os.getenv("RETENTION_DAYS", 30)),
    ALLOW_REGISTRATION=os.getenv("ALLOW_REGISTRATION", "true").lower() == "true",
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


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
        CREATE TABLE IF NOT EXISTS rate_limits (
            key TEXT NOT NULL,
            bucket INTEGER NOT NULL,
            hits INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(key, bucket)
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            details TEXT,
            remote_addr TEXT,
            created_at TEXT NOT NULL
        );
    """)
    migrations = {
        "users": {"is_admin": "INTEGER NOT NULL DEFAULT 0", "active": "INTEGER NOT NULL DEFAULT 1"},
        "endpoints": {
            "tag": "TEXT NOT NULL DEFAULT ''", "color": "TEXT NOT NULL DEFAULT '#24d2a1'",
            "archived": "INTEGER NOT NULL DEFAULT 0", "secret": "TEXT NOT NULL DEFAULT ''",
            "response_delay_ms": "INTEGER NOT NULL DEFAULT 0", "favorite": "INTEGER NOT NULL DEFAULT 0"
        },
        "requests": {"response_status": "INTEGER NOT NULL DEFAULT 200"},
    }
    for table, columns in migrations.items():
        existing = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        for column, definition in columns.items():
            if column not in existing:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    if connection.execute("SELECT COUNT(*) FROM users WHERE is_admin=1").fetchone()[0] == 0:
        first_user = connection.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
        if first_user:
            connection.execute("UPDATE users SET is_admin=1 WHERE id=?", (first_user[0],))
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


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(**kwargs):
        user = db().execute("SELECT is_admin,active FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not user or not user["active"] or not user["is_admin"]:
            abort(403)
        return view(**kwargs)
    return wrapped


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def require_csrf():
    if not secrets.compare_digest(session.get("csrf", ""), request.form.get("csrf", "")):
        abort(400, "Token CSRF inválido")


def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


def limited(scope, limit, seconds):
    bucket = int(time.time() // seconds)
    key = f"{scope}:{client_ip()}"
    connection = db()
    connection.execute("INSERT INTO rate_limits(key,bucket,hits) VALUES(?,?,1) ON CONFLICT(key,bucket) DO UPDATE SET hits=hits+1", (key, bucket))
    hits = connection.execute("SELECT hits FROM rate_limits WHERE key=? AND bucket=?", (key, bucket)).fetchone()[0]
    if secrets.randbelow(100) == 0:
        connection.execute("DELETE FROM rate_limits WHERE bucket < ?", (bucket - 2,))
    connection.commit()
    return hits > limit


def audit(action, details="", user_id=None):
    db().execute("INSERT INTO audit_log(user_id,action,details,remote_addr,created_at) VALUES(?,?,?,?,?)",
                 (user_id or session.get("user_id"), action, details[:500], client_ip(), now()))
    db().commit()


@app.context_processor
def inject_user():
    user = None
    if session.get("user_id"):
        user = db().execute("SELECT id,name,email,is_admin FROM users WHERE id=? AND active=1", (session["user_id"],)).fetchone()
    return {"current_user": user}


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'; img-src 'self' data:")
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


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
    if not app.config["ALLOW_REGISTRATION"] and not session.get("user_id"):
        abort(403, "Novos cadastros estão desativados")
    if request.method == "POST":
        require_csrf()
        if limited("register", 5, 3600):
            abort(429, "Muitas tentativas de cadastro")
        name, email, password = request.form.get("name", "").strip(), request.form.get("email", "").strip(), request.form.get("password", "")
        if not name or "@" not in email or len(password) < 8:
            flash("Preencha o nome, um e-mail válido e uma senha com ao menos 8 caracteres.", "error")
        else:
            try:
                first_user = db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
                cursor = db().execute("INSERT INTO users(name,email,password_hash,is_admin,created_at) VALUES(?,?,?,?,?)", (name, email, generate_password_hash(password), int(first_user), now()))
                db().commit()
                session.clear()
                session["user_id"] = cursor.lastrowid
                audit("user.register", email, cursor.lastrowid)
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                flash("Este e-mail já está cadastrado.", "error")
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        require_csrf()
        if limited("login", 10, 900):
            abort(429, "Muitas tentativas. Tente novamente mais tarde.")
        user = db().execute("SELECT * FROM users WHERE email = ?", (request.form.get("email", "").strip(),)).fetchone()
        if user and user["active"] and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session["user_id"] = user["id"]
            audit("user.login", user["email"], user["id"])
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
        WHERE e.user_id=? AND e.archived=? GROUP BY e.id ORDER BY e.favorite DESC,e.id DESC
    """, (session["user_id"], int(request.args.get("archived") == "1"))).fetchall()
    latest_activity = max((item["last_request"] for item in endpoints if item["last_request"]), default=None)
    return render_template("dashboard.html", endpoints=endpoints, latest_activity=latest_activity,
                           showing_archived=request.args.get("archived") == "1",
                           base_url=os.getenv("PUBLIC_BASE_URL", request.host_url.rstrip("/")))


@app.post("/endpoints")
@login_required
def create_endpoint():
    require_csrf()
    count = db().execute("SELECT COUNT(*) FROM endpoints WHERE user_id=? AND archived=0", (session["user_id"],)).fetchone()[0]
    if count >= app.config["MAX_ENDPOINTS_PER_USER"]:
        flash(f"Limite de {app.config['MAX_ENDPOINTS_PER_USER']} endpoints atingido.", "error")
        return redirect(url_for("dashboard"))
    name = request.form.get("name", "").strip()[:80]
    if not name:
        flash("Dê um nome ao endpoint.", "error")
        return redirect(url_for("dashboard"))
    token = str(uuid.uuid4())
    cursor = db().execute("INSERT INTO endpoints(user_id,uuid,name,created_at) VALUES(?,?,?,?)", (session["user_id"], token, name, now()))
    db().commit()
    audit("endpoint.create", token)
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
        cookie = SimpleCookie(); cookie.load(headers.get("Cookie", ""))
        detail = {
            "body": rendered_body or "(vazio)",
            "body_kind": body_kind,
            "body_size": len(selected["body"] or b""),
            "headers": headers,
            "header_lines": "\n".join(f"{key}: {value}" for key, value in headers.items()),
            "query": parse_qsl(selected["query_string"], keep_blank_values=True),
            "cookies": [(key, morsel.value) for key, morsel in cookie.items()],
            "status_text": HTTPStatus._value2member_map_.get(selected["response_status"], "HTTP").phrase if selected["response_status"] in HTTPStatus._value2member_map_ else "HTTP",
        }
        hook_url = f"{os.getenv('PUBLIC_BASE_URL', request.host_url.rstrip('/'))}/hook/{endpoint['uuid']}{selected['path']}"
        if selected["query_string"]:
            hook_url += f"?{selected['query_string']}"
        ignored = {"host", "content-length", "connection"}
        curl_parts = ["curl", "-X", selected["method"], shlex.quote(hook_url)]
        for key, value in headers.items():
            if key.lower() not in ignored:
                curl_parts += ["-H", shlex.quote(f"{key}: {value}")]
        if body_text:
            curl_parts += ["--data-raw", shlex.quote(body_text)]
        detail["curl"] = " \\\n  ".join(curl_parts)
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
        delay = max(0, min(request.form.get("delay", 0, type=int) or 0, 10000))
        color = request.form.get("color", "#24d2a1")
        if not color.startswith("#") or len(color) != 7:
            color = "#24d2a1"
        db().execute("UPDATE endpoints SET name=?,tag=?,color=?,secret=?,response_status=?,response_content_type=?,response_body=?,response_delay_ms=? WHERE id=?", (
            request.form.get("name", "Webhook")[:80], request.form.get("tag", "")[:30], color,
            request.form.get("secret", "")[:200], status, request.form.get("content_type", "text/plain")[:100],
            request.form.get("body", "")[:100000], delay, endpoint_id))
        db().commit(); audit("endpoint.update", str(endpoint_id)); flash("Configuração salva.", "success")
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


@app.post("/endpoints/<int:endpoint_id>/archive")
@login_required
def archive_endpoint(endpoint_id):
    require_csrf(); endpoint = owned_endpoint(endpoint_id)
    archived = 0 if endpoint["archived"] else 1
    db().execute("UPDATE endpoints SET archived=? WHERE id=?", (archived, endpoint_id)); db().commit()
    audit("endpoint.archive" if archived else "endpoint.restore", str(endpoint_id))
    flash("Endpoint arquivado." if archived else "Endpoint restaurado.", "success")
    return redirect(url_for("dashboard", archived=1) if not archived else url_for("dashboard"))


@app.post("/endpoints/<int:endpoint_id>/favorite")
@login_required
def favorite_endpoint(endpoint_id):
    require_csrf(); endpoint = owned_endpoint(endpoint_id)
    db().execute("UPDATE endpoints SET favorite=? WHERE id=?", (0 if endpoint["favorite"] else 1, endpoint_id)); db().commit()
    return redirect(request.referrer if request.referrer and request.referrer.startswith(request.host_url) else url_for("dashboard"))


@app.post("/endpoints/<int:endpoint_id>/rotate")
@login_required
def rotate_endpoint(endpoint_id):
    require_csrf(); owned_endpoint(endpoint_id)
    token = str(uuid.uuid4())
    db().execute("UPDATE endpoints SET uuid=? WHERE id=?", (token, endpoint_id)); db().commit()
    audit("endpoint.rotate", str(endpoint_id)); flash("URL regenerada. A URL anterior não funciona mais.", "success")
    return redirect(url_for("endpoint_detail", endpoint_id=endpoint_id))


@app.route("/hook/<token>", defaults={"extra_path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@app.route("/hook/<token>/<path:extra_path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def receive(token, extra_path):
    endpoint = db().execute("SELECT * FROM endpoints WHERE uuid=?", (token,)).fetchone()
    if not endpoint:
        return jsonify(error="Webhook não encontrado"), 404
    if endpoint["archived"]:
        return jsonify(error="Webhook arquivado"), 410
    if limited(f"hook:{token}", 120, 60):
        return jsonify(error="Limite de requisições excedido"), 429
    provided_secret = request.headers.get("X-Hookbox-Secret", request.args.get("secret", ""))
    if endpoint["secret"] and not secrets.compare_digest(endpoint["secret"], provided_secret):
        return jsonify(error="Segredo inválido"), 401
    forwarded = client_ip()
    db().execute("""INSERT INTO requests(endpoint_id,method,path,query_string,headers,body,content_type,remote_addr,response_status,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?)""", (endpoint["id"], request.method, "/" + extra_path if extra_path else "/", request.query_string.decode("utf-8", "replace"),
        json.dumps(dict(request.headers), ensure_ascii=False), request.get_data(), request.content_type, forwarded or request.remote_addr, endpoint["response_status"], now()))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=app.config["RETENTION_DAYS"])).isoformat(timespec="seconds")
    db().execute("DELETE FROM requests WHERE endpoint_id=? AND created_at < ?", (endpoint["id"], cutoff))
    db().execute("DELETE FROM requests WHERE endpoint_id=? AND id NOT IN (SELECT id FROM requests WHERE endpoint_id=? ORDER BY id DESC LIMIT ?)",
                 (endpoint["id"], endpoint["id"], app.config["MAX_REQUESTS_PER_ENDPOINT"]))
    db().commit()
    if endpoint["response_delay_ms"]:
        time.sleep(endpoint["response_delay_ms"] / 1000)
    return app.response_class(endpoint["response_body"], status=endpoint["response_status"], content_type=endpoint["response_content_type"])


@app.get("/api/endpoints/<int:endpoint_id>/requests")
@login_required
def requests_api(endpoint_id):
    owned_endpoint(endpoint_id)
    after = request.args.get("after", 0, type=int)
    rows = db().execute("SELECT id,method,path,created_at,content_type,remote_addr FROM requests WHERE endpoint_id=? AND id>? ORDER BY id DESC LIMIT 100", (endpoint_id, after)).fetchall()
    return jsonify([dict(row) for row in rows])


@app.get("/api/endpoints/<int:endpoint_id>/events")
@login_required
def request_events(endpoint_id):
    owned_endpoint(endpoint_id)
    start_id = request.args.get("after", 0, type=int)
    database_path = app.config["DATABASE"]

    @stream_with_context
    def stream():
        last_id = start_id
        for _ in range(25):
            connection = sqlite3.connect(database_path)
            row = connection.execute("SELECT id FROM requests WHERE endpoint_id=? AND id>? ORDER BY id DESC LIMIT 1", (endpoint_id, last_id)).fetchone()
            connection.close()
            if row:
                last_id = row[0]
                yield f"event: request\ndata: {json.dumps({'id': last_id})}\n\n"
            else:
                yield ": keepalive\n\n"
            time.sleep(1)
    return Response(stream(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/endpoints/<int:endpoint_id>/requests/<int:request_id>/export")
@login_required
def export_request(endpoint_id, request_id):
    owned_endpoint(endpoint_id)
    row = db().execute("SELECT * FROM requests WHERE id=? AND endpoint_id=?", (request_id, endpoint_id)).fetchone()
    if not row:
        abort(404)
    payload = dict(row)
    payload["body"] = bytes(row["body"] or b"").decode("utf-8", "replace")
    response = jsonify(payload)
    response.headers["Content-Disposition"] = f'attachment; filename="hookbox-request-{request_id}.json"'
    return response


def validate_replay_url(value):
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Use uma URL HTTP ou HTTPS válida")
    for result in socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)):
        address = ipaddress.ip_address(result[4][0])
        if not address.is_global:
            raise ValueError("Destinos locais ou privados não são permitidos")
    return value


@app.post("/endpoints/<int:endpoint_id>/requests/<int:request_id>/replay")
@login_required
def replay_request(endpoint_id, request_id):
    require_csrf(); owned_endpoint(endpoint_id)
    row = db().execute("SELECT * FROM requests WHERE id=? AND endpoint_id=?", (request_id, endpoint_id)).fetchone()
    if not row:
        abort(404)
    try:
        target = validate_replay_url(request.form.get("target", ""))
        stored_headers = json.loads(row["headers"])
        blocked = {"host", "content-length", "connection", "transfer-encoding"}
        headers = {key: value for key, value in stored_headers.items() if key.lower() not in blocked}
        outgoing = Request(target, data=bytes(row["body"] or b"") or None, headers=headers, method=row["method"])
        try:
            with urlopen(outgoing, timeout=10) as remote:
                status = remote.status
        except HTTPError as error:
            status = error.code
        audit("request.replay", f"request={request_id} target={urlparse(target).hostname} status={status}")
        flash(f"Requisição reenviada. Destino respondeu HTTP {status}.", "success")
    except (ValueError, URLError, OSError) as error:
        flash(f"Não foi possível reenviar: {error}", "error")
    return redirect(url_for("endpoint_detail", endpoint_id=endpoint_id, request=request_id))


@app.get("/admin")
@admin_required
def admin_dashboard():
    users = db().execute("""SELECT u.*, COUNT(DISTINCT e.id) endpoint_count, COUNT(r.id) request_count
        FROM users u LEFT JOIN endpoints e ON e.user_id=u.id LEFT JOIN requests r ON r.endpoint_id=e.id
        GROUP BY u.id ORDER BY u.id""").fetchall()
    audits = db().execute("SELECT a.*,u.email FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 50").fetchall()
    return render_template("admin.html", users=users, audits=audits, registration_open=app.config["ALLOW_REGISTRATION"])


@app.post("/admin/users/<int:user_id>/toggle")
@admin_required
def admin_toggle_user(user_id):
    require_csrf()
    if user_id == session["user_id"]:
        flash("Você não pode bloquear sua própria conta.", "error")
    else:
        user = db().execute("SELECT active FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            abort(404)
        db().execute("UPDATE users SET active=? WHERE id=?", (0 if user["active"] else 1, user_id)); db().commit()
        audit("admin.user.toggle", str(user_id)); flash("Status do usuário alterado.", "success")
    return redirect(url_for("admin_dashboard"))


@app.get("/health")
def health():
    db().execute("SELECT 1").fetchone()
    return jsonify(status="ok")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
