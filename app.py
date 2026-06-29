import csv
import io
import os
import secrets
import sqlite3
import time
from functools import wraps
from urllib.parse import urlencode

from flask import Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
import requests
import urllib3
from werkzeug.security import check_password_hash, generate_password_hash

from config import *

urllib3.disable_warnings()

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_DB_PATH = os.path.join(BASE_DIR, "portal_users.db")
SECRET_KEY_PATH = os.path.join(BASE_DIR, ".portal_secret_key")
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_SECONDS = 15 * 60


def load_secret_key():
    if os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, "r", encoding="utf-8") as key_file:
            return key_file.read().strip()

    secret_key = secrets.token_urlsafe(48)
    with open(SECRET_KEY_PATH, "w", encoding="utf-8") as key_file:
        key_file.write(secret_key)

    return secret_key


app.secret_key = os.environ.get("OCAM_PORTAL_SECRET_KEY") or load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("OCAM_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=3600
)

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Accept": "application/json"
}

json_headers = {
    **headers,
    "Content-Type": "application/json"
}

PUBLIC_ENDPOINTS = {
    "login",
    "static"
}

PASSWORD_CHANGE_ENDPOINTS = {
    "change_password",
    "logout",
    "static"
}

ROLE_LABELS = {
    "superadmin": "Super Admin",
    "admin": "Admin",
    "user": "User"
}


def db_connection():
    connection = sqlite3.connect(AUTH_DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_auth_db():
    with db_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS portal_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('superadmin', 'admin', 'user')),
                active INTEGER NOT NULL DEFAULT 1,
                password_must_change INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_login_at INTEGER
            )
        """)
        columns = [
            row["name"]
            for row in connection.execute("PRAGMA table_info(portal_users)").fetchall()
        ]

        if "password_must_change" not in columns:
            connection.execute(
                "ALTER TABLE portal_users ADD COLUMN password_must_change INTEGER NOT NULL DEFAULT 0"
            )

        connection.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                attempt_key TEXT PRIMARY KEY,
                fail_count INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            )
        """)
        connection.commit()


def get_user_by_id(user_id):
    with db_connection() as connection:
        return connection.execute(
            """
            SELECT id, username, role, active, password_must_change, created_at, updated_at, last_login_at
            FROM portal_users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()


def get_user_for_login(username):
    with db_connection() as connection:
        return connection.execute(
            """
            SELECT id, username, password_hash, role, active, password_must_change
            FROM portal_users
            WHERE lower(username) = lower(?)
            """,
            (username,)
        ).fetchone()


def login_attempt_key(username):
    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    return f"{username.strip().lower()}|{ip_address}"


def get_login_lock(username):
    key = login_attempt_key(username)
    now = int(time.time())

    with db_connection() as connection:
        attempt = connection.execute(
            "SELECT fail_count, locked_until FROM login_attempts WHERE attempt_key = ?",
            (key,)
        ).fetchone()

    if not attempt or attempt["locked_until"] <= now:
        return 0

    return attempt["locked_until"] - now


def record_failed_login(username):
    key = login_attempt_key(username)
    now = int(time.time())

    with db_connection() as connection:
        attempt = connection.execute(
            "SELECT fail_count FROM login_attempts WHERE attempt_key = ?",
            (key,)
        ).fetchone()
        fail_count = (attempt["fail_count"] if attempt else 0) + 1
        locked_until = now + LOGIN_LOCK_SECONDS if fail_count >= LOGIN_MAX_ATTEMPTS else 0
        connection.execute(
            """
            INSERT INTO login_attempts (attempt_key, fail_count, locked_until, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(attempt_key) DO UPDATE SET
                fail_count = excluded.fail_count,
                locked_until = excluded.locked_until,
                updated_at = excluded.updated_at
            """,
            (key, fail_count, locked_until, now)
        )
        connection.commit()


def clear_failed_logins(username):
    with db_connection() as connection:
        connection.execute(
            "DELETE FROM login_attempts WHERE attempt_key = ?",
            (login_attempt_key(username),)
        )
        connection.commit()


def set_logged_in_user(user):
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["password_must_change"] = bool(user["password_must_change"])
    session["csrf_token"] = secrets.token_urlsafe(32)

    with db_connection() as connection:
        connection.execute(
            "UPDATE portal_users SET last_login_at = ? WHERE id = ?",
            (int(time.time()), user["id"])
        )
        connection.commit()


def csrf_token():
    token = session.get("csrf_token")

    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token

    return token


def validate_csrf():
    form_token = request.form.get("csrf_token", "")
    if not form_token or not secrets.compare_digest(form_token, session.get("csrf_token", "")):
        abort(400)


def is_admin_user():
    return g.current_user and g.current_user["role"] in ("superadmin", "admin")


def is_superadmin_user():
    return g.current_user and g.current_user["role"] == "superadmin"


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not is_admin_user():
            abort(403)
        return view(*args, **kwargs)

    return wrapped_view


def role_label(role):
    return ROLE_LABELS.get(role, role)


def format_timestamp(timestamp):
    if not timestamp:
        return ""

    return time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp))


@app.context_processor
def inject_auth_context():
    return {
        "current_user": getattr(g, "current_user", None),
        "csrf_token": csrf_token,
        "role_label": role_label,
        "format_timestamp": format_timestamp
    }


@app.before_request
def require_login():
    init_auth_db()
    g.current_user = None

    if request.endpoint in PUBLIC_ENDPOINTS:
        return None

    user_id = session.get("user_id")

    if not user_id:
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "message": "Login required."}), 401
        return redirect(url_for("login", next=request.full_path if request.query_string else request.path))

    user = get_user_by_id(user_id)

    if not user or not user["active"]:
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "message": "Login required."}), 401
        return redirect(url_for("login"))

    g.current_user = user

    if user["password_must_change"] and request.endpoint not in PASSWORD_CHANGE_ENDPOINTS:
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "message": "Password change required."}), 403
        return redirect(url_for("change_password"))

    return None


@app.before_request
def protect_post_forms():
    if request.method == "POST" and request.endpoint != "login":
        validate_csrf()


init_auth_db()

COMMON_TEMPLATE_FIELDS = [
    "action",
    "item_type",
    "id"
]

ASSET_FIELDS = [
    "asset_tag",
    "name",
    "serial",
    "model_id",
    "status_id",
    "company_id",
    "location_id",
    "supplier_id",
    "purchase_date",
    "purchase_cost",
    "order_number",
    "warranty_months",
    "notes"
]

ASSET_HELPER_FIELDS = [
    "status_name_reference",
    "company_name_reference",
    "model_name_reference",
    "location_name_reference",
    "supplier_name_reference"
]

ASSET_REQUIRED_FIELDS = {
    "asset_tag": "Asset tag",
    "model_id": "Model (model_id)",
    "status_id": "Status (status_id)"
}

LICENSE_FIELDS = [
    "name",
    "license_name",
    "product_key",
    "license_email",
    "order_number",
    "purchase_order",
    "purchase_date",
    "expiration_date",
    "termination_date",
    "min_amt",
    "purchase_cost",
    "seats",
    "company_id",
    "supplier_id",
    "manufacturer_id",
    "category_id",
    "notes"
]

LICENSE_HELPER_FIELDS = [
    "company_name_reference",
    "supplier_name_reference",
    "manufacturer_name_reference",
    "category_name_reference"
]

LICENSE_REQUIRED_FIELDS = {
    "name": "Software Name",
    "category_id": "Category Name (category_id)",
    "seats": "Seats"
}

API_FIELD_ALIASES = {
    "license": {
        "product_key": "serial"
    }
}

TEMPLATE_ROWS = {
    "asset": {
        "action": "insert",
        "item_type": "asset",
        "asset_tag": "LAPTOP-001",
        "name": "Dell Latitude 5450",
        "serial": "SN123456",
        "model_id": "305",
        "status_id": "13",
        "company_id": "1",
        "location_id": "27",
        "supplier_id": "",
        "purchase_date": "2026-06-24",
        "purchase_cost": "2500.00",
        "order_number": "PO-10001",
        "warranty_months": "36",
        "notes": "New laptop",
        "status_name_reference": "Use /references to find status_id",
        "company_name_reference": "Use /references to find company_id",
        "model_name_reference": "Use /references to find model_id",
        "location_name_reference": "Use /references to find location_id",
        "supplier_name_reference": "Use /references to find supplier_id"
    },
    "license": {
        "action": "insert",
        "item_type": "license",
        "id": "",
        "name": "Microsoft 365 Business Standard",
        "license_name": "Business Standard",
        "product_key": "",
        "license_email": "it@example.com",
        "order_number": "ORD-10001",
        "purchase_order": "PO-10001",
        "purchase_date": "2026-06-24",
        "expiration_date": "2027-06-24",
        "termination_date": "",
        "min_amt": "1",
        "purchase_cost": "120.00",
        "seats": "10",
        "company_id": "1",
        "supplier_id": "",
        "manufacturer_id": "",
        "category_id": "12",
        "notes": "Renewal",
        "company_name_reference": "Use /references to find company_id",
        "supplier_name_reference": "Use /references to find supplier_id",
        "manufacturer_name_reference": "Use /references to find manufacturer_id",
        "category_name_reference": "Use /references to find category_id"
    }
}

API_CONFIG = {
    "asset": {
        "endpoint": "/api/v1/hardware",
        "fields": ASSET_FIELDS,
        "label_field": "asset_tag"
    },
    "license": {
        "endpoint": "/api/v1/licenses",
        "fields": LICENSE_FIELDS,
        "label_field": "name"
    }
}

REFERENCE_CONFIG = {
    "status": {
        "title": "Status Labels",
        "endpoint": "/api/v1/statuslabels",
        "columns": ["id", "name", "status_type"]
    },
    "companies": {
        "title": "Companies",
        "endpoint": "/api/v1/companies",
        "columns": ["id", "name"]
    },
    "manufacturers": {
        "title": "Manufacturers",
        "endpoint": "/api/v1/manufacturers",
        "columns": ["id", "name"]
    },
    "categories": {
        "title": "Categories",
        "endpoint": "/api/v1/categories",
        "columns": ["id", "name", "category_type"]
    },
    "models": {
        "title": "Models",
        "endpoint": "/api/v1/models",
        "columns": ["id", "name", "model_number", "manufacturer", "category"]
    },
    "locations": {
        "title": "Locations",
        "endpoint": "/api/v1/locations",
        "columns": ["id", "name", "parent", "address"]
    },
    "suppliers": {
        "title": "Suppliers",
        "endpoint": "/api/v1/suppliers",
        "columns": ["id", "name"]
    },
    "users": {
        "title": "Users",
        "endpoint": "/api/v1/users",
        "columns": ["id", "name", "username", "email", "company", "location"]
    },
    "assets": {
        "title": "Existing Assets",
        "endpoint": "/api/v1/hardware",
        "columns": ["id", "asset_tag", "name", "serial", "model", "status_label", "company", "location"]
    },
    "licenses": {
        "title": "Existing Licenses",
        "endpoint": "/api/v1/licenses",
        "columns": ["id", "name", "license_name", "seats", "category", "manufacturer", "company", "expiration_date"]
    }
}

DASHBOARD_STATS = [
    ("assets", "Assets", "/api/v1/hardware"),
    ("licenses", "Licenses", "/api/v1/licenses"),
    ("models", "Models", "/api/v1/models"),
    ("manufacturers", "Manufacturers", "/api/v1/manufacturers"),
    ("companies", "Companies", "/api/v1/companies")
]


def api_get(endpoint):
    try:
        return requests.get(
            f"{SNIPEIT_URL}{endpoint}",
            headers=headers,
            verify=VERIFY_SSL,
            timeout=30
        )
    except requests.RequestException:
        return None


def get_companies():
    try:
        response = api_get("/api/v1/companies")
        return response.json()["rows"] if response else []
    except:
        return []


def get_suppliers():
    try:
        response = api_get("/api/v1/suppliers")
        return response.json()["rows"] if response else []
    except:
        return []


def get_manufacturers():
    try:
        response = api_get("/api/v1/manufacturers")
        return response.json()["rows"] if response else []
    except:
        return []


def get_categories():
    try:
        response = api_get("/api/v1/categories")
        return response.json()["rows"] if response else []
    except:
        return []


def api_request(method, endpoint, payload=None):
    try:
        return requests.request(
            method,
            f"{SNIPEIT_URL}{endpoint}",
            headers=json_headers,
            json=payload,
            verify=VERIFY_SSL,
            timeout=30
        )
    except requests.RequestException:
        return None


def with_query(endpoint, **params):
    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}{urlencode(params)}"


def api_rows(endpoint, limit=500, search=""):
    rows = []
    offset = 0

    while True:
        params = {
            "limit": limit,
            "offset": offset
        }

        if search:
            params["search"] = search

        response = api_get(with_query(endpoint, **params))

        if response is None or response.status_code != 200:
            return rows

        data = response.json()
        batch = data.get("rows", [])
        rows.extend(batch)

        if len(batch) < limit:
            return rows

        offset += limit


def api_collection(endpoint, page=1, limit=20, search=""):
    page = max(page, 1)
    limit = min(max(limit, 1), 500)
    offset = (page - 1) * limit
    params = {
        "limit": limit,
        "offset": offset
    }

    if search:
        params["search"] = search

    response = api_get(with_query(endpoint, **params))

    if response is None:
        return {
            "ok": False,
            "message": "Could not connect to OCAM API.",
            "rows": [],
            "total": 0,
            "page": page,
            "limit": limit
        }

    if response.status_code != 200:
        return {
            "ok": False,
            "message": response.text,
            "rows": [],
            "total": 0,
            "page": page,
            "limit": limit
        }

    data = response.json()

    return {
        "ok": True,
        "message": "",
        "rows": data.get("rows", []),
        "total": data.get("total", len(data.get("rows", []))),
        "page": page,
        "limit": limit
    }


def api_all_collection(endpoint, search="", limit=500):
    rows = []
    offset = 0
    total = 0

    while True:
        params = {
            "limit": limit,
            "offset": offset
        }

        if search:
            params["search"] = search

        response = api_get(with_query(endpoint, **params))

        if response is None:
            return {
                "ok": False,
                "message": "Could not connect to OCAM API.",
                "rows": [],
                "total": 0
            }

        if response.status_code != 200:
            return {
                "ok": False,
                "message": response.text,
                "rows": [],
                "total": 0
            }

        data = response.json()
        batch = data.get("rows", [])
        total = data.get("total", len(rows) + len(batch))
        rows.extend(batch)

        if len(batch) < limit or len(rows) >= total:
            return {
                "ok": True,
                "message": "",
                "rows": rows,
                "total": total
            }

        offset += limit


def nested_name(value):
    if isinstance(value, dict):
        return value.get("name") or value.get("text") or value.get("id") or ""

    return value or ""


def reference_row(row, columns):
    normalized = {}

    for column in columns:
        value = row.get(column)

        if column == "address":
            address_parts = [
                row.get("address"),
                row.get("city"),
                row.get("state"),
                row.get("country")
            ]
            normalized[column] = ", ".join(part for part in address_parts if part)
        else:
            normalized[column] = nested_name(value)

    return normalized


def normalize_reference_rows(rows, columns):
    return [
        reference_row(row, columns)
        for row in rows
    ]


def detail_title(row):
    return (
        row.get("asset_tag")
        or row.get("name")
        or row.get("license_name")
        or row.get("username")
        or row.get("id")
        or "Record"
    )


def sorted_reference_rows(rows, sort_column, sort_order):
    if not sort_column:
        return rows

    reverse = sort_order == "desc"

    def sort_key(row):
        value = row.get(sort_column)

        if value is None:
            return (1, "")

        value = str(value).strip()

        if value == "":
            return (1, "")

        try:
            return (0, float(value))
        except ValueError:
            return (0, value.casefold())

    return sorted(rows, key=sort_key, reverse=reverse)


def paged_rows(rows, page, limit):
    page = max(page, 1)
    start = (page - 1) * limit
    end = start + limit

    return rows[start:end]


def load_reference_sections(selected_type=None):
    sections = []

    for ref_type, config in REFERENCE_CONFIG.items():
        if selected_type and selected_type != ref_type:
            continue

        rows = [
            reference_row(row, config["columns"])
            for row in api_rows(config["endpoint"])
        ]

        sections.append({
            "type": ref_type,
            "title": config["title"],
            "columns": config["columns"],
            "rows": rows
        })

    return sections


def clean_value(value):
    if value is None:
        return None

    value = value.strip()

    if value == "":
        return None

    if value.lower() in ("__clear__", "null"):
        return None

    return value


def build_payload(row, fields):
    payload = {}

    for field in fields:
        value = clean_value(row.get(field))

        if value is not None:
            payload[field] = value
        elif row.get(field, "").strip().lower() in ("__clear__", "null"):
            payload[field] = None

    return payload


def api_payload(item_type, payload):
    aliases = API_FIELD_ALIASES.get(item_type, {})

    return {
        aliases.get(field, field): value
        for field, value in payload.items()
    }


def validate_import_payload(action, item_type, payload):
    if action != "insert":
        return ""

    required_fields = {
        "asset": ASSET_REQUIRED_FIELDS,
        "license": LICENSE_REQUIRED_FIELDS
    }.get(item_type, {})

    missing = []

    for field, label in required_fields.items():
        if clean_value(payload.get(field)) is None:
            missing.append(label)

    if missing:
        return f"Missing required {item_type} field(s): {', '.join(missing)}."

    return ""


def extract_error(response):
    try:
        body = response.json()
    except ValueError:
        return response.text

    if isinstance(body, dict):
        return body.get("messages") or body.get("message") or body

    return body


def process_import_row(row_number, row, dry_run=False):
    action = (row.get("action") or "").strip().lower()
    item_type = (row.get("item_type") or "").strip().lower()

    result = {
        "row": row_number,
        "action": action or "-",
        "item_type": item_type or "-",
        "target": row.get("id") or row.get("asset_tag") or row.get("name") or "-",
        "status": "Failed",
        "message": "",
        "endpoint": "",
        "payload": ""
    }

    if action not in ("insert", "update", "delete"):
        result["message"] = "Action must be insert, update, or delete."
        return result

    if item_type not in API_CONFIG:
        result["message"] = "Item type must be asset or license."
        return result

    config = API_CONFIG[item_type]
    item_id = clean_value(row.get("id"))

    if action in ("update", "delete") and not item_id:
        result["message"] = "ID is required for update and delete."
        return result

    payload = build_payload(row, config["fields"])

    validation_message = validate_import_payload(action, item_type, payload)
    if validation_message:
        result["message"] = validation_message
        return result

    if action == "insert" and not payload:
        result["message"] = "No values found to insert."
        return result

    if action == "update" and not payload:
        result["message"] = "No values found to update."
        return result

    payload = api_payload(item_type, payload)

    if action == "insert":
        endpoint = config["endpoint"]
        method = "POST"
    elif action == "update":
        endpoint = f"{config['endpoint']}/{item_id}"
        method = "PATCH"
    else:
        endpoint = f"{config['endpoint']}/{item_id}"
        method = "DELETE"

    result["endpoint"] = f"{method} {endpoint}"
    result["payload"] = payload if action != "delete" else {}

    if dry_run:
        result["status"] = "Ready"
        result["message"] = "Dry run only. No changes were sent to OCAM."
        return result

    if action == "insert":
        response = api_request("POST", config["endpoint"], payload)
    elif action == "update":
        response = api_request("PATCH", f"{config['endpoint']}/{item_id}", payload)
    else:
        response = api_request("DELETE", f"{config['endpoint']}/{item_id}")

    if response is None:
        result["message"] = "Could not connect to OCAM API. Check network access and try again."
        return result

    if response.ok:
        result["status"] = "Success"
        result["message"] = "Processed successfully."
        return result

    result["message"] = extract_error(response)
    return result


def safe_redirect_target(target):
    if target and target.startswith("/") and not target.startswith("//"):
        return target

    return url_for("index")


def random_password(length=18):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def password_error(password, confirmation=None):
    if len(password) < 10:
        return "Password must be at least 10 characters."

    if confirmation is not None and password != confirmation:
        return "Password confirmation does not match."

    return ""


def list_portal_users():
    with db_connection() as connection:
        return connection.execute(
            """
            SELECT id, username, role, active, password_must_change, created_at, updated_at, last_login_at
            FROM portal_users
            ORDER BY
                CASE role WHEN 'superadmin' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
                username COLLATE NOCASE
            """
        ).fetchall()


def allowed_role_from_form(default_role="user"):
    requested_role = request.form.get("role", default_role).strip().lower()

    if requested_role not in ("admin", "user"):
        requested_role = "user"

    if requested_role == "admin" and not is_superadmin_user():
        requested_role = "user"

    return requested_role


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        error = password_error(password, confirmation)

        if error:
            flash(error, "danger")
            return render_template("change_password.html")

        with db_connection() as connection:
            connection.execute(
                """
                UPDATE portal_users
                SET password_hash = ?, password_must_change = 0, updated_at = ?
                WHERE id = ?
                """,
                (generate_password_hash(password), int(time.time()), g.current_user["id"])
            )
            connection.commit()

        session["password_must_change"] = False
        flash("Password updated successfully.", "success")
        return redirect(url_for("index"))

    return render_template("change_password.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id") and get_user_by_id(session["user_id"]):
        return redirect(url_for("index"))

    if request.method == "POST":
        validate_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = safe_redirect_target(request.form.get("next"))
        lock_seconds = get_login_lock(username)

        if lock_seconds > 0:
            flash(f"Too many failed attempts. Please try again in {lock_seconds // 60 + 1} minute(s).", "danger")
            return render_template("login.html", username=username, next_url=next_url), 429

        user = get_user_for_login(username)

        if not user or not user["active"] or not check_password_hash(user["password_hash"], password):
            if username:
                record_failed_login(username)
            flash("Invalid username or password.", "danger")
            return render_template("login.html", username=username, next_url=next_url), 401

        clear_failed_logins(username)
        set_logged_in_user(user)
        if user["password_must_change"]:
            return redirect(url_for("change_password"))
        return redirect(next_url)

    return render_template(
        "login.html",
        username="",
        next_url=safe_redirect_target(request.args.get("next"))
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Signed out successfully.", "success")
    return redirect(url_for("login"))


@app.route("/users")
@admin_required
def users():
    return render_template(
        "users.html",
        users=list_portal_users()
    )


@app.route("/users/create", methods=["POST"])
@admin_required
def create_user():
    username = request.form.get("username", "").strip()
    role = allowed_role_from_form()

    if not username:
        flash("Username is required.", "danger")
        return redirect(url_for("users"))

    password = random_password()
    now = int(time.time())

    try:
        with db_connection() as connection:
            connection.execute(
                """
                INSERT INTO portal_users (username, password_hash, role, active, created_at, updated_at)
                VALUES (?, ?, ?, 1, ?, ?)
                """,
                (username, generate_password_hash(password), role, now, now)
            )
            connection.commit()
    except sqlite3.IntegrityError:
        flash("That username already exists.", "danger")
        return redirect(url_for("users"))

    flash(f"User {username} created. Temporary password: {password}", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/update", methods=["POST"])
@admin_required
def update_user(user_id):
    target_user = get_user_by_id(user_id)

    if not target_user:
        abort(404)

    if target_user["role"] == "superadmin":
        flash("The superadmin account is protected.", "warning")
        return redirect(url_for("users"))

    active = 1 if request.form.get("active") == "1" else 0
    role = target_user["role"]

    if is_superadmin_user():
        role = allowed_role_from_form(target_user["role"])

    if target_user["id"] == g.current_user["id"] and not active:
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for("users"))

    with db_connection() as connection:
        connection.execute(
            "UPDATE portal_users SET role = ?, active = ?, updated_at = ? WHERE id = ?",
            (role, active, int(time.time()), user_id)
        )
        connection.commit()

    flash(f"User {target_user['username']} updated.", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def reset_user_password(user_id):
    target_user = get_user_by_id(user_id)

    if not target_user:
        abort(404)

    if target_user["role"] == "superadmin" and not is_superadmin_user():
        flash("Only a superadmin can reset the superadmin password.", "danger")
        return redirect(url_for("users"))

    reset_mode = request.form.get("reset_mode", "random")
    password_must_change = 0

    if reset_mode == "custom":
        password = request.form.get("custom_password", "")
        confirmation = request.form.get("confirm_password", "")
        error = password_error(password, confirmation)

        if error:
            flash(error, "danger")
            return redirect(url_for("users"))
    elif reset_mode == "force_change":
        password = random_password()
        password_must_change = 1
    else:
        password = random_password()

    with db_connection() as connection:
        connection.execute(
            """
            UPDATE portal_users
            SET password_hash = ?, password_must_change = ?, updated_at = ?
            WHERE id = ?
            """,
            (generate_password_hash(password), password_must_change, int(time.time()), user_id)
        )
        connection.commit()

    if reset_mode == "custom":
        flash(f"Password updated for {target_user['username']}.", "success")
    elif reset_mode == "force_change":
        flash(f"Password reset for {target_user['username']}. Temporary password: {password}. User must change it at next sign-in.", "success")
    else:
        flash(f"Password reset for {target_user['username']}. New temporary password: {password}", "success")

    return redirect(url_for("users"))


@app.route("/")
def index():
    return render_template(
        "index.html",
        reference_config=REFERENCE_CONFIG
    )


@app.route("/api/dashboard-counts")
def dashboard_counts():
    stats = []

    for stat_id, label, endpoint in DASHBOARD_STATS:
        collection = api_collection(endpoint, page=1, limit=1)
        stats.append({
            "id": stat_id,
            "label": label,
            "total": collection["total"] if collection["ok"] else None,
            "ok": collection["ok"]
        })

    return jsonify({
        "stats": stats
    })


@app.route("/api/reference/<ref_type>")
def reference_api(ref_type):
    ref_type = ref_type.lower()

    if ref_type not in REFERENCE_CONFIG:
        return jsonify({
            "ok": False,
            "message": "Invalid reference type.",
            "rows": [],
            "total": 0
        }), 404

    page = request.args.get("page", "1")
    limit_arg = request.args.get("limit", "50").strip().lower()
    search = request.args.get("search", "").strip()
    sort_column = request.args.get("sort", "").strip()
    sort_order = request.args.get("order", "asc").strip().lower()

    try:
        page = int(page)
    except ValueError:
        page = 1

    config = REFERENCE_CONFIG[ref_type]
    columns = config["columns"]

    if sort_column not in columns:
        sort_column = ""

    if sort_order not in ("asc", "desc"):
        sort_order = "asc"

    if limit_arg == "max":
        collection = api_all_collection(config["endpoint"], search=search, limit=500)
        rows = normalize_reference_rows(collection["rows"], config["columns"])
        rows = sorted_reference_rows(rows, sort_column, sort_order)

        return jsonify({
            "ok": collection["ok"],
            "message": collection["message"],
            "title": config["title"],
            "type": ref_type,
            "columns": columns,
            "rows": rows,
            "total": collection["total"],
            "page": 1,
            "limit": "max",
            "sort": sort_column,
            "order": sort_order
        })

    try:
        limit = int(limit_arg)
    except ValueError:
        limit = 50

    if sort_column:
        collection = api_all_collection(config["endpoint"], search=search, limit=500)
        all_rows = normalize_reference_rows(collection["rows"], columns)
        all_rows = sorted_reference_rows(all_rows, sort_column, sort_order)
        rows = paged_rows(all_rows, page, limit)
    else:
        collection = api_collection(
            config["endpoint"],
            page=page,
            limit=limit,
            search=search
        )
        rows = normalize_reference_rows(collection["rows"], columns)

    return jsonify({
        "ok": collection["ok"],
        "message": collection["message"],
        "title": config["title"],
        "type": ref_type,
        "columns": columns,
        "rows": rows,
        "total": collection["total"],
        "page": page if sort_column else collection["page"],
        "limit": limit if sort_column else collection["limit"],
        "sort": sort_column,
        "order": sort_order
    })


@app.route("/api/reference/<ref_type>/<int:item_id>")
def reference_detail_api(ref_type, item_id):
    ref_type = ref_type.lower()

    if ref_type not in REFERENCE_CONFIG:
        return jsonify({
            "ok": False,
            "message": "Invalid reference type.",
            "record": {}
        }), 404

    config = REFERENCE_CONFIG[ref_type]
    response = api_get(f"{config['endpoint']}/{item_id}")

    if response is None:
        return jsonify({
            "ok": False,
            "message": "Could not connect to OCAM API.",
            "record": {}
        }), 503

    if response.status_code != 200:
        return jsonify({
            "ok": False,
            "message": extract_error(response),
            "record": {}
        }), response.status_code

    record = response.json()

    return jsonify({
        "ok": True,
        "message": "",
        "type": ref_type,
        "title": config["title"],
        "record_title": detail_title(record),
        "record": record
    })


@app.route("/api/global-search")
def global_search():
    term = request.args.get("q", "").strip()

    if len(term) < 2:
        return jsonify({
            "ok": True,
            "results": []
        })

    search_types = ["assets", "licenses", "models", "manufacturers", "categories", "companies", "locations", "users"]
    results = []

    for ref_type in search_types:
        config = REFERENCE_CONFIG[ref_type]
        collection = api_collection(config["endpoint"], page=1, limit=5, search=term)

        if not collection["ok"]:
            continue

        for row in normalize_reference_rows(collection["rows"], config["columns"]):
            label = row.get("name") or row.get("asset_tag") or row.get("username") or row.get("id")
            description_parts = [
                row.get("asset_tag"),
                row.get("license_name"),
                row.get("seats"),
                row.get("serial"),
                row.get("manufacturer"),
                row.get("category"),
                row.get("company"),
                row.get("location")
            ]
            description = " | ".join(str(part) for part in description_parts if part)

            results.append({
                "type": config["title"],
                "reference_type": ref_type,
                "id": row.get("id"),
                "label": label,
                "description": description
            })

    return jsonify({
        "ok": True,
        "results": results[:20]
    })


@app.route("/references")
def references():
    sections = load_reference_sections()

    return render_template(
        "references.html",
        sections=sections
    )


@app.route("/references.csv")
def download_all_references():
    output = io.StringIO()
    fieldnames = [
        "reference_type",
        "id",
        "name",
        "asset_tag",
        "serial",
        "status_type",
        "category_type",
        "model_number",
        "manufacturer",
        "category",
        "model",
        "status_label",
        "company",
        "location",
        "parent",
        "address"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for section in load_reference_sections():
        for row in section["rows"]:
            csv_row = {
                "reference_type": section["type"],
                "id": row.get("id"),
                "name": row.get("name")
            }

            for column in fieldnames:
                if column not in csv_row:
                    csv_row[column] = row.get(column, "")

            writer.writerow(csv_row)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=ocam_id_reference.csv"
        }
    )


@app.route("/references/<ref_type>.csv")
def download_reference(ref_type):
    ref_type = ref_type.lower()

    if ref_type not in REFERENCE_CONFIG:
        return "Invalid reference type.", 404

    section = load_reference_sections(ref_type)[0]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=section["columns"])
    writer.writeheader()
    writer.writerows(section["rows"])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=ocam_{ref_type}_reference.csv"
        }
    )


@app.route("/template/<item_type>")
def download_template(item_type):
    item_type = item_type.lower()

    if item_type not in API_CONFIG:
        return "Invalid template type.", 404

    helper_fields = ASSET_HELPER_FIELDS if item_type == "asset" else LICENSE_HELPER_FIELDS
    fieldnames = COMMON_TEMPLATE_FIELDS + API_CONFIG[item_type]["fields"] + helper_fields
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerow(TEMPLATE_ROWS[item_type])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=ocam_{item_type}_import_template.csv"
        }
    )


@app.route("/import", methods=["POST"])
def import_csv():
    upload = request.files.get("csv_file")
    dry_run = request.form.get("dry_run") == "1"

    if not upload or upload.filename == "":
        return render_template(
            "index.html",
            error="Please choose a CSV file to upload."
        )

    try:
        stream = io.StringIO(upload.stream.read().decode("utf-8-sig"), newline=None)
        reader = csv.DictReader(stream)
        rows = list(reader)
    except UnicodeDecodeError:
        return render_template(
            "index.html",
            error="Could not read the file. Please upload a UTF-8 CSV file."
        )

    if not reader.fieldnames:
        return render_template(
            "index.html",
            error="The CSV file is empty or missing a header row."
        )

    if not rows:
        return render_template(
            "index.html",
            error="The CSV file has a header row but no data rows to import."
        )

    results = [
        process_import_row(index, row, dry_run=dry_run)
        for index, row in enumerate(rows, start=2)
    ]

    return render_template(
        "index.html",
        results=results,
        total=len(results),
        success_count=sum(1 for result in results if result["status"] in ("Success", "Ready")),
        dry_run=dry_run
    )


@app.route("/edit/<int:license_id>")
def edit_license(license_id):

    response = api_get(
        f"/api/v1/licenses/{license_id}"
    )

    if response is None:
        return """
        <h3 style='color:red'>Could not connect to OCAM API</h3>
        <p>The app could not reach ocam.ocsports.com.my from this server.</p>
        <a href='/'>Back</a>
        """, 503

    if response.status_code != 200:
        return response.text

    license_data = response.json()

    print("EXPIRATION DATE:")
    print(license_data.get("expiration_date"))

    print("PURCHASE DATE:")
    print(license_data.get("purchase_date"))

    return render_template(
        "edit_license.html",
        license=license_data,
        companies=get_companies(),
        suppliers=get_suppliers(),
        manufacturers=get_manufacturers(),
        categories=get_categories()
    )


@app.route("/update/<int:license_id>", methods=["POST"])
def update_license(license_id):

    payload = {
        "name": request.form.get("name"),
        "license_name": request.form.get("license_name"),
        "serial": request.form.get("product_key"),
        "license_email": request.form.get("license_email"),
        "order_number": request.form.get("order_number"),
        "purchase_order": request.form.get("purchase_order"),
        "purchase_date": request.form.get("purchase_date"),
        "expiration_date": request.form.get("expiration_date"),
        "termination_date": request.form.get("termination_date"),
        "min_amt": request.form.get("min_amt"),
        "purchase_cost": request.form.get("purchase_cost"),
        "seats": request.form.get("seats"),
        "notes": request.form.get("notes"),
        "company_id": request.form.get("company_id"),
        "supplier_id": request.form.get("supplier_id"),
        "manufacturer_id": request.form.get("manufacturer_id"),
        "category_id": request.form.get("category_id")
    }

    # Allow fields to be cleared

    for key in payload:

        if payload[key] == "":
            payload[key] = None


    # Convert dropdown empty values to null

    for key in [
        "company_id",
        "supplier_id",
        "manufacturer_id",
        "category_id"
    ]:

        if payload.get(key) in ("", None):
            payload[key] = None

    response = requests.patch(
        f"{SNIPEIT_URL}/api/v1/licenses/{license_id}",
        headers=json_headers,
        json=payload,
        verify=VERIFY_SSL,
        timeout=30
    )

    if response.status_code == 200:

        return f"""
        <h3 style='color:green'>
        ✓ License updated successfully
        </h3>

        <pre>{response.text}</pre>

        <a href='/edit/{license_id}'>
        Back to License
        </a>
        """

    return f"""
    <h3 style='color:red'>
    ✗ Update Failed
    </h3>

    <pre>{response.text}</pre>

    <a href='/edit/{license_id}'>
    Back to License
    </a>
    """


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False
    )
