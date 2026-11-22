from fastapi import FastAPI, HTTPException, Header
from fastapi.security import HTTPBearer
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from pathlib import Path
from datetime import datetime, timedelta

from pydantic import BaseModel

import sqlite3
import hashlib
import secrets
import socket


from response_executor import execute_response_action


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="ZeroGuard API",
    description="AI-Based Zero-Day Attack Detection Using Graph Neural Networks",
    version="1.0.0",
)

# ============================================================
# SWAGGER AUTHENTICATION
# ============================================================

security = HTTPBearer(
    scheme_name="BearerAuth",
    description="Enter your ZeroGuard token as: Bearer <token>",
)

# ============================================================
# CUSTOM OPENAPI / SWAGGER AUTHENTICATION
# ============================================================

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="ZeroGuard API",
        version="1.0.0",
        description="AI-Based Zero-Day Attack Detection Using Graph Neural Networks",
        routes=app.routes,
    )

    openapi_schema.setdefault("components", {})
    openapi_schema["components"].setdefault("securitySchemes", {})

    openapi_schema["components"]["securitySchemes"]["BearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "Token",
        "description": "Enter your ZeroGuard token.",
    }

    # Apply Bearer authentication to routes that already
    # declare an Authorization header.
    for path_item in openapi_schema.get("paths", {}).values():
        for method, operation in path_item.items():

            if method.lower() not in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "options",
                "head",
            }:
                continue

            if not isinstance(operation, dict):
                continue

            parameters = operation.get("parameters", [])

            has_authorization_header = any(
                parameter.get("name") == "authorization"
                and parameter.get("in") == "header"
                for parameter in parameters
            )

            if has_authorization_header:
                operation["security"] = [
                    {
                        "BearerAuth": []
                    }
                ]

    app.openapi_schema = openapi_schema

    return app.openapi_schema


app.openapi = custom_openapi

# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIST = BASE_DIR.parent / "frontend" / "dist"
DB_PATH = BASE_DIR / "zeroguard.db"


# ============================================================
# PRODUCTION FRONTEND
# ============================================================

if FRONTEND_DIST.exists():
    assets_dir = FRONTEND_DIST / "assets"

    if assets_dir.exists():
        app.mount(
            "/assets",
            StaticFiles(directory=assets_dir),
            name="assets",
        )


@app.get("/favicon.svg", include_in_schema=False)
def serve_favicon():

    favicon_file = FRONTEND_DIST / "favicon.svg"

    if not favicon_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Favicon not found",
        )

    return FileResponse(favicon_file)


@app.get("/", include_in_schema=False)
def serve_frontend():

    index_file = FRONTEND_DIST / "index.html"

    if not index_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Frontend build not found. Run: npm run build",
        )

    return FileResponse(index_file)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DATABASE
# ============================================================

def get_connection():

    connection = sqlite3.connect(
        str(DB_PATH),
        timeout=30,
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


# ============================================================
# PASSWORD HELPERS
# ============================================================

def hash_password(password: str) -> str:

    return hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


def verify_password(
    password: str,
    password_hash: str,
) -> bool:

    return hash_password(password) == password_hash


# ============================================================
# DATABASE COLUMN HELPER
# ============================================================

def ensure_column(
    connection,
    table_name: str,
    column_name: str,
    column_definition: str,
):

    columns = [
        row["name"]
        for row in connection.execute(
            f"PRAGMA table_info({table_name})"
        ).fetchall()
    ]

    if column_name not in columns:

        connection.execute(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name} {column_definition}
            """
        )

        print(
            f"Database migration: added "
            f"{table_name}.{column_name}"
        )


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_database():

    connection = get_connection()

    try:

        # ====================================================
        # DEVICES
        # ====================================================

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                device_name TEXT,
                ip_address TEXT,
                mac_address TEXT,
                device_type TEXT,
                operating_system TEXT,
                risk_level TEXT DEFAULT 'low',
                status TEXT DEFAULT 'online',
                created_at TEXT,
                first_seen TEXT,
                last_seen TEXT
            )
            """
        )

        device_columns = {
            "name": "TEXT",
            "device_name": "TEXT",
            "ip_address": "TEXT",
            "mac_address": "TEXT",
            "device_type": "TEXT",
            "operating_system": "TEXT",
            "risk_level": "TEXT DEFAULT 'low'",
            "status": "TEXT DEFAULT 'online'",
            "created_at": "TEXT",
            "first_seen": "TEXT",
            "last_seen": "TEXT",
        }

        for column, definition in device_columns.items():
            ensure_column(
                connection,
                "devices",
                column,
                definition,
            )

        # ====================================================
        # NETWORK EVENTS
        # ====================================================

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                protocol TEXT,
                port INTEGER,
                event_type TEXT,
                risk TEXT,
                timestamp TEXT,
                threat_id INTEGER,
                device_id INTEGER
            )
            """
        )

        network_columns = {
            "source_ip": "TEXT",
            "destination_ip": "TEXT",
            "protocol": "TEXT",
            "port": "INTEGER",
            "event_type": "TEXT",
            "risk": "TEXT",
            "timestamp": "TEXT",
            "threat_id": "INTEGER",
            "device_id": "INTEGER",
        }

        for column, definition in network_columns.items():
            ensure_column(
                connection,
                "network_events",
                column,
                definition,
            )

        # ====================================================
        # AGENTS
        # ====================================================

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                agent_name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'active',
                last_heartbeat TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (device_id)
                    REFERENCES devices(id)
                    ON DELETE CASCADE
            )
            """
        )

        # ====================================================
        # USERS
        # ====================================================

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT,
                role TEXT DEFAULT 'user',
                status TEXT DEFAULT 'active',
                created_at TEXT,
                last_login TEXT
            )
            """
        )

        user_columns = {
            "name": "TEXT",
            "role": "TEXT DEFAULT 'user'",
            "status": "TEXT DEFAULT 'active'",
            "created_at": "TEXT",
            "last_login": "TEXT",
        }

        for column, definition in user_columns.items():
            ensure_column(
                connection,
                "users",
                column,
                definition,
            )

        # ====================================================
        # DEVICE PAIRINGS
        # ====================================================

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS device_pairings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT NOT NULL UNIQUE,
                created_by INTEGER,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                FOREIGN KEY (created_by)
                    REFERENCES users(id)
                    ON DELETE SET NULL
            )
            """
        )

        # ====================================================
        # THREATS
        # ====================================================

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_type TEXT,
                severity TEXT,
                confidence REAL,
                anomaly_score REAL,
                risk_score REAL,
                baseline_z_score REAL,
                source_ip TEXT,
                destination_ip TEXT,
                description TEXT,
                status TEXT DEFAULT 'active',
                detected_at TEXT
            )
            """
        )

        threat_columns = {
            "threat_type": "TEXT",
            "severity": "TEXT",
            "confidence": "REAL",
            "anomaly_score": "REAL",
            "risk_score": "REAL",
            "baseline_z_score": "REAL",
            "source_ip": "TEXT",
            "destination_ip": "TEXT",
            "description": "TEXT",
            "status": "TEXT DEFAULT 'active'",
            "detected_at": "TEXT",
        }

        for column, definition in threat_columns.items():
            ensure_column(
                connection,
                "threats",
                column,
                definition,
            )

        # ====================================================
        # INCIDENTS
        # ====================================================

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                description TEXT,
                severity TEXT,
                status TEXT DEFAULT 'open',
                threat_id INTEGER,
                created_at TEXT,
                updated_at TEXT
            )
            """
        )

        incident_columns = {
            "title": "TEXT",
            "description": "TEXT",
            "severity": "TEXT",
            "status": "TEXT DEFAULT 'open'",
            "threat_id": "INTEGER",
            "created_at": "TEXT",
            "updated_at": "TEXT",
        }

        for column, definition in incident_columns.items():
            ensure_column(
                connection,
                "incidents",
                column,
                definition,
            )

        # ====================================================
        # RESPONSE ACTIONS
        # ====================================================

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS response_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                action_type TEXT,
                target TEXT,
                reason TEXT,
                status TEXT DEFAULT 'pending',
                threat_id INTEGER,
                created_at TEXT
            )
            """
        )

        response_columns = {
            "incident_id": "INTEGER",
            "action_type": "TEXT",
            "target": "TEXT",
            "reason": "TEXT",
            "status": "TEXT DEFAULT 'pending'",
            "threat_id": "INTEGER",
            "created_at": "TEXT",
        }

        for column, definition in response_columns.items():
            ensure_column(
                connection,
                "response_actions",
                column,
                definition,
            )

        # ====================================================
        # SESSIONS
        # ====================================================

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT,
                FOREIGN KEY(user_id)
                    REFERENCES users(id)
            )
            """
        )

        # ====================================================
        # NORMALIZE DEVICES
        # ====================================================

        connection.execute(
            """
            UPDATE devices
            SET device_name = name
            WHERE
                (device_name IS NULL OR device_name = '')
                AND name IS NOT NULL
            """
        )

        connection.execute(
            """
            UPDATE devices
            SET name = device_name
            WHERE
                (name IS NULL OR name = '')
                AND device_name IS NOT NULL
            """
        )

        connection.execute(
            """
            UPDATE devices
            SET risk_level = 'low'
            WHERE
                risk_level IS NULL
                OR risk_level = ''
            """
        )

        connection.execute(
            """
            UPDATE devices
            SET status = 'online'
            WHERE
                status IS NULL
                OR status = ''
            """
        )

        # ====================================================
        # NORMALIZE USERS
        # ====================================================

        connection.execute(
            """
            UPDATE users
            SET name = username
            WHERE
                name IS NULL
                OR name = ''
            """
        )

        connection.execute(
            """
            UPDATE users
            SET status = 'active'
            WHERE
                status IS NULL
                OR status = ''
            """
        )

        connection.execute(
            """
            UPDATE users
            SET role = 'user'
            WHERE
                role IS NULL
                OR role = ''
            """
        )

        # ====================================================
        # DEFAULT ADMIN
        # ====================================================

        admin = connection.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            """,
            ("admin",),
        ).fetchone()

        if admin is None:

            now = datetime.now().isoformat()

            connection.execute(
                """
                INSERT INTO users
                (
                    username,
                    email,
                    password_hash,
                    name,
                    role,
                    status,
                    created_at,
                    last_login
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "admin",
                    "admin@zeroguard.local",
                    hash_password("Admin@123"),
                    "Administrator",
                    "admin",
                    "active",
                    now,
                    None,
                ),
            )

            print()
            print("==========================================")
            print("Default ZeroGuard administrator created")
            print("Username : admin")
            print("Email    : admin@zeroguard.local")
            print("Password : Admin@123")
            print("==========================================")
            print()

        connection.commit()

        print("Database initialized")
        print(f"Database path: {DB_PATH}")

    finally:
        connection.close()


# ============================================================
# LOCAL NETWORK HELPERS
# ============================================================

def get_local_ip_addresses() -> list[str]:

    local_ips = set()

    try:

        hostname = socket.gethostname()

        try:

            addresses = socket.gethostbyname_ex(
                hostname
            )[2]

            for address in addresses:

                if address:
                    local_ips.add(str(address))

        except Exception:
            pass

    except Exception:
        pass

    local_ips.add("127.0.0.1")

    try:

        import psutil

        for interface_addresses in psutil.net_if_addrs().values():

            for address in interface_addresses:

                ip_address = getattr(
                    address,
                    "address",
                    None,
                )

                if not ip_address:
                    continue

                if ":" in ip_address:
                    continue

                local_ips.add(str(ip_address))

    except Exception as error:

        print(
            "Unable to enumerate local interface addresses:",
            error,
        )

    return sorted(local_ips)


# ============================================================
# AUTHENTICATION
# ============================================================

def create_session(user_id: int) -> str:

    token = secrets.token_hex(32)

    created_at = datetime.now()
    expires_at = created_at + timedelta(days=7)

    connection = get_connection()

    try:

        connection.execute(
            """
            INSERT INTO sessions
            (
                user_id,
                token,
                expires_at,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                user_id,
                token,
                expires_at.isoformat(),
                created_at.isoformat(),
            ),
        )

        connection.commit()

    finally:
        connection.close()

    return token


def get_current_user(
    authorization: str | None,
):

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization header required",
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization format",
        )

    token = authorization.replace(
        "Bearer ",
        "",
        1,
    ).strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Authentication token is missing",
        )

    connection = get_connection()

    try:

        row = connection.execute(
            """
            SELECT
                users.id,
                users.username,
                users.email,
                users.name,
                users.role,
                users.status,
                sessions.token,
                sessions.expires_at
            FROM sessions
            JOIN users
                ON users.id = sessions.user_id
            WHERE sessions.token = ?
            """,
            (token,),
        ).fetchone()

    finally:
        connection.close()

    if row is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid session",
        )

    if row["status"] != "active":
        raise HTTPException(
            status_code=403,
            detail="Account is inactive",
        )

    try:

        expires_at = datetime.fromisoformat(
            row["expires_at"]
        )

    except Exception:

        raise HTTPException(
            status_code=401,
            detail="Invalid session expiry",
        )

    if expires_at < datetime.now():

        raise HTTPException(
            status_code=401,
            detail="Session expired",
        )

    return row


# ============================================================
# ADMIN AUTHORIZATION
# ============================================================

def get_current_admin(
    authorization: str | None,
):

    user = get_current_user(
        authorization
    )

    normalized_role = str(
        user["role"] or ""
    ).strip().lower()

    if normalized_role not in {
        "admin",
        "administrator",
    }:

        raise HTTPException(
            status_code=403,
            detail="Administrator access required",
        )

    if user["status"] != "active":

        raise HTTPException(
            status_code=403,
            detail="Administrator account is inactive",
        )

    return user


# ============================================================
# PYDANTIC MODELS
# ============================================================

class SignupRequest(BaseModel):
    username: str
    email: str
    password: str
    name: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class IncidentRequest(BaseModel):
    title: str
    description: str
    severity: str
    threat_id: int | None = None


class ResponseActionRequest(BaseModel):
    action_type: str
    target: str
    reason: str
    threat_id: int | None = None
    incident_id: int | None = None


class DeviceRegistrationRequest(BaseModel):
    device_name: str
    mac_address: str
    device_type: str = "endpoint"
    ip_address: str


class AgentRegistrationRequest(BaseModel):
    agent_name: str
    device_name: str
    mac_address: str
    device_type: str = "Computer"
    ip_address: str
    operating_system: str | None = None


class DevicePairingRequest(BaseModel):
    pairing_code: str


class DevicePairingRegistrationRequest(BaseModel):
    pairing_code: str
    agent_name: str
    device_name: str
    mac_address: str = ""
    device_type: str = "Computer"
    ip_address: str = ""
    operating_system: str | None = None
    device_identifier: str = ""


class AgentNetworkEvent(BaseModel):
    source_ip: str
    destination_ip: str = ""
    protocol: str | None = None
    port: int | None = None
    event_type: str | None = None
    risk: str = "low"
    timestamp: str | None = None


class AgentNetworkEventsRequest(BaseModel):
    events: list[AgentNetworkEvent]


class UserRoleUpdateRequest(BaseModel):
    role: str


class UserStatusUpdateRequest(BaseModel):
    status: str


class ThreatEventLinkRequest(BaseModel):
    event_ids: list[int] = []


# ============================================================
# GNN
# ============================================================

try:

    from gnn_detector import analyze_database

    GNN_AVAILABLE = True
    GNN_IMPORT_ERROR = None

except Exception as error:

    GNN_AVAILABLE = False
    analyze_database = None
    GNN_IMPORT_ERROR = error

    print("GNN detector unavailable:")
    print(error)


# ============================================================
# RISK CORRELATOR
# ============================================================

try:

    from risk_correlator import correlate_risk

    RISK_CORRELATOR_AVAILABLE = True
    RISK_CORRELATOR_IMPORT_ERROR = None

except Exception as error:

    RISK_CORRELATOR_AVAILABLE = False
    correlate_risk = None
    RISK_CORRELATOR_IMPORT_ERROR = error

    print("Risk Correlator unavailable:")
    print(error)


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup_event():

    initialize_database()

    if GNN_AVAILABLE:
        print("GNN API integration: OK")
    else:
        print("GNN API integration: FAILED")

    if RISK_CORRELATOR_AVAILABLE:
        print("Risk Correlator integration: OK")
    else:
        print("Risk Correlator integration: FAILED")


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/api/health")
def api_health():

    return {
        "status": "healthy",
        "database": str(DB_PATH),
        "database_exists": DB_PATH.exists(),
        "gnn_available": GNN_AVAILABLE,
        "risk_correlator_available": RISK_CORRELATOR_AVAILABLE,
        "timestamp": datetime.now().isoformat(),
    }


# ============================================================
# API STATUS
# ============================================================

@app.get("/api/status")
def api_status(
    authorization: str | None = Header(default=None),
):

    get_current_user(authorization)

    connection = get_connection()

    try:

        devices = connection.execute(
            "SELECT COUNT(*) AS count FROM devices"
        ).fetchone()["count"]

        network_events = connection.execute(
            "SELECT COUNT(*) AS count FROM network_events"
        ).fetchone()["count"]

        threats = connection.execute(
            "SELECT COUNT(*) AS count FROM threats"
        ).fetchone()["count"]

        threats_blocked = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM threats
            WHERE status IN ('blocked', 'resolved')
            """
        ).fetchone()["count"]

        agents = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM agents
            WHERE status = 'active'
            """
        ).fetchone()["count"]

        return {
            "status": "protected",
            "devices": devices,
            "network_events": network_events,
            "threats": threats,
            "threats_blocked": threats_blocked,
            "active_agents": agents,
            "gnn_available": GNN_AVAILABLE,
            "risk_correlator_available": RISK_CORRELATOR_AVAILABLE,
            "timestamp": datetime.now().isoformat(),
        }

    finally:
        connection.close()


# ============================================================
# DATABASE SUMMARY
# ============================================================

@app.get("/api/database/summary")
def database_summary(
    authorization: str | None = Header(default=None),
):

    get_current_user(authorization)

    connection = get_connection()

    try:

        tables = [
            "devices",
            "network_events",
            "agents",
            "threats",
            "incidents",
            "response_actions",
            "users",
            "sessions",
        ]

        result = {}

        for table in tables:

            result[table] = connection.execute(
                f"""
                SELECT COUNT(*) AS count
                FROM {table}
                """
            ).fetchone()["count"]

        return result

    finally:
        connection.close()


# ============================================================
# SIGNUP
# ============================================================

@app.post("/api/auth/signup")
def signup(request: SignupRequest):

    username = request.username.strip()
    email = request.email.strip().lower()

    if not username:

        raise HTTPException(
            status_code=400,
            detail="Username is required",
        )

    if not email:

        raise HTTPException(
            status_code=400,
            detail="Email is required",
        )

    if len(request.password) < 6:

        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 6 characters",
        )

    connection = get_connection()

    try:

        existing = connection.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
               OR email = ?
            """,
            (
                username,
                email,
            ),
        ).fetchone()

        if existing:

            raise HTTPException(
                status_code=409,
                detail="Username or email already exists",
            )

        now = datetime.now().isoformat()

        name = (
            request.name.strip()
            if request.name
            else username
        )

        cursor = connection.execute(
            """
            INSERT INTO users
            (
                username,
                email,
                password_hash,
                name,
                role,
                status,
                created_at,
                last_login
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                email,
                hash_password(request.password),
                name,
                "user",
                "active",
                now,
                None,
            ),
        )

        connection.commit()

        user_id = cursor.lastrowid

        token = create_session(user_id)

        return {
            "message": "Account created successfully",
            "token": token,
            "user": {
                "id": user_id,
                "username": username,
                "email": email,
                "name": name,
                "role": "user",
            },
        }

    finally:
        connection.close()


# ============================================================
# LOGIN
# ============================================================

@app.post("/api/auth/login")
def login(request: LoginRequest):

    connection = get_connection()

    try:

        username_or_email = request.username.strip()

        user = connection.execute(
            """
            SELECT
                id,
                username,
                email,
                password_hash,
                name,
                role,
                status
            FROM users
            WHERE username = ?
               OR email = ?
            """,
            (
                username_or_email,
                username_or_email,
            ),
        ).fetchone()

        if user is None:

            raise HTTPException(
                status_code=401,
                detail="Invalid username or password",
            )

        if user["status"] != "active":

            raise HTTPException(
                status_code=403,
                detail="Account is inactive",
            )

        if not verify_password(
            request.password,
            user["password_hash"],
        ):

            raise HTTPException(
                status_code=401,
                detail="Invalid username or password",
            )

        now = datetime.now().isoformat()

        connection.execute(
            """
            UPDATE users
            SET last_login = ?
            WHERE id = ?
            """,
            (
                now,
                user["id"],
            ),
        )

        connection.commit()

        token = create_session(
            user["id"]
        )

        return {
            "message": "Login successful",
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "name": user["name"],
                "role": user["role"],
            },
        }

    finally:
        connection.close()


# ============================================================
# CURRENT USER
# ============================================================

@app.get("/api/auth/me")
def me(
    authorization: str | None = Header(default=None),
):

    user = get_current_user(
        authorization
    )

    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
    }


# ============================================================
# LOGOUT
# ============================================================

@app.post("/api/auth/logout")
def logout(
    authorization: str | None = Header(default=None),
):

    if not authorization:

        return {
            "message": "Logged out",
        }

    if authorization.startswith("Bearer "):

        token = authorization.replace(
            "Bearer ",
            "",
            1,
        ).strip()

        connection = get_connection()

        try:

            connection.execute(
                """
                DELETE FROM sessions
                WHERE token = ?
                """,
                (token,),
            )

            connection.commit()

        finally:
            connection.close()

    return {
        "message": "Logged out successfully",
    }


# ============================================================
# ADMIN USERS
# ============================================================

@app.get("/api/admin/users")
def get_admin_users(
    authorization: str | None = Header(default=None),
):

    admin = get_current_admin(
        authorization
    )

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT
                id,
                name,
                username,
                email,
                role,
                status,
                created_at,
                last_login
            FROM users
            ORDER BY id ASC
            """
        ).fetchall()

        return {
            "users": [
                dict(row)
                for row in rows
            ],
            "total": len(rows),
            "admin_id": admin["id"],
        }

    finally:
        connection.close()


# ============================================================
# CHANGE USER ROLE
# ============================================================

@app.patch("/api/admin/users/{user_id}/role")
def update_user_role(
    user_id: int,
    request: UserRoleUpdateRequest,
    authorization: str | None = Header(default=None),
):

    admin = get_current_admin(
        authorization
    )

    new_role = request.role.strip().lower()

    if new_role not in ["user", "admin"]:

        raise HTTPException(
            status_code=400,
            detail="Invalid role. Allowed roles: user, admin",
        )

    if user_id == admin["id"]:

        raise HTTPException(
            status_code=400,
            detail="You cannot change your own administrator role.",
        )

    connection = get_connection()

    try:

        user = connection.execute(
            """
            SELECT
                id,
                username,
                email,
                name,
                role,
                status
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

        if user is None:

            raise HTTPException(
                status_code=404,
                detail="User not found",
            )

        connection.execute(
            """
            UPDATE users
            SET role = ?
            WHERE id = ?
            """,
            (
                new_role,
                user_id,
            ),
        )

        connection.commit()

        return {
            "message": "User role updated successfully",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "name": user["name"],
                "role": new_role,
                "status": user["status"],
            },
        }

    finally:
        connection.close()


# ============================================================
# ACTIVATE / DEACTIVATE USER
# ============================================================

@app.patch("/api/admin/users/{user_id}/status")
def update_user_status(
    user_id: int,
    request: UserStatusUpdateRequest,
    authorization: str | None = Header(default=None),
):

    admin = get_current_admin(
        authorization
    )

    new_status = request.status.strip().lower()

    if new_status not in ["active", "inactive"]:

        raise HTTPException(
            status_code=400,
            detail="Invalid status. Allowed statuses: active, inactive",
        )

    if user_id == admin["id"]:

        raise HTTPException(
            status_code=400,
            detail="You cannot deactivate your own administrator account.",
        )

    connection = get_connection()

    try:

        user = connection.execute(
            """
            SELECT
                id,
                username,
                email,
                name,
                role,
                status
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

        if user is None:

            raise HTTPException(
                status_code=404,
                detail="User not found",
            )

        connection.execute(
            """
            UPDATE users
            SET status = ?
            WHERE id = ?
            """,
            (
                new_status,
                user_id,
            ),
        )

        if new_status == "inactive":

            connection.execute(
                """
                DELETE FROM sessions
                WHERE user_id = ?
                """,
                (user_id,),
            )

        connection.commit()

        return {
            "message": "User status updated successfully",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "name": user["name"],
                "role": user["role"],
                "status": new_status,
            },
        }

    finally:
        connection.close()


# ============================================================
# DELETE USER
# ============================================================

@app.delete("/api/admin/users/{user_id}")
def delete_admin_user(
    user_id: int,
    authorization: str | None = Header(default=None),
):

    admin = get_current_admin(
        authorization
    )

    if user_id == admin["id"]:

        raise HTTPException(
            status_code=400,
            detail="You cannot delete your own account.",
        )

    connection = get_connection()

    try:

        user = connection.execute(
            """
            SELECT
                id,
                username,
                email,
                name,
                role
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

        if user is None:

            raise HTTPException(
                status_code=404,
                detail="User not found",
            )

        connection.execute(
            """
            DELETE FROM sessions
            WHERE user_id = ?
            """,
            (user_id,),
        )

        connection.execute(
            """
            DELETE FROM users
            WHERE id = ?
            """,
            (user_id,),
        )

        connection.commit()

        return {
            "message": "User deleted successfully",
            "deleted_user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "name": user["name"],
                "role": user["role"],
            },
        }

    finally:
        connection.close()


# ============================================================
# DEVICES
# ============================================================

@app.post("/api/devices/register")
def register_device(
    request: DeviceRegistrationRequest,
    authorization: str | None = Header(default=None),
):

    get_current_user(authorization)

    connection = get_connection()

    try:

        now = datetime.now().isoformat()

        existing = connection.execute(
            """
            SELECT *
            FROM devices
            WHERE mac_address = ?
            LIMIT 1
            """,
            (request.mac_address,),
        ).fetchone()

        if not existing:

            existing = connection.execute(
                """
                SELECT *
                FROM devices
                WHERE ip_address = ?
                LIMIT 1
                """,
                (request.ip_address,),
            ).fetchone()

        if existing:

            connection.execute(
                """
                UPDATE devices
                SET
                    name = ?,
                    device_name = ?,
                    mac_address = ?,
                    device_type = ?,
                    ip_address = ?,
                    status = 'online',
                    last_seen = ?
                WHERE id = ?
                """,
                (
                    request.device_name,
                    request.device_name,
                    request.mac_address,
                    request.device_type,
                    request.ip_address,
                    now,
                    existing["id"],
                ),
            )

            connection.commit()

            updated = connection.execute(
                """
                SELECT *
                FROM devices
                WHERE id = ?
                LIMIT 1
                """,
                (existing["id"],),
            ).fetchone()

            return {
                "message": "Device updated successfully",
                "registered": True,
                "created": False,
                "device": dict(updated),
            }

        cursor = connection.execute(
            """
            INSERT INTO devices
            (
                name,
                device_name,
                mac_address,
                device_type,
                ip_address,
                risk_level,
                status,
                created_at,
                first_seen,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.device_name,
                request.device_name,
                request.mac_address,
                request.device_type,
                request.ip_address,
                "low",
                "online",
                now,
                now,
                now,
            ),
        )

        connection.commit()

        device = connection.execute(
            """
            SELECT *
            FROM devices
            WHERE id = ?
            LIMIT 1
            """,
            (cursor.lastrowid,),
        ).fetchone()

        return {
            "message": "Device registered successfully",
            "registered": True,
            "created": True,
            "device": dict(device),
        }

    finally:
        connection.close()


# ============================================================
# DEVICE PAIRING
# ============================================================

@app.post("/api/device-pairings")
def create_device_pairing(
    authorization: str | None = Header(default=None),
):

    admin = get_current_admin(
        authorization
    )

    connection = get_connection()

    try:

        now = datetime.now()
        now_iso = now.isoformat()

        connection.execute(
            """
            UPDATE device_pairings
            SET status = 'expired'
            WHERE status = 'active'
              AND expires_at <= ?
            """,
            (now_iso,),
        )

        pairing_code = secrets.token_urlsafe(6).upper()

        code_hash = hashlib.sha256(
            pairing_code.encode("utf-8")
        ).hexdigest()

        expires_at = (
            now + timedelta(minutes=10)
        ).isoformat()

        connection.execute(
            """
            INSERT INTO device_pairings
            (
                code_hash,
                created_by,
                created_at,
                expires_at,
                status
            )
            VALUES (?, ?, ?, ?, 'active')
            """,
            (
                code_hash,
                admin["id"],
                now_iso,
                expires_at,
            ),
        )

        connection.commit()

        return {
            "message": "Device pairing code generated",
            "pairing_code": pairing_code,
            "expires_at": expires_at,
            "expires_in_minutes": 10,
        }

    finally:
        connection.close()


# ============================================================
# DEVICE PAIRING REGISTRATION
# ============================================================

@app.post("/api/device-pairings/register")
def register_device_with_pairing(
    request: DevicePairingRegistrationRequest,
):
    """
    Register a ZeroGuard device using a one-time pairing code.

    Supports:
        - Windows/Linux/macOS agents with a real MAC address
        - Android devices without exposing their real Wi-Fi MAC address

    Android uses a stable device_identifier supplied by the app.

    Flow:
        Admin generates pairing code
        -> device submits pairing code
        -> code is validated
        -> existing device is found OR created
        -> previous agents are disabled
        -> new agent is created
        -> new agent token is returned once
    """

    connection = get_connection()

    try:

        # ====================================================
        # BASIC INPUT
        # ====================================================

        pairing_code = (
            request.pairing_code.strip().upper()
            if request.pairing_code
            else ""
        )

        device_name = (
            request.device_name.strip()
            if request.device_name
            else ""
        )

        agent_name = (
            request.agent_name.strip()
            if request.agent_name
            else ""
        )

        device_type = (
            request.device_type.strip()
            if request.device_type
            else "Computer"
        )

        operating_system = (
            request.operating_system.strip()
            if request.operating_system
            else None
        )

        mac_address = (
            request.mac_address.strip()
            if request.mac_address
            else ""
        )

        ip_address = (
            request.ip_address.strip()
            if request.ip_address
            else ""
        )

        device_identifier = (
            request.device_identifier.strip()
            if request.device_identifier
            else ""
        )

        # ====================================================
        # BASIC VALIDATION
        # ====================================================

        if not pairing_code:
            raise HTTPException(
                status_code=400,
                detail="Pairing code is required",
            )

        if not device_name:
            raise HTTPException(
                status_code=400,
                detail="Device name is required",
            )

        if not agent_name:
            raise HTTPException(
                status_code=400,
                detail="Agent name is required",
            )

        # ====================================================
        # DETECT ANDROID
        # ====================================================

        is_android = (
            device_type.lower()
            in {
                "android",
                "android phone",
                "android device",
            }
            or (
                operating_system is not None
                and "android" in operating_system.lower()
            )
        )

        # ====================================================
        # ANDROID IDENTIFIER
        # ====================================================

        if is_android:

            # Android should provide a stable application/device
            # identifier. We use it as a ZeroGuard-specific
            # identifier and do NOT expose the real Wi-Fi MAC.
            if device_identifier:

                android_identifier = (
                    "android-" + device_identifier
                )

                # Use the stable identifier as the internal
                # ZeroGuard MAC-like identifier.
                mac_address = android_identifier

            elif not mac_address:

                # Backward compatibility for an already-created
                # Android device.
                #
                # This value is only a fallback. New Android
                # clients should always send device_identifier.
                mac_address = (
                    "android-"
                    + secrets.token_hex(16)
                )

        else:

            # Windows/Linux/macOS agents still require their
            # real MAC address.
            if not mac_address:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "MAC address is required "
                        "for non-Android devices"
                    ),
                )

        # ====================================================
        # IP ADDRESS
        # ====================================================

        if not ip_address:

            if is_android:

                # SQLite has a UNIQUE constraint on
                # devices.ip_address.
                #
                # Do NOT use "unknown" for a new Android
                # device because multiple Android devices
                # would collide.
                ip_address = (
                    "android-ip-"
                    + secrets.token_hex(8)
                )

            else:

                ip_address = "unknown"

        # ====================================================
        # HASH PAIRING CODE
        # ====================================================

        code_hash = hashlib.sha256(
            pairing_code.encode("utf-8")
        ).hexdigest()

        now = datetime.now()
        now_iso = now.isoformat()

        # ====================================================
        # FIND ACTIVE PAIRING
        # ====================================================

        pairing = connection.execute(
            """
            SELECT *
            FROM device_pairings
            WHERE code_hash = ?
              AND status = 'active'
            LIMIT 1
            """,
            (code_hash,),
        ).fetchone()

        if pairing is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid or already used pairing code",
            )

        # ====================================================
        # CHECK EXPIRATION
        # ====================================================

        try:

            expires_at = datetime.fromisoformat(
                pairing["expires_at"]
            )

        except (ValueError, TypeError):

            connection.execute(
                """
                UPDATE device_pairings
                SET status = 'expired'
                WHERE id = ?
                """,
                (pairing["id"],),
            )

            connection.commit()

            raise HTTPException(
                status_code=401,
                detail="Pairing code has expired",
            )

        if expires_at <= now:

            connection.execute(
                """
                UPDATE device_pairings
                SET status = 'expired'
                WHERE id = ?
                """,
                (pairing["id"],),
            )

            connection.commit()

            raise HTTPException(
                status_code=401,
                detail="Pairing code has expired",
            )

        # ====================================================
        # FIND EXISTING DEVICE
        # ====================================================

        device = None

        # ----------------------------------------------------
        # 1. Stable MAC / Android identifier
        # ----------------------------------------------------

        if mac_address:

            device = connection.execute(
                """
                SELECT *
                FROM devices
                WHERE mac_address = ?
                LIMIT 1
                """,
                (mac_address,),
            ).fetchone()

        # ----------------------------------------------------
        # 2. Android fallback for the EXISTING Device #7
        # ----------------------------------------------------
        #
        # Your first Android pairing created Device #7 with:
        #
        #     mac_address = android-<random value>
        #     ip_address  = unknown
        #
        # The new Android client will use a stable identifier.
        # Therefore, if no stable identifier match exists,
        # look for an existing Android device whose IP was
        # "unknown".
        #
        # This prevents Device #7 from being lost and avoids
        # creating another device with "unknown" IP.
        # ----------------------------------------------------

        if device is None and is_android:

            device = connection.execute(
                """
                SELECT *
                FROM devices
                WHERE LOWER(device_type) = 'android'
                  AND (
                        ip_address = 'unknown'
                        OR ip_address LIKE 'android-ip-%'
                      )
                ORDER BY id ASC
                LIMIT 1
                """
            ).fetchone()

        # ----------------------------------------------------
        # 3. Current IP for desktop devices
        # ----------------------------------------------------

        if (
            device is None
            and ip_address != "unknown"
            and not is_android
        ):

            device = connection.execute(
                """
                SELECT *
                FROM devices
                WHERE ip_address = ?
                LIMIT 1
                """,
                (ip_address,),
            ).fetchone()

        # ====================================================
        # CREATE OR UPDATE DEVICE
        # ====================================================

        if device:

            device_id = device["id"]

            connection.execute(
                """
                UPDATE devices
                SET
                    name = ?,
                    device_name = ?,
                    ip_address = ?,
                    mac_address = ?,
                    device_type = ?,
                    operating_system = ?,
                    status = 'online',
                    last_seen = ?
                WHERE id = ?
                """,
                (
                    device_name,
                    device_name,
                    ip_address,
                    mac_address,
                    device_type,
                    operating_system,
                    now_iso,
                    device_id,
                ),
            )

        else:

            cursor = connection.execute(
                """
                INSERT INTO devices
                (
                    name,
                    ip_address,
                    status,
                    risk_level,
                    last_seen,
                    device_name,
                    mac_address,
                    device_type,
                    created_at,
                    operating_system,
                    first_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_name,
                    ip_address,
                    "online",
                    "low",
                    now_iso,
                    device_name,
                    mac_address,
                    device_type,
                    now_iso,
                    operating_system,
                    now_iso,
                ),
            )

            device_id = cursor.lastrowid

        # ====================================================
        # DISABLE PREVIOUS AGENTS
        # ====================================================

        connection.execute(
            """
            UPDATE agents
            SET status = 'inactive'
            WHERE device_id = ?
              AND status = 'active'
            """,
            (device_id,),
        )

        # ====================================================
        # GENERATE NEW AGENT TOKEN
        # ====================================================

        raw_token = secrets.token_urlsafe(32)

        token_hash = hashlib.sha256(
            raw_token.encode("utf-8")
        ).hexdigest()

        # ====================================================
        # CREATE AGENT
        # ====================================================

        cursor = connection.execute(
            """
            INSERT INTO agents
            (
                device_id,
                agent_name,
                token_hash,
                status,
                last_heartbeat,
                created_at
            )
            VALUES (?, ?, ?, 'active', ?, ?)
            """,
            (
                device_id,
                agent_name,
                token_hash,
                now_iso,
                now_iso,
            ),
        )

        agent_id = cursor.lastrowid

        # ====================================================
        # CONSUME PAIRING CODE
        # ====================================================

        connection.execute(
            """
            UPDATE device_pairings
            SET
                status = 'used',
                used_at = ?
            WHERE id = ?
            """,
            (
                now_iso,
                pairing["id"],
            ),
        )

        connection.commit()

        # ====================================================
        # RETURN RESULT
        # ====================================================

        return {
            "message": (
                "Device paired and agent "
                "registered successfully"
            ),

            "agent_id": agent_id,

            "device_id": device_id,

            "device": {
                "id": device_id,
                "name": device_name,
                "ip_address": ip_address,
                "mac_address": mac_address,
                "device_type": device_type,
                "operating_system": operating_system,
                "status": "online",
            },

            "agent_token": raw_token,

            "paired_at": now_iso,

            "platform": (
                "android"
                if is_android
                else "desktop"
            ),

            "warning": (
                "Android IP address may be unavailable "
                "during pairing."
                if is_android
                else None
            ),
        }

    except HTTPException:
        connection.rollback()
        raise

    except sqlite3.IntegrityError as exc:

        connection.rollback()

        raise HTTPException(
            status_code=409,
            detail=(
                "Device registration conflicts with "
                "an existing device record: "
                + str(exc)
            ),
        )

    except Exception as exc:

        connection.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "Device registration failed: "
                + str(exc)
            ),
        )

    finally:

        connection.close()


# ============================================================
# AGENT REGISTRATION
# ============================================================

@app.post("/api/agents/register")
def register_agent(
    request: AgentRegistrationRequest,
):

    connection = get_connection()

    try:

        now = datetime.now().isoformat()

        # ====================================================
        # FIND DEVICE
        # ====================================================

        device = connection.execute(
            """
            SELECT *
            FROM devices
            WHERE mac_address = ?
            LIMIT 1
            """,
            (request.mac_address,),
        ).fetchone()

        if not device:

            device = connection.execute(
                """
                SELECT *
                FROM devices
                WHERE ip_address = ?
                LIMIT 1
                """,
                (request.ip_address,),
            ).fetchone()

        # ====================================================
        # CREATE OR UPDATE DEVICE
        # ====================================================

        if device:

            connection.execute(
                """
                UPDATE devices
                SET
                    name = ?,
                    device_name = ?,
                    mac_address = ?,
                    device_type = ?,
                    ip_address = ?,
                    operating_system = ?,
                    status = 'online',
                    last_seen = ?
                WHERE id = ?
                """,
                (
                    request.device_name,
                    request.device_name,
                    request.mac_address,
                    request.device_type,
                    request.ip_address,
                    request.operating_system,
                    now,
                    device["id"],
                ),
            )

            device_id = device["id"]

        else:

            cursor = connection.execute(
                """
                INSERT INTO devices
                (
                    name,
                    device_name,
                    mac_address,
                    device_type,
                    ip_address,
                    operating_system,
                    risk_level,
                    status,
                    created_at,
                    first_seen,
                    last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.device_name,
                    request.device_name,
                    request.mac_address,
                    request.device_type,
                    request.ip_address,
                    request.operating_system,
                    "low",
                    "online",
                    now,
                    now,
                    now,
                ),
            )

            device_id = cursor.lastrowid

        # ====================================================
        # CREATE AGENT TOKEN
        # ====================================================

        raw_token = secrets.token_urlsafe(32)

        token_hash = hashlib.sha256(
            raw_token.encode("utf-8")
        ).hexdigest()

        # ====================================================
        # DISABLE OLD AGENTS
        # ====================================================

        connection.execute(
            """
            UPDATE agents
            SET status = 'inactive'
            WHERE device_id = ?
            """,
            (device_id,),
        )

        # ====================================================
        # CREATE AGENT
        # ====================================================

        cursor = connection.execute(
            """
            INSERT INTO agents
            (
                device_id,
                agent_name,
                token_hash,
                status,
                last_heartbeat,
                created_at
            )
            VALUES (?, ?, ?, 'active', ?, ?)
            """,
            (
                device_id,
                request.agent_name,
                token_hash,
                now,
                now,
            ),
        )

        agent_id = cursor.lastrowid

        connection.commit()

        return {
            "message": "Agent registered successfully",
            "agent_id": agent_id,
            "device_id": device_id,
            "device": {
                "id": device_id,
                "name": request.device_name,
                "ip_address": request.ip_address,
                "mac_address": request.mac_address,
                "device_type": request.device_type,
                "operating_system": request.operating_system,
            },
            "agent_token": raw_token,
            "warning": (
                "Store this agent token securely. "
                "It will not be returned again."
            ),
        }

    finally:
        connection.close()


# ============================================================
# AGENT AUTHENTICATION
# ============================================================

def get_agent(
    authorization: str | None,
):

    if not authorization:

        raise HTTPException(
            status_code=401,
            detail="Agent authorization required",
        )

    if not authorization.startswith("Bearer "):

        raise HTTPException(
            status_code=401,
            detail="Invalid agent authorization format",
        )

    token = authorization.replace(
        "Bearer ",
        "",
        1,
    ).strip()

    if not token:

        raise HTTPException(
            status_code=401,
            detail="Agent token is missing",
        )

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    connection = get_connection()

    try:

        agent = connection.execute(
            """
            SELECT
                agents.id AS agent_id,
                agents.device_id,
                agents.agent_name,
                agents.status AS agent_status,
                agents.last_heartbeat,
                devices.name AS device_name,
                devices.ip_address,
                devices.mac_address,
                devices.device_type,
                devices.operating_system
            FROM agents
            JOIN devices
                ON devices.id = agents.device_id
            WHERE agents.token_hash = ?
            LIMIT 1
            """,
            (token_hash,),
        ).fetchone()

    finally:
        connection.close()

    if agent is None:

        raise HTTPException(
            status_code=401,
            detail="Invalid agent token",
        )

    if agent["agent_status"] != "active":

        raise HTTPException(
            status_code=401,
            detail="Agent is inactive",
        )

    return agent


# ============================================================
# AGENT HEARTBEAT
# ============================================================


class AgentHeartbeatRequest(BaseModel):
    ip_address: str | None = None


@app.post("/api/agents/heartbeat")
def agent_heartbeat(
    request: AgentHeartbeatRequest | None = None,
    authorization: str | None = Header(default=None),
):
    agent = get_agent(authorization)

    now = datetime.now().isoformat()
    connection = get_connection()

    try:
        connection.execute(
            """
            UPDATE agents
            SET last_heartbeat = ?
            WHERE id = ?
            """,
            (now, agent["agent_id"]),
        )

        if request and request.ip_address:
            current_ip = request.ip_address.strip()

            if current_ip and current_ip.lower() != "unknown":
                connection.execute(
                    """
                    UPDATE devices
                    SET
                        ip_address = ?,
                        status = 'online',
                        last_seen = ?
                    WHERE id = ?
                    """,
                    (current_ip, now, agent["device_id"]),
                )
            else:
                connection.execute(
                    """
                    UPDATE devices
                    SET status = 'online', last_seen = ?
                    WHERE id = ?
                    """,
                    (now, agent["device_id"]),
                )
        else:
            connection.execute(
                """
                UPDATE devices
                SET status = 'online', last_seen = ?
                WHERE id = ?
                """,
                (now, agent["device_id"]),
            )

        connection.commit()

    finally:
        connection.close()

    return {
        "status": "ok",
        "message": "Heartbeat received",
        "agent_id": agent["agent_id"],
        "device_id": agent["device_id"],
        "timestamp": now,
    }



# ============================================================
# AGENT INFORMATION
# ============================================================

@app.get("/api/agents/me")
def agent_me(
    authorization: str | None = Header(default=None),
):

    agent = get_agent(authorization)

    return {
        "agent_id": agent["agent_id"],
        "device_id": agent["device_id"],
        "agent_name": agent["agent_name"],
        "status": agent["agent_status"],
        "device": {
            "name": agent["device_name"],
            "ip_address": agent["ip_address"],
            "mac_address": agent["mac_address"],
            "device_type": agent["device_type"],
            "operating_system": agent["operating_system"],
        },
        "last_heartbeat": agent["last_heartbeat"],
    }


# ============================================================
# AGENT NETWORK EVENTS
# ============================================================

@app.post("/api/agents/events")
def agent_upload_events(
    request: AgentNetworkEventsRequest,
    authorization: str | None = Header(default=None),
):

    agent = get_agent(authorization)

    if not request.events:

        return {
            "message": "No network events supplied.",
            "agent_id": agent["agent_id"],
            "device_id": agent["device_id"],
            "received": 0,
            "saved": 0,
        }

    connection = get_connection()

    saved_count = 0
    duplicate_count = 0

    try:

        now = datetime.now().isoformat()

        for event in request.events:

            event_timestamp = (
                event.timestamp
                if event.timestamp
                else now
            )

            destination_ip = (
                event.destination_ip
                if event.destination_ip is not None
                else ""
            )

            protocol = (
                event.protocol
                if event.protocol
                else "OTHER"
            )

            event_type = (
                event.event_type
                if event.event_type
                else "NETWORK_CONNECTION"
            )

            risk = (
                event.risk
                if event.risk
                else "low"
            )

            existing = connection.execute(
                """
                SELECT id
                FROM network_events
                WHERE
                    device_id = ?
                    AND source_ip = ?
                    AND destination_ip = ?
                    AND protocol = ?
                    AND port IS ?
                    AND event_type = ?
                    AND timestamp = ?
                LIMIT 1
                """,
                (
                    agent["device_id"],
                    event.source_ip,
                    destination_ip,
                    protocol,
                    event.port,
                    event_type,
                    event_timestamp,
                ),
            ).fetchone()

            if existing is not None:

                duplicate_count += 1
                continue

            connection.execute(
                """
                INSERT INTO network_events
                (
                    source_ip,
                    destination_ip,
                    protocol,
                    port,
                    event_type,
                    risk,
                    timestamp,
                    threat_id,
                    device_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.source_ip,
                    destination_ip,
                    protocol,
                    event.port,
                    event_type,
                    risk,
                    event_timestamp,
                    None,
                    agent["device_id"],
                ),
            )

            saved_count += 1

        connection.execute(
            """
            UPDATE agents
            SET last_heartbeat = ?
            WHERE id = ?
            """,
            (
                now,
                agent["agent_id"],
            ),
        )

        connection.execute(
            """
            UPDATE devices
            SET
                status = 'online',
                last_seen = ?
            WHERE id = ?
            """,
            (
                now,
                agent["device_id"],
            ),
        )

        connection.commit()

        return {
            "message": "Network events received successfully",
            "agent_id": agent["agent_id"],
            "device_id": agent["device_id"],
            "received": len(request.events),
            "saved": saved_count,
            "duplicates": duplicate_count,
            "timestamp": now,
        }

    finally:
        connection.close()


# ============================================================
# GET DEVICES
# ============================================================

@app.get("/api/devices")
def get_devices(
    authorization: str | None = Header(default=None),
):

    get_current_user(authorization)

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT
                id,
                name,
                device_name,
                ip_address,
                mac_address,
                device_type,
                operating_system,
                risk_level,
                status,
                created_at,
                first_seen,
                last_seen
            FROM devices
            ORDER BY
                CASE
                    WHEN last_seen IS NULL THEN 1
                    ELSE 0
                END,
                last_seen DESC
            """
        ).fetchall()

        devices = []

        for row in rows:

            device = dict(row)

            last_seen = device.get("last_seen")

            if last_seen:

                try:

                    last_seen_dt = datetime.fromisoformat(
                        last_seen
                    )

                    age_seconds = (
                        datetime.now() - last_seen_dt
                    ).total_seconds()

                    if age_seconds <= 300:
                        device["status"] = "online"
                    else:
                        device["status"] = "offline"

                except (ValueError, TypeError):

                    device["status"] = "offline"

            else:

                device["status"] = "offline"

            devices.append(device)

        return devices

    finally:
        connection.close()


# ============================================================
# NETWORK EVENTS
# ============================================================

@app.get("/api/network-events")
def get_network_events(
    limit: int = 100,
    offset: int = 0,
    authorization: str | None = Header(default=None),
):

    get_current_user(authorization)

    limit = max(
        1,
        min(limit, 1000),
    )

    offset = max(
        0,
        offset,
    )

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                network_events.id,
                network_events.source_ip,
                network_events.destination_ip,
                network_events.protocol,
                network_events.port,
                network_events.event_type,
                network_events.risk,
                network_events.timestamp,
                network_events.threat_id,
                network_events.device_id,

                devices.name AS device_name,
                devices.device_name AS connected_device_name,
                devices.ip_address AS device_ip,
                devices.mac_address AS device_mac,
                devices.device_type AS device_type,
                devices.operating_system AS device_operating_system,
                devices.status AS device_status

            FROM network_events

            LEFT JOIN devices
                ON devices.id = network_events.device_id

            ORDER BY network_events.id DESC

            LIMIT ?
            OFFSET ?
            """,
            (
                limit,
                offset,
            ),
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        connection.close()


# ============================================================
# THREATS
# ============================================================

@app.get("/api/threats")
def get_threats(
    authorization: str | None = Header(default=None),
):

    get_current_user(authorization)

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT *
            FROM threats
            ORDER BY id DESC
            """
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        connection.close()


# ============================================================
# THREAT SEVERITY
# ============================================================

@app.get("/api/threats/severity")
def threat_severity(
    authorization: str | None = Header(default=None),
):

    get_current_user(authorization)

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT
                severity,
                COUNT(*) AS count
            FROM threats
            GROUP BY severity
            """
        ).fetchall()

        return {
            row["severity"]: row["count"]
            for row in rows
        }

    finally:
        connection.close()


# ============================================================
# THREAT DETAILS
# ============================================================

@app.get("/api/threats/{threat_id}")
def get_threat(
    threat_id: int,
    authorization: str | None = Header(default=None),
):

    get_current_user(authorization)

    connection = get_connection()

    try:

        threat = connection.execute(
            """
            SELECT *
            FROM threats
            WHERE id = ?
            """,
            (threat_id,),
        ).fetchone()

        if threat is None:

            raise HTTPException(
                status_code=404,
                detail="Threat not found",
            )

        return dict(threat)

    finally:
        connection.close()


# ============================================================
# THREAT NETWORK EVENTS
# ============================================================

@app.get("/api/threats/{threat_id}/network-events")
def get_threat_network_events(
    threat_id: int,
    authorization: str | None = Header(default=None),
):

    get_current_user(authorization)

    connection = get_connection()

    try:

        threat = connection.execute(
            """
            SELECT id
            FROM threats
            WHERE id = ?
            """,
            (threat_id,),
        ).fetchone()

        if threat is None:

            raise HTTPException(
                status_code=404,
                detail="Threat not found",
            )

        rows = connection.execute(
            """
            SELECT *
            FROM network_events
            WHERE threat_id = ?
            ORDER BY id DESC
            """,
            (threat_id,),
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        connection.close()


# ============================================================
# THREAT EVENTS ALIAS
# ============================================================

@app.get("/api/threats/{threat_id}/events")
def get_threat_events(
    threat_id: int,
    authorization: str | None = Header(default=None),
):

    return get_threat_network_events(
        threat_id,
        authorization,
    )


# ============================================================
# LINK THREAT EVENTS
# ============================================================

@app.post("/api/threats/{threat_id}/events")
def link_threat_events_frontend(
    threat_id: int,
    request: ThreatEventLinkRequest,
    authorization: str | None = Header(default=None),
):

    get_current_admin(authorization)

    connection = get_connection()

    try:

        threat = connection.execute(
            """
            SELECT *
            FROM threats
            WHERE id = ?
            """,
            (threat_id,),
        ).fetchone()

        if threat is None:

            raise HTTPException(
                status_code=404,
                detail="Threat not found",
            )

        event_ids = [
            int(event_id)
            for event_id in request.event_ids
        ]

        if not event_ids:

            return {
                "message": "No event IDs were supplied.",
                "threat_id": threat_id,
                "linked_events": 0,
            }

        placeholders = ",".join(
            ["?"] * len(event_ids)
        )

        result = connection.execute(
            f"""
            UPDATE network_events
            SET threat_id = ?
            WHERE id IN ({placeholders})
            """,
            [
                threat_id,
                *event_ids,
            ],
        )

        connection.commit()

        return {
            "message": "Events linked to threat successfully",
            "threat_id": threat_id,
            "linked_events": result.rowcount,
            "event_ids": event_ids,
        }

    finally:
        connection.close()


# ============================================================
# INCIDENTS
# ============================================================

@app.get("/api/incidents")
def get_incidents(
    authorization: str | None = Header(default=None),
):

    get_current_admin(authorization)

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT *
            FROM incidents
            ORDER BY id DESC
            """
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        connection.close()


# ============================================================
# SINGLE INCIDENT
# ============================================================

@app.get("/api/incidents/{incident_id}")
def get_incident(
    incident_id: int,
    authorization: str | None = Header(default=None),
):

    get_current_admin(authorization)

    connection = get_connection()

    try:

        incident = connection.execute(
            """
            SELECT *
            FROM incidents
            WHERE id = ?
            """,
            (incident_id,),
        ).fetchone()

        if incident is None:

            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        return dict(incident)

    finally:
        connection.close()


# ============================================================
# CREATE INCIDENT
# ============================================================

@app.post("/api/incidents")
def create_incident(
    request: IncidentRequest,
    authorization: str | None = Header(default=None),
):

    get_current_admin(authorization)

    now = datetime.now().isoformat()

    connection = get_connection()

    try:

        cursor = connection.execute(
            """
            INSERT INTO incidents
            (
                title,
                description,
                severity,
                status,
                threat_id,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.title,
                request.description,
                request.severity,
                "open",
                request.threat_id,
                now,
                now,
            ),
        )

        connection.commit()

        return {
            "message": "Incident created",
            "id": cursor.lastrowid,
        }

    finally:
        connection.close()


# ============================================================
# CREATE INCIDENT FROM THREAT
# ============================================================

@app.post("/api/incidents/create/{threat_id}")
def create_incident_from_threat(
    threat_id: int,
    authorization: str | None = Header(default=None),
):

    get_current_admin(authorization)

    connection = get_connection()

    try:

        threat = connection.execute(
            """
            SELECT *
            FROM threats
            WHERE id = ?
            """,
            (threat_id,),
        ).fetchone()

        if threat is None:

            raise HTTPException(
                status_code=404,
                detail="Threat not found",
            )

        existing = connection.execute(
            """
            SELECT *
            FROM incidents
            WHERE threat_id = ?
              AND status IN (
                  'new',
                  'open',
                  'investigating',
                  'contained'
              )
            ORDER BY id DESC
            LIMIT 1
            """,
            (threat_id,),
        ).fetchone()

        if existing:

            return {
                "message": "Incident already exists",
                "id": existing["id"],
                "threat_id": threat_id,
                "existing": True,
            }

        now = datetime.now().isoformat()

        title = "GNN Network Behavior Anomaly"

        description = (
            threat["description"]
            or
            "ZeroGuard detected a network behavior anomaly "
            "requiring investigation."
        )

        cursor = connection.execute(
            """
            INSERT INTO incidents
            (
                title,
                description,
                severity,
                status,
                threat_id,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                description,
                threat["severity"] or "low",
                "open",
                threat_id,
                now,
                now,
            ),
        )

        connection.commit()

        return {
            "message": "Incident created",
            "id": cursor.lastrowid,
            "threat_id": threat_id,
            "existing": False,
        }

    finally:
        connection.close()


# ============================================================
# UPDATE INCIDENT
# ============================================================

@app.patch("/api/incidents/{incident_id}")
def update_incident_status(
    incident_id: int,
    status: str,
    authorization: str | None = Header(default=None),
):

    get_current_admin(authorization)

    allowed_statuses = [
        "new",
        "open",
        "investigating",
        "contained",
        "resolved",
        "closed",
    ]

    status = status.strip().lower()

    if status not in allowed_statuses:

        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid status. "
                f"Allowed values: {allowed_statuses}"
            ),
        )

    connection = get_connection()

    try:

        result = connection.execute(
            """
            UPDATE incidents
            SET
                status = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                status,
                datetime.now().isoformat(),
                incident_id,
            ),
        )

        connection.commit()

        if result.rowcount == 0:

            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        return {
            "message": "Incident updated",
            "id": incident_id,
            "status": status,
        }

    finally:
        connection.close()


# ============================================================
# FRONTEND INCIDENT STATUS ENDPOINT
# ============================================================

@app.patch("/api/incidents/{incident_id}/status")
def update_incident_status_frontend(
    incident_id: int,
    status: str,
    authorization: str | None = Header(default=None),
):

    return update_incident_status(
        incident_id,
        status,
        authorization,
    )


# ============================================================
# RESPONSE ACTIONS
# ============================================================

@app.get("/api/response-actions")
def get_response_actions(
    authorization: str | None = Header(default=None),
):

    get_current_admin(authorization)

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT *
            FROM response_actions
            ORDER BY id DESC
            """
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        connection.close()


# ============================================================
# CREATE RESPONSE ACTION
# ============================================================

@app.post("/api/response-actions")
def create_response_action(
    request: ResponseActionRequest,
    authorization: str | None = Header(default=None),
):
    get_current_admin(authorization)

    # --------------------------------------------------------
    # VALIDATE ACTION INPUT
    # --------------------------------------------------------

    supported_actions = {
        "Alert Generated",
        "Block Source",
        "Isolate Device",
        "Terminate Connection",
        "Network Quarantine",
    }

    protected_actions = {
        "Block Source",
        "Isolate Device",
        "Terminate Connection",
        "Network Quarantine",
    }

    action_type = request.action_type.strip()
    target = request.target.strip()
    reason = request.reason.strip()

    if action_type not in supported_actions:
        raise HTTPException(
            status_code=400,
            detail="Unsupported response action type",
        )

    if not target:
        raise HTTPException(
            status_code=400,
            detail="Target cannot be empty",
        )

    if not reason:
        raise HTTPException(
            status_code=400,
            detail="Reason cannot be empty",
        )

    if (
        action_type in protected_actions
        and request.threat_id is None
    ):
        raise HTTPException(
            status_code=400,
            detail="A linked threat is required for this action",
        )

    # --------------------------------------------------------
    # VALIDATE LINKED INCIDENT AND THREAT
    # --------------------------------------------------------

    connection = get_connection()

    try:
        if request.incident_id is not None:
            incident = connection.execute(
                """
                SELECT id
                FROM incidents
                WHERE id = ?
                """,
                (request.incident_id,),
            ).fetchone()

            if incident is None:
                raise HTTPException(
                    status_code=404,
                    detail="Incident not found",
                )

        if request.threat_id is not None:
            threat = connection.execute(
                """
                SELECT id
                FROM threats
                WHERE id = ?
                """,
                (request.threat_id,),
            ).fetchone()

            if threat is None:
                raise HTTPException(
                    status_code=404,
                    detail="Threat not found",
                )

        # ----------------------------------------------------
        # CREATE PENDING ACTION
        # ----------------------------------------------------

        now = datetime.now().isoformat()

        cursor = connection.execute(
            """
            INSERT INTO response_actions
            (
                incident_id,
                action_type,
                target,
                reason,
                status,
                threat_id,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.incident_id,
                action_type,
                target,
                reason,
                "pending",
                request.threat_id,
                now,
            ),
        )

        connection.commit()

        return {
            "message": "Response action created",
            "id": cursor.lastrowid,
            "incident_id": request.incident_id,
            "action_type": action_type,
            "status": "pending",
            "threat_id": request.threat_id,
        }

    finally:
        connection.close()

# ============================================================
# EXECUTE RESPONSE ACTION
# ============================================================

@app.post("/api/response-actions/{action_id}/execute")
def execute_existing_response_action(
    action_id: int,
    authorization: str | None = Header(default=None),
):

    get_current_admin(authorization)

    connection = get_connection()

    try:

        action_row = connection.execute(
            """
            SELECT *
            FROM response_actions
            WHERE id = ?
            """,
            (action_id,),
        ).fetchone()

        if action_row is None:

            raise HTTPException(
                status_code=404,
                detail="Response action not found",
            )

        action = dict(action_row)

        if action["status"] == "completed":

            return {
                "success": True,
                "message": (
                    "Response action is already completed."
                ),
                "action": action,
            }

        action_type = str(
            action.get("action_type") or ""
        ).strip()

        threat_id = action.get("threat_id")

        threat = None

        if threat_id is not None:

            threat_row = connection.execute(
                """
                SELECT *
                FROM threats
                WHERE id = ?
                """,
                (threat_id,),
            ).fetchone()

            if threat_row is not None:
                threat = dict(threat_row)

        # ====================================================
        # PROTECTED DEFENSIVE ACTIONS
        # ====================================================

        protected_actions = {
            "Block Source",
            "Isolate Device",
            "Terminate Connection",
            "Network Quarantine",
        }

        if action_type in protected_actions:

            if threat is None:

                denied_message = (
                    "Response action denied. "
                    "No associated threat was found, "
                    "so ZeroGuard cannot verify risk authorization."
                )

                connection.execute(
                    """
                    UPDATE response_actions
                    SET status = ?
                    WHERE id = ?
                    """,
                    (
                        "denied",
                        action_id,
                    ),
                )

                connection.commit()

                return {
                    "success": False,
                    "message": denied_message,
                    "result": {
                        "success": False,
                        "status": "denied",
                        "authorization": "denied",
                        "action_type": action_type,
                        "threat_id": threat_id,
                    },
                    "action": action,
                }

            threat_severity = str(
                threat.get("severity") or "unknown"
            ).strip().lower()

            try:

                risk_score = float(
                    threat.get("risk_score")
                    if threat.get("risk_score") is not None
                    else 0
                )

            except (
                TypeError,
                ValueError,
            ):

                risk_score = 0.0

            if threat_severity != "critical":

                denied_message = (
                    "Response action denied. "
                    "Automatic defensive actions are authorized "
                    "only for CRITICAL contextual risk. "
                    f"Current threat severity: "
                    f"{threat_severity.upper()}. "
                    f"Risk score: {risk_score:.1f}/100."
                )

                connection.execute(
                    """
                    UPDATE response_actions
                    SET status = ?
                    WHERE id = ?
                    """,
                    (
                        "denied",
                        action_id,
                    ),
                )

                connection.commit()

                updated_row = connection.execute(
                    """
                    SELECT *
                    FROM response_actions
                    WHERE id = ?
                    """,
                    (action_id,),
                ).fetchone()

                updated_action = (
                    dict(updated_row)
                    if updated_row
                    else action
                )

                return {
                    "success": False,
                    "message": denied_message,
                    "result": {
                        "success": False,
                        "status": "denied",
                        "authorization": "denied",
                        "action_type": action_type,
                        "threat_id": threat_id,
                        "risk_level": threat_severity,
                        "risk_score": risk_score,
                    },
                    "action": updated_action,
                }

            if risk_score < 80:

                denied_message = (
                    "Response action denied. "
                    "Critical severity requires a contextual "
                    "risk score of at least 80/100. "
                    f"Current score: {risk_score:.1f}/100."
                )

                connection.execute(
                    """
                    UPDATE response_actions
                    SET status = ?
                    WHERE id = ?
                    """,
                    (
                        "denied",
                        action_id,
                    ),
                )

                connection.commit()

                updated_row = connection.execute(
                    """
                    SELECT *
                    FROM response_actions
                    WHERE id = ?
                    """,
                    (action_id,),
                ).fetchone()

                updated_action = (
                    dict(updated_row)
                    if updated_row
                    else action
                )

                return {
                    "success": False,
                    "message": denied_message,
                    "result": {
                        "success": False,
                        "status": "denied",
                        "authorization": "denied",
                        "action_type": action_type,
                        "threat_id": threat_id,
                        "risk_level": threat_severity,
                        "risk_score": risk_score,
                    },
                    "action": updated_action,
                }

        # ====================================================
        # EXECUTE ACTION
        # ====================================================

        result = execute_response_action(
            action_type=action_type,
            target=action["target"],
            reason=action["reason"],
        )

        new_status = result.get(
            "status",
            "failed",
        )

        connection.execute(
            """
            UPDATE response_actions
            SET status = ?
            WHERE id = ?
            """,
            (
                new_status,
                action_id,
            ),
        )

        connection.commit()

        updated_row = connection.execute(
            """
            SELECT *
            FROM response_actions
            WHERE id = ?
            """,
            (action_id,),
        ).fetchone()

        updated_action = (
            dict(updated_row)
            if updated_row
            else action
        )

        return {
            "success": result.get(
                "success",
                False,
            ),
            "message": result.get(
                "message",
                "Response action processed.",
            ),
            "result": result,
            "action": updated_action,
        }

    finally:
        connection.close()


# ============================================================
# GNN DETECTION / ANALYSIS
# ============================================================

@app.post("/api/detection/analyze")
def analyze_network(
    authorization: str | None = Header(default=None),
):

    get_current_user(authorization)

    if not GNN_AVAILABLE or analyze_database is None:

        raise HTTPException(
            status_code=503,
            detail="GNN detector is not available",
        )

    if (
        not RISK_CORRELATOR_AVAILABLE
        or correlate_risk is None
    ):

        raise HTTPException(
            status_code=503,
            detail="Risk Correlator is not available",
        )

    # ========================================================
    # RUN GNN
    # ========================================================

    try:

        result = analyze_database()

    except Exception as error:

        import traceback

        traceback.print_exc()

        raise HTTPException(
            status_code=500,
            detail={
                "error": "GNN analysis failed",
                "error_type": type(error).__name__,
                "error_message": str(error),
                "traceback": traceback.format_exc(),
            },
        )

    if not isinstance(result, dict):

        raise HTTPException(
            status_code=500,
            detail="GNN detector returned invalid data",
        )

    suspicious_nodes = int(
        result.get(
            "suspicious_nodes",
            0,
        )
    )

    maximum_score = float(
        result.get(
            "maximum_anomaly_score",
            0,
        )
    )

    average_score = float(
        result.get(
            "anomaly_score",
            0,
        )
    )

    gnn_severity = str(
        result.get(
            "severity",
            "low",
        )
    ).lower()

    node_details = result.get(
        "node_details",
        [],
    )

    # ========================================================
    # SUSPICIOUS IPS
    # ========================================================

    suspicious_ips = []
    suspicious_node_z_scores = []

    for node in node_details:

        if not isinstance(node, dict):
            continue

        if node.get("suspicious"):

            ip_address = node.get(
                "ip_address"
            )

            if ip_address:

                suspicious_ips.append(
                    str(ip_address)
                )

            z_score = node.get(
                "baseline_z_score"
            )

            if z_score is not None:

                try:

                    suspicious_node_z_scores.append(
                        float(z_score)
                    )

                except Exception:
                    pass

    suspicious_ips = list(
        dict.fromkeys(
            suspicious_ips
        )
    )

    baseline_z_score = 0.0

    if suspicious_node_z_scores:

        baseline_z_score = max(
            suspicious_node_z_scores
        )

    local_ips = get_local_ip_addresses()

    connection = get_connection()

    threat_id = None
    linked_events = 0
    correlated_events = []

    risk_result = {
        "risk_score": 0.0,
        "risk_level": "low",
        "reasons": [],
        "positive_context": [],
        "warnings": [],
        "recommended_action": "Monitor the activity.",
        "automatic_response_allowed": False,
    }

    try:

        # ====================================================
        # CORRELATE NETWORK EVIDENCE
        # ====================================================

        if suspicious_ips:

            placeholders = ",".join(
                ["?"] * len(suspicious_ips)
            )

            event_rows = connection.execute(
                f"""
                SELECT *
                FROM network_events
                WHERE
                    source_ip IN ({placeholders})
                    OR destination_ip IN ({placeholders})
                ORDER BY id DESC
                LIMIT 500
                """,
                suspicious_ips + suspicious_ips,
            ).fetchall()

            correlated_events = [
                dict(row)
                for row in event_rows
            ]

        # ====================================================
        # RISK CORRELATION
        # ====================================================

        if suspicious_nodes > 0:

            try:

                risk_result = correlate_risk(
                    anomaly_score=maximum_score,
                    baseline_z_score=baseline_z_score,
                    suspicious_nodes=suspicious_nodes,
                    events=correlated_events,
                    local_ips=local_ips,
                )

            except Exception as error:

                print(
                    "Risk Correlator failed:",
                    error,
                )

                risk_result = {
                    "risk_score": 0.0,
                    "risk_level": "low",
                    "reasons": [
                        "Risk correlation could not be completed."
                    ],
                    "positive_context": [],
                    "warnings": [
                        (
                            "Risk Correlator error occurred. "
                            "Automatic response is disabled."
                        )
                    ],
                    "recommended_action": (
                        "Manual investigation required. "
                        "No automatic blocking is recommended."
                    ),
                    "automatic_response_allowed": False,
                }

        # ====================================================
        # FINAL RISK
        # ====================================================

        final_risk_level = str(
            risk_result.get(
                "risk_level",
                "low",
            )
        ).lower()

        try:

            final_risk_score = float(
                risk_result.get(
                    "risk_score",
                    0,
                )
            )

        except Exception:

            final_risk_score = 0.0

        automatic_response_allowed = bool(
            risk_result.get(
                "automatic_response_allowed",
                False,
            )
        )

        if not suspicious_nodes:
            automatic_response_allowed = False

        if final_risk_level != "critical":
            automatic_response_allowed = False

        # ====================================================
        # CREATE / UPDATE THREAT
        # ====================================================

        if suspicious_nodes > 0:

            existing_threat = connection.execute(
                """
                SELECT *
                FROM threats
                WHERE threat_type = ?
                  AND status = 'active'
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    "GNN Network Anomaly",
                ),
            ).fetchone()

            source_ip = (
                suspicious_ips[0]
                if suspicious_ips
                else None
            )

            reasons_text = "; ".join(
                str(item)
                for item in risk_result.get(
                    "reasons",
                    [],
                )
            )

            context_text = "; ".join(
                str(item)
                for item in risk_result.get(
                    "positive_context",
                    [],
                )
            )

            warnings_text = "; ".join(
                str(item)
                for item in risk_result.get(
                    "warnings",
                    [],
                )
            )

            description = (
                "ZeroGuard detected a statistical network "
                "behavior anomaly using the trained GNN. "
                f"GNN average anomaly score: "
                f"{average_score:.2f}%. "
                f"GNN maximum anomaly score: "
                f"{maximum_score:.2f}%. "
                f"Baseline Z-score: "
                f"{baseline_z_score:.3f}. "
                f"Suspicious nodes: "
                f"{suspicious_nodes}. "
                f"Correlated events: "
                f"{len(correlated_events)}. "
                f"Final contextual risk score: "
                f"{final_risk_score:.1f}/100. "
                f"Final risk level: "
                f"{final_risk_level.upper()}. "
                f"GNN severity before contextual correlation: "
                f"{gnn_severity.upper()}. "
                "The GNN score represents statistical "
                "deviation from learned normal behavior and "
                "is not an attack probability."
            )

            if reasons_text:

                description += (
                    " Risk reasons: "
                    + reasons_text
                    + "."
                )

            if context_text:

                description += (
                    " Positive context: "
                    + context_text
                    + "."
                )

            if warnings_text:

                description += (
                    " Warnings: "
                    + warnings_text
                    + "."
                )

            description += (
                " Recommended action: "
                + str(
                    risk_result.get(
                        "recommended_action",
                        "Manual investigation.",
                    )
                )
            )

            threat_timestamp = datetime.now().isoformat()

            if existing_threat:

                threat_id = existing_threat["id"]

                connection.execute(
                    """
                    UPDATE threats
                    SET
                        severity = ?,
                        confidence = ?,
                        anomaly_score = ?,
                        risk_score = ?,
                        baseline_z_score = ?,
                        source_ip = ?,
                        destination_ip = ?,
                        description = ?,
                        status = 'active',
                        detected_at = ?
                    WHERE id = ?
                    """,
                    (
                        final_risk_level,
                        final_risk_score,
                        maximum_score,
                        final_risk_score,
                        baseline_z_score,
                        source_ip,
                        None,
                        description,
                        threat_timestamp,
                        threat_id,
                    ),
                )

            else:

                cursor = connection.execute(
                    """
                    INSERT INTO threats
                    (
                        threat_type,
                        severity,
                        confidence,
                        anomaly_score,
                        risk_score,
                        baseline_z_score,
                        source_ip,
                        destination_ip,
                        description,
                        status,
                        detected_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "GNN Network Anomaly",
                        final_risk_level,
                        final_risk_score,
                        maximum_score,
                        final_risk_score,
                        baseline_z_score,
                        source_ip,
                        None,
                        description,
                        "active",
                        threat_timestamp,
                    ),
                )

                threat_id = cursor.lastrowid

            # =================================================
            # LINK EVENTS
            # =================================================

            if suspicious_ips:

                placeholders = ",".join(
                    ["?"] * len(suspicious_ips)
                )

                link_query = f"""
                    UPDATE network_events
                    SET threat_id = ?
                    WHERE threat_id IS NULL
                    AND id IN (
                        SELECT id
                        FROM network_events
                        WHERE
                            source_ip IN ({placeholders})
                            OR destination_ip IN ({placeholders})
                        ORDER BY id DESC
                        LIMIT 500
                    )
                """

                parameters = (
                    [threat_id]
                    + suspicious_ips
                    + suspicious_ips
                )

                linked_events = connection.execute(
                    link_query,
                    parameters,
                ).rowcount

            # =================================================
            # INCIDENT
            # =================================================

            existing_incident = connection.execute(
                """
                SELECT id
                FROM incidents
                WHERE threat_id = ?
                  AND status IN (
                      'new',
                      'open',
                      'investigating',
                      'contained'
                  )
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    threat_id,
                ),
            ).fetchone()

            incident_title = (
                "GNN Network Behavior Anomaly"
            )

            incident_description = (
                "ZeroGuard identified a statistically "
                "unusual network behavior pattern. "
                f"GNN maximum anomaly score: "
                f"{maximum_score:.2f}%. "
                f"Baseline Z-score: "
                f"{baseline_z_score:.3f}. "
                f"Suspicious nodes: "
                f"{suspicious_nodes}. "
                f"Correlated events: "
                f"{len(correlated_events)}. "
                f"Final contextual risk score: "
                f"{final_risk_score:.1f}/100 "
                f"({final_risk_level.upper()}). "
                f"GNN severity before contextual correlation: "
                f"{gnn_severity.upper()}. "
                "The GNN anomaly score represents statistical "
                "deviation from learned normal behavior and "
                "is not an attack probability. "
                "Final incident severity is determined "
                "using contextual risk correlation."
            )

            if reasons_text:

                incident_description += (
                    " Risk reasons: "
                    + reasons_text
                    + "."
                )

            if context_text:

                incident_description += (
                    " Positive context: "
                    + context_text
                    + "."
                )

            if warnings_text:

                incident_description += (
                    " Warnings: "
                    + warnings_text
                    + "."
                )

            incident_description += (
                " Recommended action: "
                + str(
                    risk_result.get(
                        "recommended_action",
                        "Manual investigation.",
                    )
                )
            )

            now = datetime.now().isoformat()

            if existing_incident:

                incident_id = existing_incident["id"]

                connection.execute(
                    """
                    UPDATE incidents
                    SET
                        title = ?,
                        description = ?,
                        severity = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        incident_title,
                        incident_description,
                        final_risk_level,
                        now,
                        incident_id,
                    ),
                )

            else:

                connection.execute(
                    """
                    INSERT INTO incidents
                    (
                        title,
                        description,
                        severity,
                        status,
                        threat_id,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_title,
                        incident_description,
                        final_risk_level,
                        "open",
                        threat_id,
                        now,
                        now,
                    ),
                )

        connection.commit()

    finally:

        connection.close()

    # ========================================================
    # RESPONSE MESSAGE
    # ========================================================

    if suspicious_nodes > 0:

        status = final_risk_level

        message = (
            f"GNN analysis identified "
            f"{suspicious_nodes} suspicious "
            f"network node(s). "
            f"Maximum statistical anomaly score: "
            f"{maximum_score:.2f}%. "
            f"Contextual risk score: "
            f"{final_risk_score:.1f}/100. "
            f"Final risk level: "
            f"{final_risk_level.upper()}. "
            "The anomaly score is not an attack probability."
        )

        if final_risk_level == "low":

            message += (
                " Current evidence supports monitoring "
                "rather than automatic blocking."
            )

        elif final_risk_level == "medium":

            message += (
                " Manual investigation is recommended "
                "before any response."
            )

        elif final_risk_level == "high":

            message += (
                " Enhanced investigation and controlled "
                "response review are recommended."
            )

        elif final_risk_level == "critical":

            message += (
                " Critical risk requires analyst validation "
                "and controlled defensive response."
            )

    else:

        status = "normal"

        final_risk_level = "low"
        final_risk_score = 0.0
        automatic_response_allowed = False

        message = (
            "GNN analysis completed successfully. "
            "No suspicious network nodes were identified."
        )

    # ========================================================
    # RETURN RESULT
    # ========================================================

    result["threat_id"] = threat_id

    result["linked_events"] = linked_events

    result["suspicious_ips"] = suspicious_ips

    result["status"] = status

    result["message"] = message

    result["severity"] = final_risk_level

    result["gnn_severity"] = gnn_severity

    result["maximum_anomaly_score"] = maximum_score

    result["average_anomaly_score"] = average_score

    result["baseline_z_score"] = baseline_z_score

    result["risk_score"] = final_risk_score

    result["risk_level"] = final_risk_level

    result["risk_reasons"] = risk_result.get(
        "reasons",
        [],
    )

    result["risk_context"] = risk_result.get(
        "positive_context",
        [],
    )

    result["risk_warnings"] = risk_result.get(
        "warnings",
        [],
    )

    result["recommended_action"] = risk_result.get(
        "recommended_action",
        "Manual investigation.",
    )

    result["automatic_response_allowed"] = (
        automatic_response_allowed
    )

    result["risk_correlator_available"] = (
        RISK_CORRELATOR_AVAILABLE
    )

    result["local_ip_count"] = len(
        local_ips
    )

    result["correlated_event_count"] = len(
        correlated_events
    )

    result["detection_pipeline"] = [
        "network_collection",
        "graph_construction",
        "gnn_analysis",
        "baseline_comparison",
        "anomaly_assessment",
        "network_evidence",
        "context_correlation",
        "risk_classification",
        "threat_or_monitoring_decision",
    ]

    result["timestamp"] = datetime.now().isoformat()

    return result


# ============================================================
# MANUALLY LINK EVENTS TO THREAT
# ============================================================

@app.post("/api/threats/{threat_id}/link-events")
def link_events_to_threat(
    threat_id: int,
    authorization: str | None = Header(default=None),
):

    get_current_admin(authorization)

    connection = get_connection()

    try:

        threat = connection.execute(
            """
            SELECT
                id,
                source_ip
            FROM threats
            WHERE id = ?
            """,
            (threat_id,),
        ).fetchone()

        if threat is None:

            raise HTTPException(
                status_code=404,
                detail="Threat not found",
            )

        source_ip = threat["source_ip"]

        if not source_ip:

            return {
                "message": (
                    "Threat has no suspicious "
                    "source IP available for linking."
                ),
                "threat_id": threat_id,
                "linked_events": 0,
                "limit": 500,
            }

        linked_events = connection.execute(
            """
            UPDATE network_events
            SET threat_id = ?

            WHERE threat_id IS NULL

              AND id IN (
                  SELECT id
                  FROM network_events
                  WHERE threat_id IS NULL
                    AND (
                        source_ip = ?
                        OR destination_ip = ?
                    )
                  ORDER BY id DESC
                  LIMIT 500
              )
            """,
            (
                threat_id,
                source_ip,
                source_ip,
            ),
        ).rowcount

        connection.commit()

        return {
            "message": (
                "Matching recent network events "
                "linked to threat"
            ),
            "threat_id": threat_id,
            "source_ip": source_ip,
            "linked_events": linked_events,
            "limit": 500,
        }

    finally:
        connection.close()


# ============================================================
# REACT SPA FALLBACK
# ============================================================

@app.get("/{full_path:path}", include_in_schema=False)
def serve_react_app(full_path: str):

    if full_path.startswith("api/"):

        raise HTTPException(
            status_code=404,
            detail="API endpoint not found",
        )

    index_file = FRONTEND_DIST / "index.html"

    if not index_file.exists():

        raise HTTPException(
            status_code=404,
            detail="Frontend build not found. Run: npm run build",
        )

    return FileResponse(index_file)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
