# ============================================================
# ZERO GUARD AUTHENTICATION
# ============================================================

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path


# ============================================================
# DATABASE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "zeroguard.db"


def get_connection():
    connection = sqlite3.connect(
        str(DATABASE_PATH)
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# PASSWORD HASHING
# ============================================================

def hash_password(password: str) -> str:
    """
    Create a secure salted password hash.
    """

    salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000
    ).hex()

    return f"{salt}${password_hash}"


# ============================================================
# PASSWORD VERIFICATION
# ============================================================

def verify_password(
    password: str,
    stored_password: str
) -> bool:

    try:

        salt, stored_hash = stored_password.split("$", 1)

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100_000
        ).hex()

        return secrets.compare_digest(
            password_hash,
            stored_hash
        )

    except Exception:

        return False


# ============================================================
# CREATE USERS TABLE
# ============================================================

def initialize_auth_database():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            name TEXT NOT NULL,

            email TEXT NOT NULL UNIQUE,

            password_hash TEXT NOT NULL,

            role TEXT NOT NULL DEFAULT 'user',

            created_at TEXT NOT NULL

        )
        """
    )

    connection.commit()

    connection.close()


# ============================================================
# CREATE USER
# ============================================================

def create_user(
    name: str,
    email: str,
    password: str,
    role: str = "user"
):

    name = name.strip()

    email = email.strip().lower()

    role = role.strip().lower()

    if not name:

        raise ValueError(
            "Name is required."
        )

    if not email:

        raise ValueError(
            "Email is required."
        )

    if len(password) < 6:

        raise ValueError(
            "Password must contain at least 6 characters."
        )

    if role not in (
        "user",
        "admin"
    ):

        raise ValueError(
            "Invalid user role."
        )

    connection = get_connection()

    try:

        existing = connection.execute(
            """
            SELECT id
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        if existing:

            raise ValueError(
                "An account with this email already exists."
            )

        password_hash = hash_password(
            password
        )

        created_at = datetime.now().isoformat()

        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO users
            (
                name,
                email,
                password_hash,
                role,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                name,
                email,
                password_hash,
                role,
                created_at
            )
        )

        user_id = cursor.lastrowid

        connection.commit()

        return {
            "id": user_id,
            "name": name,
            "email": email,
            "role": role,
            "created_at": created_at
        }

    finally:

        connection.close()


# ============================================================
# GET USER BY EMAIL
# ============================================================

def get_user_by_email(email: str):

    email = email.strip().lower()

    connection = get_connection()

    try:

        user = connection.execute(
            """
            SELECT
                id,
                name,
                email,
                password_hash,
                role,
                created_at
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        if not user:

            return None

        return dict(user)

    finally:

        connection.close()


# ============================================================
# AUTHENTICATE USER
# ============================================================

def authenticate_user(
    email: str,
    password: str
):

    user = get_user_by_email(
        email
    )

    if not user:

        return None

    if not verify_password(
        password,
        user["password_hash"]
    ):

        return None

    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "created_at": user["created_at"]
    }


# ============================================================
# ADMIN CREATION
# ============================================================

def create_admin(
    name: str,
    email: str,
    password: str
):

    return create_user(
        name=name,
        email=email,
        password=password,
        role="admin"
    )


# ============================================================
# INITIALIZE
# ============================================================

initialize_auth_database()


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("ZeroGuard Authentication")
    print("=" * 60)

    initialize_auth_database()

    print(
        f"Database: {DATABASE_PATH}"
    )

    print(
        "Authentication database initialized successfully."
    )

    print("=" * 60)