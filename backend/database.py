import hashlib
import secrets
import sqlite3
from datetime import datetime
from pathlib import Path


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATABASE_NAME = BASE_DIR / "zeroguard.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    connection = sqlite3.connect(
        str(DATABASE_NAME),
        check_same_thread=False
    )

    connection.row_factory = sqlite3.Row

    # Enable foreign keys
    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


# ============================================================
# ADD COLUMN IF MISSING
# ============================================================

def add_column_if_missing(
    connection,
    table_name,
    column_name,
    column_definition
):

    cursor = connection.cursor()

    columns = cursor.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    existing_columns = [
        column["name"]
        for column in columns
    ]

    if column_name not in existing_columns:

        cursor.execute(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name}
            {column_definition}
            """
        )

        print(
            f"Added column '{column_name}' "
            f"to table '{table_name}'."
        )


def hash_legacy_password(password):
    """Convert a pre-existing plaintext password during the one-time migration."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    ).hex()
    return f"{salt}${digest}"


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()

    # ========================================================
    # DEVICES TABLE
    # ========================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            name TEXT NOT NULL,

            ip_address TEXT NOT NULL UNIQUE,

            status TEXT DEFAULT 'online',

            risk_level TEXT DEFAULT 'low',

            last_seen TEXT

        )
        """
    )

    # --------------------------------------------------------
    # DEVICE MIGRATION
    # --------------------------------------------------------

    add_column_if_missing(
        connection,
        "devices",
        "device_name",
        "TEXT"
    )

    add_column_if_missing(
        connection,
        "devices",
        "mac_address",
        "TEXT"
    )

    add_column_if_missing(
        connection,
        "devices",
        "device_type",
        "TEXT"
    )

    add_column_if_missing(
        connection,
        "devices",
        "created_at",
        "TEXT"
    )


    # ========================================================
    # THREATS TABLE
    # ========================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS threats (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            device_id INTEGER,

            threat_type TEXT,

            severity TEXT,

            confidence REAL,

            description TEXT,

            status TEXT DEFAULT 'new',

            detected_at TEXT,

            FOREIGN KEY (device_id)
            REFERENCES devices(id)

        )
        """
    )


    # ========================================================
    # NETWORK EVENTS TABLE
    # ========================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS network_events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            source_ip TEXT NOT NULL,

            destination_ip TEXT NOT NULL,

            protocol TEXT,

            port INTEGER,

            event_type TEXT,

            risk TEXT DEFAULT 'low',

            timestamp TEXT,

            threat_id INTEGER,

            FOREIGN KEY (threat_id)
            REFERENCES threats(id)

        )
        """
    )

    # --------------------------------------------------------
    # NETWORK EVENTS MIGRATION
    # --------------------------------------------------------

    add_column_if_missing(
        connection,
        "network_events",
        "threat_id",
        "INTEGER"
    )


    # ========================================================
    # INCIDENTS TABLE
    # ========================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            threat_id INTEGER,

            status TEXT DEFAULT 'new',

            created_at TEXT,

            resolved_at TEXT,

            FOREIGN KEY (threat_id)
            REFERENCES threats(id)

        )
        """
    )


    # ========================================================
    # RESPONSE ACTIONS TABLE
    # ========================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS response_actions (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id INTEGER,

            action_type TEXT,

            status TEXT,

            created_at TEXT,

            FOREIGN KEY (incident_id)
            REFERENCES incidents(id)

        )
        """
    )


    # ========================================================
    # USERS TABLE
    # ========================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            name TEXT NOT NULL,

            username TEXT UNIQUE,

            email TEXT UNIQUE,

            password_hash TEXT NOT NULL,

            password TEXT,

            role TEXT DEFAULT 'user',

            status TEXT DEFAULT 'active',

            created_at TEXT,

            last_login TEXT

        )
        """
    )


    # ========================================================
    # USERS MIGRATION
    # ========================================================

    # Existing database may already have users table
    # with different columns.

    add_column_if_missing(
        connection,
        "users",
        "name",
        "TEXT DEFAULT 'User'"
    )

    add_column_if_missing(
        connection,
        "users",
        "username",
        "TEXT"
    )

    add_column_if_missing(
        connection,
        "users",
        "email",
        "TEXT"
    )

    add_column_if_missing(
        connection,
        "users",
        "password",
        "TEXT"
    )

    add_column_if_missing(
        connection,
        "users",
        "password_hash",
        "TEXT"
    )

    add_column_if_missing(
        connection,
        "users",
        "role",
        "TEXT DEFAULT 'user'"
    )

    add_column_if_missing(
        connection,
        "users",
        "status",
        "TEXT DEFAULT 'active'"
    )

    add_column_if_missing(
        connection,
        "users",
        "created_at",
        "TEXT"
    )

    add_column_if_missing(
        connection,
        "users",
        "last_login",
        "TEXT"
    )


    # ========================================================
    # FIX OLD USER RECORDS
    # ========================================================

    # If old records have NULL name, give them a safe value.

    cursor.execute(
        """
        UPDATE users
        SET name = 'User'
        WHERE name IS NULL
        """
    )

    cursor.execute(
        """
        UPDATE users
        SET username = 'user_' || id
        WHERE username IS NULL OR TRIM(username) = ''
        """
    )

    cursor.execute(
        """
        UPDATE users
        SET email = 'user_' || id || '@legacy.local'
        WHERE email IS NULL OR TRIM(email) = ''
        """
    )

    # Set missing status values

    cursor.execute(
        """
        UPDATE users
        SET status = 'active'
        WHERE status IS NULL
        """
    )

    # Set missing role values

    cursor.execute(
        """
        UPDATE users
        SET role = 'user'
        WHERE role IS NULL
        """
    )

    cursor.execute(
        """
        UPDATE users
        SET created_at = ?
        WHERE created_at IS NULL OR TRIM(created_at) = ''
        """,
        (datetime.now().isoformat(),)
    )

    legacy_passwords = cursor.execute(
        """
        SELECT id, password
        FROM users
        WHERE (password_hash IS NULL OR TRIM(password_hash) = '')
          AND password IS NOT NULL AND TRIM(password) != ''
        """
    ).fetchall()

    for user in legacy_passwords:
        cursor.execute(
            """
            UPDATE users
            SET password_hash = ?, password = NULL
            WHERE id = ?
            """,
            (hash_legacy_password(user["password"]), user["id"])
        )


    # ========================================================
    # SAVE
    # ========================================================

    connection.commit()

    connection.close()

    print(
        "Database initialized successfully."
    )


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    initialize_database()

    print()
    print("=" * 50)
    print("ZeroGuard Database")
    print("=" * 50)
    print()
    print(
        f"Database: {DATABASE_NAME}"
    )
    print()
    print(
        "Database initialization complete."
    )
    print()