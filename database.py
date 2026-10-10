import os
import sqlite3
from flask import g, current_app, has_app_context

def get_db_path():
    """Retrieve the database path from Flask config or environment default."""
    if has_app_context():
        cfg_path = current_app.config.get("DATABASE_PATH")
        if cfg_path:
            return cfg_path
    base_dir = os.path.abspath(os.path.dirname(__file__))
    return os.environ.get("DATABASE_PATH", os.path.join(base_dir, "instance", "phc.db"))

def create_connection(db_path):
    """Create a new SQLite connection with row factory and foreign keys enabled."""
    if db_path != ":memory:":
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def get_db(custom_path=None):
    """
    Get or create a SQLite database connection.
    If inside Flask app/request context and the path matches the context's db,
    stores and reuses the connection on flask.g, closing it on teardown.
    """
    target_path = custom_path or get_db_path()

    if has_app_context():
        app_db_path = get_db_path()
        # If no custom_path is specified, or it matches the current app's configured path
        if custom_path is None or os.path.abspath(custom_path) == os.path.abspath(app_db_path):
            if "db" not in g or g.db is None:
                g.db = create_connection(app_db_path)
            return g.db

    # Standalone connection (outside app context, or a separate custom path)
    return create_connection(target_path)

def close_db(e=None):
    """Close the database connection stored on flask.g if present."""
    if has_app_context():
        db = g.pop("db", None)
        if db is not None:
            try:
                db.close()
            except Exception:
                pass

def init_db(custom_path=None):
    """Initialize database tables and indexes from schema.sql."""
    base_dir = os.path.abspath(os.path.dirname(__file__))
    schema_path = os.path.join(base_dir, "schema.sql")

    is_standalone = False
    if not has_app_context() or (custom_path is not None and os.path.abspath(custom_path) != os.path.abspath(get_db_path())):
        conn = get_db(custom_path)
        is_standalone = True
    else:
        conn = get_db()

    try:
        with open(schema_path, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        conn.commit()
    finally:
        if is_standalone:
            conn.close()
    return conn

def query_db(query, args=(), one=False, conn=None):
    """Execute a parameterized query and return row results."""
    close_after = False
    if conn is None:
        if has_app_context():
            conn = get_db()
        else:
            conn = get_db()
            close_after = True
    try:
        cur = conn.execute(query, args)
        rv = cur.fetchall()
        cur.close()
        return (rv[0] if rv else None) if one else rv
    finally:
        if close_after:
            conn.close()

def execute_db(query, args=(), commit=True, conn=None):
    """Execute an INSERT/UPDATE/DELETE query and return (lastrowid, rowcount)."""
    close_after = False
    if conn is None:
        if has_app_context():
            conn = get_db()
        else:
            conn = get_db()
            close_after = True
    try:
        cur = conn.execute(query, args)
        last_id = cur.lastrowid
        row_count = cur.rowcount
        cur.close()
        if commit:
            conn.commit()
        return last_id, row_count
    finally:
        if close_after:
            conn.close()