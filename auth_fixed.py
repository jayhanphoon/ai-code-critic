import os
import secrets
import time
import bcrypt
from typing import Optional, Dict, List, Tuple

# In‑memory user store (replace with a real database in production)
# Passwords are stored as bcrypt hashes.
USERS_DB: Dict[str, bytes] = {}

# In‑memory session store (token -> username)
SESSIONS: Dict[str, str] = {}

# Rate limiting: IP -> list of timestamps of recent requests
RATE_LIMIT: Dict[str, List[float]] = {}
RATE_LIMIT_WINDOW = 60          # seconds
RATE_LIMIT_MAX_ATTEMPTS = 5     # max attempts per window per IP

# Secret key for session tokens (fallback: auto‑generated per process start)
SECRET_KEY = os.environ.get("AUTH_SECRET_KEY", secrets.token_hex(32))

def _init_default_user():
    """
    Initialize a default admin user from environment variables.
    If not set, no default user exists.
    """
    admin_username = os.environ.get("ADMIN_USERNAME", "admin")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if admin_password:
        # Hash the provided password
        hashed = bcrypt.hashpw(admin_password.encode("utf-8"), bcrypt.gensalt())
        USERS_DB[admin_username] = hashed

def _check_rate_limit(ip_address: str) -> bool:
    """
    Check if the given IP has exceeded the rate limit.
    Returns True if allowed, False if rate limit exceeded.
    """
    now = time.time()
    timestamps = RATE_LIMIT.get(ip_address, [])
    # Remove timestamps older than the window
    timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(timestamps) >= RATE_LIMIT_MAX_ATTEMPTS:
        return False
    # Record the attempt
    timestamps.append(now)
    RATE_LIMIT[ip_address] = timestamps
    return True

def login_user(username: str, password: str, ip_address: Optional[str] = None) -> Optional[str]:
    """
    Authenticate a user.
    Returns a session token on success, None on failure.
    The token should be included in subsequent requests to verify the session.
    """
    # Use a default IP if none provided (for testing or non‑network contexts)
    if ip_address is None:
        ip_address = "127.0.0.1"

    # 1. Rate limiting
    if not _check_rate_limit(ip_address):
        # Log the rate limit event without exposing credentials
        print(f"Rate limit exceeded for IP {ip_address}")
        return None

    # 2. Safe logging – only non‑sensitive information
    print(f"Login attempt for user {username} from IP {ip_address}")

    # 3. Verify user exists and password matches (constant‑time hashing)
    stored_hash = USERS_DB.get(username)
    if stored_hash is None:
        # User not found – do not reveal that the username doesn't exist
        print(f"Login failed for user {username}")
        return None

    # Verify password against stored hash
    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        print(f"Login failed for user {username}")
        return None

    # 4. Successful authentication – generate session token
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = username
    print(f"Login successful for user {username}")
    return token

def get_session_user(token: str) -> Optional[str]:
    """
    Retrieve the username associated with a valid session token.
    Returns None if the token is invalid or expired.
    """
    return SESSIONS.get(token)

def logout_user(token: str) -> None:
    """Invalidate a session token."""
    SESSIONS.pop(token, None)

# Auto‑initialize the default user when module is loaded
_init_default_user()