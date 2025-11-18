# main.py
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import json
import re
from typing import Dict, Any
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError

# ==============================================================
#  App Configuration
# ==============================================================
app = FastAPI(
    title="iGnosis Auth Server",
    description="Auth server implementation for hiring task",
    version="1.0.0"
)

# --- USING JSON FILE INSTEAD OF IN-MEMORY DB ---
USER_DB_FILE = "users.json"
# -----------------------------------------------

# Use 'bcrypt' to match your requirements.txt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = "your-very-secret-key-for-this-task"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Regex validation
USERNAME_RE = re.compile(r"^[a-z]{4,}$")
NAME_RE = re.compile(r"^[A-Za-z]+$")


# ==============================================================
#  Helper Functions — Hashing, JWT, Responses
# ==============================================================

# --- ADDED DB FUNCTIONS BACK IN ---
def read_db() -> Dict[str, dict]:
    """Reads the user database from the JSON file."""
    try:
        with open(USER_DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # If file is empty or missing, return empty dict
        return {}

def write_db(data: Dict[str, dict]) -> None:
    """Writes the user database to the JSON file."""
    with open(USER_DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
# ----------------------------------

def get_password_hash(password: str) -> str:
    """Hashes a plain-text password."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Verifies a plain-text password against a hash."""
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Creates a new JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=15)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ==============================================================
#  Custom Response Helpers
# (Formatted to pass the exact Postman test requirements)
# ==============================================================

def result_ok(message: str, extra: Dict[str, Any] | None = None, status_code: int = 200):
    """Returns a standard JSON success response."""
    payload = {"result": True, "message": message}
    if extra:
        payload.update(extra)
    return JSONResponse(status_code=status_code, content=payload)


def result_bad(message: str, status_code: int = 400):
    """Returns a 400 Bad Request error, formatted as tests expect."""
    return JSONResponse(status_code=status_code, content={"result": False, "error": message})


def result_unauth(message: str):
    """Returns a 401 Unauthorized error, formatted as tests expect."""
    return JSONResponse(status_code=401, content={"result": False, "error": message})


def result_internal(message: str = "Internal Server Error"):
    """Returns a 500 Internal Server Error, formatted as tests expect."""
    return JSONResponse(status_code=500, content={"result": False, "error": message})


# ==============================================================
#  Manual Validation Helpers
# ==============================================================

def validate_signup_payload(data: dict) -> (bool, str):
    """Validate the entire signup JSON body."""
    required = ("username", "password", "fname", "lname")

    if not all(k in data and str(data[k]).strip() for k in required):
        return False, "fields can't be empty"

    if not USERNAME_RE.fullmatch(str(data["username"])):
        return False, "username check failed"

    pw = str(data["password"])
    if (
        len(pw) < 5
        or not re.search(r"[a-z]", pw)
        or not re.search(r"[A-Z]", pw)
        or not re.search(r"\d", pw)
        or re.search(r"[^A-Za-z\d]", pw)
    ):
        return False, "password check failed"

    if not NAME_RE.fullmatch(str(data["fname"])) or not NAME_RE.fullmatch(str(data["lname"])):
        return False, "fname or lname check failed"

    return True, ""


def validate_signin_payload(data: dict) -> (bool, str):
    """Validate the entire signin JSON body."""
    if (
        not data
        or "username" not in data
        or "password" not in data
        or not data["username"]
        or not data["password"]
    ):
        return False, "Please provide username and password"
    return True, ""


# ==============================================================
#  API Endpoints
# ==============================================================

@app.get("/")
def root():
    """Root endpoint to confirm the server is running."""
    return JSONResponse(
        status_code=200,
        content={"result": True, "message": "Welcome to the iGnosis Auth Server!"}
    )


# ------------------ SIGNUP ------------------
@app.post("/signup")
async def signup(request: Request):
    """Handles new user registration."""
    try:
        body = await request.json()
    except Exception:
        return result_bad("fields can't be empty")

    if not isinstance(body, dict):
        return result_bad("fields can't be empty")

    ok, err = validate_signup_payload(body)
    if not ok:
        return result_bad(err)

    username = body["username"]
    
    # --- USING FILE DB ---
    db = read_db()
    
    if username in db:
        return result_bad("username already exists")

    try:
        db[username] = {
            "fname": body["fname"],
            "lname": body["lname"],
            "password": get_password_hash(body["password"])
        }
        # --- SAVING TO FILE ---
        write_db(db)
    except Exception:
        return result_internal()

    return result_ok("SignUp success. Please proceed to Signin", status_code=200)


# ------------------ SIGNIN ------------------
@app.post("/signin")
async def signin(request: Request):
    """Handles user login and returns a JWT."""
    try:
        body = await request.json()
    except Exception:
        return result_bad("Please provide username and password")

    if not isinstance(body, dict):
        return result_bad("Please provide username and password")

    ok, err = validate_signin_payload(body)
    if not ok:
        return result_bad(err)

    username = body["username"]
    password = body["password"]

    # --- USING FILE DB ---
    db = read_db()
    
    if username not in db:
        return result_bad("Invalid username/password", status_code=401)

    user = db[username]

    if not verify_password(password, user["password"]):
        return result_bad("Invalid username/password", status_code=401)

    token = create_access_token(
        {"username": username, "firstname": user["fname"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return JSONResponse(
        status_code=200,
        content={"result": True, "jwt": token, "message": "Signin success"}
    )


# ------------------ USER INFO ------------------
@app.get("/user/me")
async def user_me(request: Request):
    """Returns the current user's details from their JWT."""
    auth = request.headers.get("Authorization") or request.headers.get("authorization")

    if not auth:
        return result_unauth("Please provide a JWT token")

    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return result_unauth("JWT Verification Failed")

    token = parts[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("username")
        if not username:
            return result_unauth("JWT Verification Failed")
    except JWTError:
        return result_unauth("JWT Verification Failed")

    # --- USING FILE DB ---
    db = read_db()
    
    user = db.get(username)
    if not user:
        return result_unauth("JWT Verification Failed")

    return JSONResponse(status_code=200, content={"result": True, "data": user})