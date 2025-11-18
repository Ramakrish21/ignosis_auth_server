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

# In-memory database (required by Render; avoids file I/O issues)
db: Dict[str, dict] = {}

# Password hashing using bcrypt_sha256
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")

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

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create a JWT token with expiry."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=15)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ==============================================================
#  Response Helpers (match EXACT test expectations)
# ==============================================================

def result_ok(message: str, extra: Dict[str, Any] | None = None, status_code: int = 200):
    payload = {"result": True, "message": message}
    if extra:
        payload.update(extra)
    return JSONResponse(status_code=status_code, content=payload)


def result_bad(message: str, status_code: int = 400):
    return JSONResponse(status_code=status_code, content={"result": False, "error": message})


def result_unauth(message: str):
    return JSONResponse(status_code=401, content={"result": False, "error": message})


def result_internal(message: str = "Internal Server Error"):
    return JSONResponse(status_code=500, content={"result": False, "error": message})


# ==============================================================
#  Validation Helpers
# ==============================================================

def validate_signup_payload(data: dict) -> (bool, str):
    """Validate signup body fields manually."""
    required = ("username", "password", "fname", "lname")

    # Check empty fields
    if not all(k in data and str(data[k]).strip() for k in required):
        return False, "fields can't be empty"

    # Username validation
    if not USERNAME_RE.fullmatch(str(data["username"])):
        return False, "username check failed"

    # Password validation
    pw = str(data["password"])
    if (
        len(pw) < 5
        or not re.search(r"[a-z]", pw)
        or not re.search(r"[A-Z]", pw)
        or not re.search(r"\d", pw)
        or re.search(r"[^A-Za-z\d]", pw)
    ):
        return False, "password check failed"

    # Name validation
    if not NAME_RE.fullmatch(str(data["fname"])) or not NAME_RE.fullmatch(str(data["lname"])):
        return False, "fname or lname check failed"

    return True, ""


def validate_signin_payload(data: dict) -> (bool, str):
    """Validate signin body fields manually."""
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
    return JSONResponse(
        status_code=200,
        content={"result": True, "message": "Welcome to the iGnosis Auth Server!"}
    )


# ------------------ SIGNUP ------------------
@app.post("/signup")
async def signup(request: Request):
    # Parse JSON body
    try:
        body = await request.json()
    except Exception:
        return result_bad("fields can't be empty")

    if not isinstance(body, dict):
        return result_bad("fields can't be empty")

    # Validate fields
    ok, err = validate_signup_payload(body)
    if not ok:
        return result_bad(err)

    username = body["username"]

    # Check unique username
    if username in db:
        return result_bad("username already exists")

    # Save user
    try:
        db[username] = {
            "fname": body["fname"],
            "lname": body["lname"],
            "password": get_password_hash(body["password"])
        }
    except Exception:
        return result_internal()

    # Tests expect status **200**
    return result_ok("SignUp success. Please proceed to Signin", status_code=200)


# ------------------ SIGNIN ------------------
@app.post("/signin")
async def signin(request: Request):
    try:
        body = await request.json()
    except Exception:
        return result_bad("Please provide username and password")

    if not isinstance(body, dict):
        return result_bad("Please provide username and password")

    # Validate fields
    ok, err = validate_signin_payload(body)
    if not ok:
        return result_bad(err)

    username = body["username"]
    password = body["password"]

    # Invalid user (tests expect 401)
    if username not in db:
        return result_bad("Invalid username/password", status_code=401)

    user = db[username]

    # Wrong password → 401
    if not verify_password(password, user["password"]):
        return result_bad("Invalid username/password", status_code=401)

    # Create token
    token = create_access_token(
        {"username": username, "firstname": user["fname"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    # Tests expect: "Signin success"
    return JSONResponse(
        status_code=200,
        content={"result": True, "jwt": token, "message": "Signin success"}
    )


# ------------------ USER INFO ------------------
@app.get("/user/me")
async def user_me(request: Request):
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

    user = db.get(username)
    if not user:
        return result_unauth("JWT Verification Failed")

    return JSONResponse(status_code=200, content={"result": True, "data": user})
