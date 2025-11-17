# main.py
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import json
import re
from typing import Dict, Any
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError

# ---------------------------
# App & Config
# ---------------------------
app = FastAPI(title="iGnosis Auth Server", description="Auth server", version="1.0.0")
USER_DB_FILE = "users.json"

# Use bcrypt_sha256 to avoid bcrypt 72-byte limit
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")

# JWT settings (replace SECRET_KEY for production)
SECRET_KEY = "your-very-secret-key-for-this-task"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Regex patterns
USERNAME_RE = re.compile(r"^[a-z]{4,}$")
NAME_RE = re.compile(r"^[A-Za-z]+$")


# ---------------------------
# Helpers: DB, hashing, JWT
# ---------------------------
def read_db() -> Dict[str, dict]:
    try:
        with open(USER_DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def write_db(data: Dict[str, dict]) -> None:
    with open(USER_DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ---------------------------
# Response helpers (match tests)
# ---------------------------
def result_ok(message: str, extra: Dict[str, Any] | None = None, status_code: int = 200) -> JSONResponse:
    payload: Dict[str, Any] = {"result": True, "message": message}
    if extra:
        payload.update(extra)
    return JSONResponse(status_code=status_code, content=payload)


def result_bad(message: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"result": True, "message": message})


def result_unauth(message: str) -> JSONResponse:
    return JSONResponse(status_code=401, content={"result": True, "message": message})


def result_internal(message: str = "Internal Server Error") -> JSONResponse:
    return JSONResponse(status_code=500, content={"result": True, "message": message})


# ---------------------------
# Validation helpers (manual)
# ---------------------------
def validate_signup_payload(data: dict) -> (bool, str):
    required = ("username", "password", "fname", "lname")
    if not all(k in data and data[k] is not None and str(data[k]).strip() != "" for k in required):
        return False, "fields can't be empty"

    username = str(data["username"])
    if not USERNAME_RE.fullmatch(username):
        return False, "username check failed"

    pw = str(data["password"])
    if len(pw) < 5 or not re.search(r"[a-z]", pw) or not re.search(r"[A-Z]", pw) or not re.search(r"\d", pw) or re.search(r"[^A-Za-z\d]", pw):
        return False, "password check failed"

    if not NAME_RE.fullmatch(str(data["fname"])) or not NAME_RE.fullmatch(str(data["lname"])):
        return False, "fname or lname check failed"

    return True, ""


def validate_signin_payload(data: dict) -> (bool, str):
    if not data or "username" not in data or "password" not in data or not data["username"] or not data["password"]:
        return False, "Please provide username and password"
    return True, ""


# ---------------------------
# Endpoints (manual parsing to control responses)
# ---------------------------
@app.get("/")
def root():
    return JSONResponse(status_code=200, content={"result": True, "message": "Welcome to the iGnosis Auth Server!"})


@app.post("/signup")
async def signup(request: Request):
    # parse JSON body manually to control error messages and status codes
    try:
        body = await request.json()
    except Exception:
        # invalid JSON or empty body
        return result_bad("fields can't be empty", status_code=400)

    if not isinstance(body, dict):
        return result_bad("fields can't be empty", status_code=400)

    ok, err = validate_signup_payload(body)
    if not ok:
        return result_bad(err, status_code=400)

    username = str(body["username"])
    fname = str(body["fname"])
    lname = str(body["lname"])
    password = str(body["password"])

    db = read_db()
    if username in db:
        return result_bad("username already exists", status_code=400)

    try:
        hashed = get_password_hash(password)
        db[username] = {"fname": fname, "lname": lname, "password": hashed}
        write_db(db)
    except Exception:
        return result_internal()

    # success: tests expect 201 and message "SignUp success. Please proceed to Signin"
    return result_ok("SignUp success. Please proceed to Signin", status_code=201)


@app.post("/signin")
async def signin(request: Request):
    try:
        body = await request.json()
    except Exception:
        return result_bad("Please provide username and password", status_code=400)

    if not isinstance(body, dict):
        return result_bad("Please provide username and password", status_code=400)

    ok, err = validate_signin_payload(body)
    if not ok:
        return result_bad(err, status_code=400)

    username = str(body["username"])
    password = str(body["password"])

    db = read_db()
    if username not in db:
        return result_bad("Invalid username/password", status_code=400)

    user = db[username]
    if not verify_password(password, user["password"]):
        return result_bad("Invalid username/password", status_code=400)

    token = create_access_token({"username": username, "firstname": user["fname"]}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    # tests expect message "Log In Successful"
    return JSONResponse(status_code=200, content={"result": True, "jwt": token, "message": "Log In Successful"})


@app.get("/user/me")
async def user_me(request: Request):
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
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

    db = read_db()
    user = db.get(username)
    if not user:
        return result_unauth("JWT Verification Failed")

    # return user object (hashed password included) as tests expect
    return JSONResponse(status_code=200, content={"result": True, "data": user})
