from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, validator
import re
import json
from typing import Dict, Annotated
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt

# -----------------------------------------------------------------------------
# App + Configuration
# -----------------------------------------------------------------------------
app = FastAPI(
    title="iGnosis Auth Server",
    description="A simple auth server for the iGnosis backend task.",
    version="1.0.0",
)

# JSON file used as a simple DB (username -> user data)
USER_DB_FILE = "users.json"

# Use bcrypt_sha256 to avoid bcrypt's 72-byte limit (Passlib pre-hashes with SHA256).
# If you explicitly want plain bcrypt, change to: CryptContext(schemes=["bcrypt"], ...)
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")

# JWT settings (replace SECRET_KEY for production)
SECRET_KEY = "your-very-secret-key-for-this-task"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 scheme: extractor for "Authorization: Bearer <token>" header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="signin")


# -----------------------------------------------------------------------------
# Pydantic models
# -----------------------------------------------------------------------------

class UserCreate(BaseModel):
    """
    Model for signup payload. Uses Field validations and a custom validator
    for the password rule set (uppercase, lowercase, digit, no special chars).
    """
    username: str = Field(
        ...,
        min_length=4,
        pattern=r"^[a-z]{4,}$",
        description="Username must be ≥4 chars and only lowercase English alphabets.",
    )

    # We validate the password via the validator below (keeps Field simple)
    password: str = Field(
        ...,
        min_length=5,
        description="Password must be at least 5 characters, contain 1 uppercase, 1 lowercase and 1 number, and no special characters.",
    )

    fname: str = Field(..., pattern=r"^[A-Za-z]+$", description="First name: alphabets only.")
    lname: str = Field(..., pattern=r"^[A-Za-z]+$", description="Last name: alphabets only.")

    @validator("password")
    def validate_password_rules(cls, value: str) -> str:
        """
        Enforces password rules:
         - minimum length 5 (Field already ensures min_length but we keep check)
         - at least 1 lowercase letter
         - at least 1 uppercase letter
         - at least 1 digit
         - no special characters (only A-Za-z0-9 allowed)
        """
        if len(value) < 5:
            raise ValueError("Password must be at least 5 characters")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least 1 lowercase character")
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least 1 uppercase character")
        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least 1 number")
        if re.search(r"[^A-Za-z\d]", value):
            raise ValueError("Password must not contain special characters")
        return value


class UserLogin(BaseModel):
    """Model for signin payload."""
    username: str
    password: str


class UserPublicData(BaseModel):
    """Model for returned user data (public-facing)."""
    fname: str
    lname: str
    password: str  # hashed password (as requested)


class UserInDB(BaseModel):
    """Internal representation of user data stored in DB."""
    fname: str
    lname: str
    password: str  # hashed password


# -----------------------------------------------------------------------------
# Utilities: password hashing + JSON DB helpers
# -----------------------------------------------------------------------------

def get_password_hash(password: str) -> str:
    """Hash a plain password using passlib context."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def read_db() -> Dict[str, dict]:
    """Read the JSON file and return DB dict. Return {} if missing/corrupt."""
    try:
        with open(USER_DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def write_db(data: Dict[str, dict]) -> None:
    """Persist the DB dict to the JSON file."""
    with open(USER_DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


# -----------------------------------------------------------------------------
# JWT helpers
# -----------------------------------------------------------------------------

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create a signed JWT with an expiration time."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token


# -----------------------------------------------------------------------------
# Authentication dependency
# -----------------------------------------------------------------------------

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> UserInDB:
    """
    Dependency that:
      - decodes the JWT token,
      - extracts username,
      - loads user from DB, and
      - returns a UserInDB instance.
    Raises a 401 on any failure.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Please provide a JWT token")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("username")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    db = read_db()
    user = db.get(username)
    if user is None:
        raise credentials_exception

    return UserInDB(**user)


# -----------------------------------------------------------------------------
# API endpoints
# -----------------------------------------------------------------------------

@app.get("/")
def read_root():
    """Root endpoint — quick sanity check."""
    return {"message": "Welcome to the iGnosis Auth Server!"}


@app.post("/signup", status_code=status.HTTP_201_CREATED)
def user_signup(user: UserCreate):
    """
    Create a new user:
      - validate payload via UserCreate model
      - ensure username uniqueness
      - hash password and save user (fname, lname, hashed password)
    """
    db = read_db()
    if user.username in db:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")

    hashed_password = get_password_hash(user.password)
    user_data = {"fname": user.fname, "lname": user.lname, "password": hashed_password}
    db[user.username] = user_data
    write_db(db)

    return {"result": True, "message": "SignUp success. Please proceed to Signin"}


@app.post("/signin")
def user_signin(form_data: UserLogin):
    """
    Sign-in endpoint:
      - verifies username & password
      - returns a JWT (access token) on success
    """
    db = read_db()
    if form_data.username not in db:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid credentials")

    user_from_db = db[form_data.username]
    if not verify_password(form_data.password, user_from_db["password"]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid credentials")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token_data = {"username": form_data.username, "firstname": user_from_db["fname"]}
    access_token = create_access_token(data=token_data, expires_delta=access_token_expires)

    return {"result": True, "jwt": access_token, "message": "Signin success"}


@app.get("/user/me")
def read_users_me(current_user: Annotated[UserInDB, Depends(get_current_user)]):
    """
    Protected endpoint returning the current user's stored data.
    Returns the hashed password as requested. The dependency ensures token validity.
    """
    return {"result": True, "data": current_user.dict()}
