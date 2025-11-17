from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
import json
from typing import Dict, Annotated
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt

# --- Configuration & Setup ---

app = FastAPI(
    title="iGnosis Auth Server",
    description="A simple auth server for the iGnosis backend task.",
    version="1.0.0"
)

USER_DB_FILE = "users.json"

# Use bcrypt_sha256 to avoid bcrypt's 72-byte limit (passlib pre-hashes with SHA256 before bcrypt)
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")

# --- JWT Configuration ---
# IMPORTANT: change SECRET_KEY to a secure, unpredictable value for production
SECRET_KEY = "your-very-secret-key-for-this-task"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 scheme (used to extract token from Authorization header)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="signin")


# --- Pydantic Models ---

class UserCreate(BaseModel):
    username: str = Field(..., min_length=4, pattern=r"^[a-z]{4,}$")
    password: str = Field(
        ...,
        min_length=5,
        max_length=128,
        pattern=r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{5,}$",
        description="Password must be at least 5 chars, contain 1 uppercase, 1 lowercase and 1 digit"
    )
    fname: str = Field(..., pattern=r"^[A-Za-z]+$")
    lname: str = Field(..., pattern=r"^[A-Za-z]+$")


class UserLogin(BaseModel):
    username: str
    password: str


class UserPublicData(BaseModel):
    fname: str
    lname: str
    password: str


class UserInDB(BaseModel):
    fname: str
    lname: str
    password: str  # hashed password


# --- Helpers (password hashing + JSON DB) ---

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def read_db() -> Dict[str, dict]:
    try:
        with open(USER_DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def write_db(data: Dict[str, dict]):
    with open(USER_DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


# --- JWT helpers ---

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    # jose accepts datetime for 'exp'
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- Dependency to get current user from JWT token ---

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> UserInDB:
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


# --- Endpoints ---

@app.get("/")
def read_root():
    return {"message": "Welcome to the iGnosis Auth Server!"}


@app.post("/signup", status_code=status.HTTP_201_CREATED)
def user_signup(user: UserCreate):
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
    # return structured response including the current user's data (hashed password included as requested)
    return {"result": True, "data": current_user.dict()}
