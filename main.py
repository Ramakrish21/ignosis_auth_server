from fastapi import FastAPI, HTTPException, status, Depends, Request, Header
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, validator
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import re
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

# --- FIX #1: In-Memory Database ---
# We use a simple dictionary instead of a file.
# Render's filesystem is read-only, so write_db() was causing the 500 Error.
db: Dict[str, dict] = {}
# --- End of FIX #1 ---


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- JWT Configuration ---
SECRET_KEY = "your-very-secret-key-for-this-task"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# We still need this, but our new dependency will be different
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="signin")


# --- FIX #2: Custom Exception Handler for 422 Errors ---
# This catches FastAPI's 422 Validation Errors and returns
# the 400 Bad Request + custom JSON that the test expects.
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Determine the error message based on the endpoint
    url_path = request.url.path
    error_message = "Validation Error" # Default
    
    if url_path == "/signup":
        error_message = "Invalid data" # A generic one
    elif url_path == "/signin":
        error_message = "Please provide username and password"

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"result": False, "error": error_message}
    )
# --- End of FIX #2 ---


# --- Pydantic Models (Data Validation) ---

class UserCreate(BaseModel):
    username: str = Field(
        ...,
        min_length=4,
        pattern=r"^[a-z]{4,}$", 
        description="Username must be at least 4 characters and contain only lowercase English alphabets."
    )
    password: str = Field(
        ...,
        min_length=5,
        description="Password must be at least 5 characters, contain at least 1 uppercase, 1 lowercase, 1 number, and no special characters."
    )
    fname: str = Field(
        ...,
        pattern=r"^[A-Za-z]+$",
        description="First name must only contain English alphabets."
    )
    lname: str = Field(
        ...,
        pattern=r"^[A-Za-z]+$",
        description="Last name must only contain English alphabets."
    )

    @validator('password')
    def validate_password_rules(cls, value):
        if len(value) < 5:
            raise ValueError('Password must be at least 5 characters')
        if not re.search(r'[a-z]', value):
            raise ValueError('Password must contain at least 1 lowercase character')
        if not re.search(r'[A-Z]', value):
            raise ValueError('Password must contain at least 1 uppercase character')
        if not re.search(r'\d', value):
            raise ValueError('Password must contain at least 1 number')
        if re.search(r'[^A-Za-z\d]', value):
            raise ValueError('Password must not contain special characters')
        return value

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
    password: str

# --- Helper Functions (Password) ---

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# --- File I/O functions are no longer needed ---
# def read_db(): ...
# def write_db(data): ...


# --- JWT Helper Function ---
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- FIX #3: Custom Authentication Dependency ---
# We manually check the 'Authorization' header to
# return the exact 400 error JSON the test expects.
async def get_current_user(
    authorization: Annotated[str | None, Header()] = None
) -> UserInDB:
    
    # Custom error for bad token
    credentials_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="JWT Verification Failed",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Custom error for missing token
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide a JWT token"
        )

    # Manually parse the "Bearer <token>" string
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise credentials_exception
    except ValueError:
        raise credentials_exception

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    # Use the global 'db' dictionary
    user = db.get(username)
    
    if user is None:
        raise credentials_exception
    return UserInDB(**user)

# Custom handler to return the JSON the test expects
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"result": False, "error": exc.detail},
    )
# --- End of FIX #3 ---


# --- API Endpoints ---

@app.get("/")
def read_root():
    return {"message": "Welcome to the iGnosis Auth Server!"}

@app.post("/signup", status_code=status.HTTP_201_CREATED)
def user_signup(user: UserCreate):
    # Use global 'db' dictionary
    if user.username in db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    hashed_password = get_password_hash(user.password)
    user_data = {
        "fname": user.fname,
        "lname": user.lname,
        "password": hashed_password
    }
    db[user.username] = user_data # Add to dictionary
    
    return {
        "result": True,
        "message": "SignUp success. Please proceed to Signin"
    }

@app.post("/signin")
def user_signin(form_data: UserLogin):
    # Use global 'db' dictionary
    if form_data.username not in db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid credentials"
        )
        
    user_from_db = db[form_data.username]
    
    if not verify_password(form_data.password, user_from_db['password']):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid credentials"
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token_data = {
        "username": form_data.username,
        "firstname": user_from_db['fname']
    }
    access_token = create_access_token(
        data=token_data, expires_delta=access_token_expires
    )
    
    return {
        "result": True,
        "jwt": access_token,
        "message": "Signin success"
    }

@app.get("/user/me")
def read_users_me(
    # Use our new dependency
    current_user: Annotated[UserInDB, Depends(get_current_user)]
):
    # The task asks for this exact response format
    return {
        "result": True,
        "data": {
            "fname": current_user.fname,
            "lname": current_user.lname,
            "password": current_user.password
        }
    }