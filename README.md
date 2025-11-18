# iGnosis Auth Server

A robust authentication backend server built with **FastAPI** (Python). This project implements user signup, secure sign-in with JWT (JSON Web Tokens), and a protected route to retrieve user information.

It is designed to pass a specific Postman test collection and is deployed on **Render**.

## 🚀 Features

* **User Signup:** Registers new users with strict validation (regex for username, password strength, etc.).
* **Secure Signin:** Authenticates users and issues a secure JWT access token.
* **Password Hashing:** Uses **BCrypt** to securely hash and verify passwords.
* **JWT Authentication:** Protects routes using Bearer token authentication.
* **In-Memory Database:** Uses a Python dictionary for high-speed storage (compatible with Render's read-only filesystem).
* **Custom Error Handling:** Overrides standard FastAPI errors to match specific API test requirements (returns 400 instead of 422/401 in specific cases).

## 🛠️ Tech Stack

* **Language:** Python 3.11
* **Framework:** FastAPI
* **Server:** Uvicorn
* **Security:** Passlib (BCrypt), Python-Jose (JWT)
* **Testing:** Postman / Newman

## 📂 Project Structure

```text
ignosis_auth_server/
├── main.py             # The complete application code (API, DB, Validation, Auth)
├── requirements.txt    # List of dependencies (fastapi, uvicorn, passlib, python-jose)
├── runtime.txt         # Config to force Render to use Python 3.11
├── test.sh             # Shell script to automate testing with Newman
├── .gitignore          # Files to ignore in Git (venv, __pycache__)
└── README.md           # Project documentation