# 🔐 JWKS Server - Project 2 (SQLite-backed)

This project extends a basic JWKS (JSON Web Key Set) server by adding **SQLite-based key storage**.
Instead of keeping keys in memory, private keys are securely stored in a database and retrieved when needed.

---

## 🚀 Features

* SQLite database for persistent key storage
* Automatic generation of:

  * ✅ Valid (unexpired) RSA key
  * ❌ Expired RSA key
* JWT (JSON Web Token) generation
* JWKS endpoint for public key distribution
* Support for expired token testing (`?expired=true`)
* SQL injection-safe queries using parameterized statements
* Fully tested with pytest

---

## 📁 Project Structure

```
jwks-server-project2/
│
├── app.py              # Flask server with endpoints
├── keys.py             # SQLite key management
├── tests/              # Test suite (pytest)
├── screenshots/        # Required output screenshots
├── requirements.txt    # Dependencies
├── verify.py           # Verification script
└── README.md
```

---

## ⚙️ Setup & Installation

1. Clone the repository:

```bash
git clone https://github.com/esatsglm/jwks-server-project2.git
cd jwks-server-project2
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the server:

```bash
python app.py
```

---

## 🌐 API Endpoints

### 🔑 `POST /auth`

Generates a JWT signed with a private key from the database.

* Default → uses **valid key**
* With query:

```bash
/auth?expired=true
```

→ uses **expired key**

Example:

```bash
curl -X POST http://127.0.0.1:8080/auth
```

---

### 📡 `GET /.well-known/jwks.json`

Returns **only unexpired public keys** in JWKS format.

Example:

```bash
curl http://127.0.0.1:8080/.well-known/jwks.json
```

---

## 🗄️ Database

* File: `totally_not_my_privateKeys.db`
* Table schema:

```sql
CREATE TABLE keys(
  kid INTEGER PRIMARY KEY AUTOINCREMENT,
  key BLOB NOT NULL,
  exp INTEGER NOT NULL
);
```

* Keys are stored as **PEM-encoded private keys**
* Expiration (`exp`) is stored as a Unix timestamp

---

## 🧪 Testing

Run tests with:

```bash
python -m pytest -v
```

✔ All tests pass:

* JWKS returns only valid keys
* JWT is correctly signed
* Expired token logic works

---

## 📸 Screenshots

Screenshots included in `/screenshots`:

* JWKS endpoint output
* Test results (`pytest`)

---

## 🔒 Security Notes

* Uses **parameterized SQL queries** to prevent SQL injection
* Private keys are stored securely in database
* Only **valid keys** are exposed via JWKS

---

## 📌 Summary

This project demonstrates:

* Secure key management with SQLite
* JWT authentication flow
* REST API design with Flask
* Testing and validation of authentication systems

---

## 👨‍💻 Author

**Esat  Kaan Saglam**  
Cybersecurity Student – University of North Texas  

 
LinkedIn: https://www.linkedin.com/in/esat-kaan-saglam/

## Key Improvement Over Project 1

- Keys are no longer stored in memory
- Keys are persisted in a SQLite database
- Keys survive server restarts
- Secure SQL queries prevent injection attacks

