# Basic JWKS Server (Python + Flask)

## Overview

This project implements a RESTful JWKS (JSON Web Key Set) server in Python using Flask.

The server demonstrates:

- RSA key pair generation
- Unique `kid` assignment for each key
- Key expiration handling
- JWKS endpoint serving only unexpired public keys
- JWT issuance signed with RS256
- Expired token simulation via query parameter
- Automated test suite with 99% coverage

This project simulates a real-world authentication flow including key rotation behavior.

---

## Architecture

- RSA private keys are generated at server startup.
- Each key is assigned a unique `kid`.
- The JWKS endpoint exposes only unexpired public keys.
- JWTs include the `kid` in the header.
- Tokens are signed using RS256.
- Expired tokens simulate key rotation scenarios.

---

## Endpoints

### 1. JWKS Endpoint

GET /.well-known/jwks.json

Returns all active (unexpired) public keys in JWKS format.

---

### 2. Authentication Endpoint

POST /auth

Returns a valid JWT signed with the active key.

---

### 3. Expired Token Endpoint

POST /auth?expired=true

Returns a JWT signed with the expired key and an expiration timestamp in the past.

---

## Running the Server

Activate virtual environment:

```bash
.venv\Scripts\activate


Start server: python app.py

Server runs on: http://localhost:8080

Run tests:pytest

Run coverage: coverage run -m pytest
              coverage report -m

Current total coverage: 99%


Security Concepts Demonstrated

 -RSA asymmetric cryptography

 -JWT signing and verification

 -Key rotation principles

 -JWKS standard implementation

 -Expiration validation

 -RESTful API design

 -Automated testing and coverage analysis

## Author

**Esat  Kaan Saglam**  
Cybersecurity Student – University of North Texas  

 
LinkedIn: https://www.linkedin.com/in/esat-kaan-saglam/

