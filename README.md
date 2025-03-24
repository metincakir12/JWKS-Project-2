# JWKS Server

A FastAPI-based JWKS (JSON Web Key Set) server implementation that manages RSA key pairs and provides JWT authentication.

## Features

- Dynamic RSA key pair generation and management
- SQLite database storage for key persistence
- JWKS endpoint (/.well-known/jwks.json) for public key distribution
- Authentication endpoint for JWT generation
- Support for both valid and expired keys (useful for testing)

## Requirements

- Python 3.7+
- Dependencies listed in requirements.txt

## Installation

1. Clone the repository
2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```
3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the server:
```bash
python proje/prpje.py
```

2. The server will run on http://localhost:8080 with the following endpoints:

- `/.well-known/jwks.json` (GET) - Retrieve public keys in JWKS format
- `/auth` (POST) - Generate a JWT token
  - Query parameter `expired=true` to generate a token with an expired key

## API Examples

### Get JWKS
```bash
curl http://localhost:8080/.well-known/jwks.json
```

### Generate Valid JWT
```bash
curl -X POST http://localhost:8080/auth
```

### Generate JWT with Expired Key
```bash
curl -X POST "http://localhost:8080/auth?expired=true"
```

## Security Notes

- This implementation is for demonstration/development purposes
- The private keys are stored unencrypted in SQLite (not recommended for production)
- Consider implementing proper key encryption and secure storage in production environments

## License

MIT 