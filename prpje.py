from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from jose import jwt
import time
import base64
import json
import sqlite3
from typing import Dict, List, Optional

app = FastAPI()

# Database file name
DB_FILE = "totally_not_my_privateKeys.db"

def init_db():
    """Initialize the SQLite database"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create keys table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    ''')
    
    conn.commit()
    conn.close()

def generate_key_pair(expiry_hours: int = 24) -> Dict:
    """Generate a new RSA key pair with expiry"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Calculate expiry
    expiry = int(time.time() + (expiry_hours * 3600))
    
    # Convert to PEM format
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Get public key components
    public_numbers = public_key.public_numbers()
    
    # Store key in database and get the kid
    kid = store_key_in_db(pem_private, expiry)
    
    # Create key entry with public key data
    key_entry = {
        "kid": str(kid),
        "expiry": expiry,
        "private_key": pem_private,
        "public_key_data": {
            "kty": "RSA",
            "kid": str(kid),
            "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("="),
            "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("="),
            "alg": "RS256",
            "use": "sig"
        }
    }
    
    return key_entry

def store_key_in_db(key_data: bytes, expiry: int) -> int:
    """Store a key in the database and return the kid"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Insert the key and expiry into the database
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key_data, expiry))
    
    # Get the kid (which is the autoincremented primary key)
    kid = cursor.lastrowid
    
    conn.commit()
    conn.close()
    
    return kid

def get_key_from_db(expired: bool = False) -> Optional[Dict]:
    """Get a key from the database
    
    Args:
        expired: If True, get an expired key, otherwise get a valid key
    
    Returns:
        Dict containing the key data or None if no suitable key is found
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    current_time = int(time.time())
    
    if expired:
        # Get an expired key
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1", (current_time,))
    else:
        # Get a valid key
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1", (current_time,))
    
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    kid, key_data, expiry = row
    
    # Deserialize the private key
    private_key = serialization.load_pem_private_key(
        key_data,
        password=None,
        backend=default_backend()
    )
    
    # Get public key components
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    
    # Create key entry
    key_entry = {
        "kid": str(kid),
        "expiry": expiry,
        "private_key": key_data,
        "public_key_data": {
            "kty": "RSA",
            "kid": str(kid),
            "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("="),
            "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("="),
            "alg": "RS256",
            "use": "sig"
        }
    }
    
    return key_entry

def get_all_valid_keys_from_db() -> List[Dict]:
    """Get all valid (non-expired) keys from the database"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    current_time = int(time.time())
    
    # Get all valid keys
    cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (current_time,))
    
    rows = cursor.fetchall()
    conn.close()
    
    valid_keys = []
    
    for row in rows:
        kid, key_data, expiry = row
        
        # Deserialize the private key
        private_key = serialization.load_pem_private_key(
            key_data,
            password=None,
            backend=default_backend()
        )
        
        # Get public key components
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        
        # Create public key data
        public_key_data = {
            "kty": "RSA",
            "kid": str(kid),
            "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("="),
            "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("="),
            "alg": "RS256",
            "use": "sig"
        }
        
        valid_keys.append(public_key_data)
    
    return valid_keys

@app.on_event("startup")
async def startup_event():
    """Initialize database and generate initial keys on startup"""
    # Initialize the database
    init_db()
    
    # Check if we have valid keys
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    current_time = int(time.time())
    
    # Check for valid keys
    cursor.execute("SELECT COUNT(*) FROM keys WHERE exp > ?", (current_time,))
    valid_count = cursor.fetchone()[0]
    
    # Check for expired keys
    cursor.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (current_time,))
    expired_count = cursor.fetchone()[0]
    
    conn.close()
    
    # Generate keys if needed
    if valid_count == 0:
        # Generate a valid key (1 hour validity)
        generate_key_pair(1)
    
    if expired_count == 0:
        # Generate an expired key
        generate_key_pair(-1)  # Already expired

@app.get("/.well-known/jwks.json")
async def jwks():
    """Serve the JWKS endpoint with valid keys from the database"""
    valid_keys = get_all_valid_keys_from_db()
    
    return JSONResponse({
        "keys": valid_keys
    })

@app.post("/auth")
async def auth(expired: bool = False):
    """Authentication endpoint that returns a JWT
    
    Args:
        expired: If True, use an expired key to sign the JWT
    """
    key = get_key_from_db(expired)
    
    if not key:
        if expired:
            raise HTTPException(status_code=400, detail="No expired keys available")
        else:
            raise HTTPException(status_code=500, detail="No valid keys available")
    
    # Create JWT payload
    payload = {
        "sub": "1234567890",
        "name": "Test User",
        "iat": int(time.time()),
        "exp": key["expiry"]
    }
    
    # Create JWT headers
    headers = {
        "kid": key["kid"]
    }
    
    # Sign the JWT
    token = jwt.encode(
        payload,
        key["private_key"] if isinstance(key["private_key"], str) else key["private_key"].decode('utf-8'),
        algorithm="RS256",
        headers=headers
    )
    
    return JSONResponse({
        "token": token
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
    