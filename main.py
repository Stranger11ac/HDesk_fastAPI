from fastapi import FastAPI, Header, HTTPException
from psycopg2.extras import RealDictCursor
import hashlib
from datetime import datetime, timedelta
import jwt

from database import get_connection
from auth import create_token
from models import LoginRequest, RefreshRequest
from settings import settings

app = FastAPI()

ACCESS_MINUTES = 5
REFRESH_MINUTES = 60 * 24 * 7
SECRET_KEY = settings.secret_key
ALGORITHM = "HS256"

@app.post("/api/SIIGAA/Auth/Token")
def login(data: LoginRequest):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    hashed = hashlib.sha256(data.contraseña.encode()).hexdigest()

    cur.execute("""
        SELECT id, username, fullname, role
        FROM users
        WHERE username=%s AND password=%s AND active=true
    """, (data.usuario, hashed))

    user = cur.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    payload = {
        "Username": user["username"],
        "nameid": user["fullname"],
        "role": user["role"]
    }

    token = create_token(payload, ACCESS_MINUTES)
    refresh = create_token(payload, REFRESH_MINUTES)

    cur.execute("""
        INSERT INTO refresh_tokens (user_id, token, expires_at)
        VALUES (%s, %s, %s)
    """, (
        user["id"],
        refresh,
        datetime.utcnow() + timedelta(minutes=REFRESH_MINUTES)
    ))

    conn.commit()
    cur.close()
    conn.close()

    return {
        "token": token,
        "refreshToken": refresh
    }

@app.get("/api/SIIGAA/Auth/CheckToken")
def check_token(authorization: str = Header(None)):
    if not authorization:
        return {"valid": False}

    token = authorization.replace("Bearer ", "")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = datetime.fromtimestamp(payload["exp"])
        near = (exp - datetime.utcnow()).total_seconds() < 60

        return {
            "valid": True,
            "nearExpiration": near
        }
    except:
        return {"valid": False}

@app.post("/api/SIIGAA/Auth/RefreshToken")
def refresh_token(data: RefreshRequest):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT * FROM refresh_tokens
        WHERE token=%s AND expires_at > now()
    """, (data.refreshToken,))

    token_row = cur.fetchone()
    if not token_row:
        raise HTTPException(status_code=401, detail="Refresh inválido")

    payload = jwt.decode(data.refreshToken, SECRET_KEY, algorithms=[ALGORITHM])

    new_payload = {
        "Username": payload["Username"],
        "nameid": payload["nameid"],
        "role": payload["role"]
    }

    return {
        "token": create_token(new_payload, ACCESS_MINUTES),
        "refreshToken": create_token(new_payload, REFRESH_MINUTES)
    }
