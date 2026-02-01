from jose import jwt, JWTError, ExpiredSignatureError
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Header, HTTPException
from psycopg2.extras import RealDictCursor
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
import psycopg2
import hashlib
# uvicorn main:app --host 127.0.0.1 --port 8080 --reload
from auth import create_token
from settings import settings
from database import get_connection
from models import LogupRequest, LoginRequest, RefreshRequest

app = FastAPI()

ACCESS_MINUTES = 5
REFRESH_MINUTES = 60 * 24 * 7
SECRET_KEY = settings.secret_key
ALGORITHM = "HS256"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/apilocal/insetuser")
def login(data: LogupRequest):
    conn = get_connection()
    if conn is None:
        return JSONResponse(status_code=500, content={"error": "No se pudo conectar a la base de datos"})
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        hashed = hashlib.sha256(data.password.encode()).hexdigest()
        cur.execute("INSERT INTO users (username, password, fullname, role) VALUES (%s, %s, %s, %s)", (data.username, hashed, data.fullname, data.role))
        conn.commit()
        return JSONResponse(status_code=201, content={"mensaje": f"Usuario '{data.fullname}' registrado correctamente"})

    except psycopg2.Error as e:
        conn.rollback()
        return JSONResponse(status_code=400, content={"error": str(e)})
    finally:
        cur.close()
        conn.close()

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

    try:
        # 1️⃣ Verificar que el refresh exista en BD
        cur.execute("""
            SELECT * FROM refresh_tokens
            WHERE token=%s AND expires_at > now()
        """, (data.refreshToken,))
        token_row = cur.fetchone()

        if not token_row:
            raise HTTPException(status_code=401, detail="Refresh token inválido o expirado")

        # 2️⃣ Decodificar con python-jose (MISMA LIBRERÍA)
        payload = jwt.decode(
            data.refreshToken,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        new_payload = {
            "Username": payload["Username"],
            "nameid": payload["nameid"],
            "role": payload["role"]
        }

        new_token = create_token(new_payload, ACCESS_MINUTES)
        new_refresh = create_token(new_payload, REFRESH_MINUTES)

        # 3️⃣ (opcional pero recomendado) invalidar refresh viejo
        cur.execute(
            "DELETE FROM refresh_tokens WHERE id=%s",
            (token_row["id"],)
        )

        # 4️⃣ Guardar nuevo refresh
        cur.execute("""
            INSERT INTO refresh_tokens (user_id, token, expires_at)
            VALUES (%s, %s, %s)
        """, (
            token_row["user_id"],
            new_refresh,
            datetime.utcnow() + timedelta(minutes=REFRESH_MINUTES)
        ))

        conn.commit()

        return {
            "token": new_token,
            "refreshToken": new_refresh
        }

    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expirado")

    except JWTError:
        raise HTTPException(status_code=401, detail="Refresh token inválido")

    finally:
        cur.close()
        conn.close()

