from jose import jwt, JWTError, ExpiredSignatureError
from datetime import datetime, timedelta
from fastapi import HTTPException

from settings import settings

SECRET_KEY = settings.secret_key.strip()
ALGORITHM = "HS256"

def create_token(payload: dict, minutes: int):
    data = payload.copy()
    data["exp"] = datetime.utcnow() + timedelta(minutes=minutes)
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


def get_payload_from_bearer(authorization: str) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization format")

    token = authorization.replace("Bearer ", "").strip()

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload

    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
