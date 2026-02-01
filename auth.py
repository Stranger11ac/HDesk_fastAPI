from datetime import datetime, timedelta
from jose import jwt

SECRET_KEY = "DEV_SECRET_KEY"
ALGORITHM = "HS256"

def create_token(payload: dict, minutes: int):
    data = payload.copy()
    data["exp"] = datetime.utcnow() + timedelta(minutes=minutes)
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
