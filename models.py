from pydantic import BaseModel

class LogupRequest(BaseModel):
    username: str
    password: str
    fullname: str
    role: str

class LoginRequest(BaseModel):
    usuario: str
    contraseña: str

class RefreshRequest(BaseModel):
    refreshToken: str
