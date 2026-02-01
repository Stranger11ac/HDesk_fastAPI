from pydantic import BaseModel

class LoginRequest(BaseModel):
    usuario: str
    contraseña: str

class RefreshRequest(BaseModel):
    refreshToken: str
