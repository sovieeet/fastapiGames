import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from typing import List, Dict

oauth2scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = "testing"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

blacklisted_tokens: List[Dict[str, datetime]] = []

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def get_current_user(token: str = Depends(oauth2scheme)):
    print("Token recibido:", token)
    now = datetime.utcnow()

    for entry in blacklisted_tokens:
        print("Revisando token en lista negra:", entry["token"])
        if entry["token"] == token:
            if entry["expiration"] > now:
                print("El token ha sido revocado")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")
    
    payload = decode_token(token)
    username: str = payload.get("sub")
    if username is None:
        print("Nombre de usuario no encontrado en el token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    print("Usuario autenticado:", username)
    return username
