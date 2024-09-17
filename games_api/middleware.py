from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from games_api.auth import decode_token
from starlette.responses import RedirectResponse
from typing import List, Dict
from datetime import datetime

# Lista negra de tokens
blacklisted_tokens: List[Dict[str, datetime]] = []

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.username = None

        excluded_paths = ["/login", "/register", "/logout", "/static", "/docs", "/openapi.json", "/redoc", "/register-user"]
        if any([request.url.path.startswith(path) for path in excluded_paths]):
            return await call_next(request)

        token = request.cookies.get("access_token")
        if not token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header[len("Bearer "):]

        if not token:
            return RedirectResponse("/login")

        now = datetime.utcnow()

        for entry in blacklisted_tokens:
            if entry["token"] == token and entry["expiration"] > now:
                return RedirectResponse("/login")

        try:
            payload = decode_token(token)
            request.state.username = payload.get("sub")
        except Exception:
            return RedirectResponse("/login")

        response = await call_next(request)
        return response
