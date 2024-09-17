import os
from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
from fastapi.staticfiles import StaticFiles
from passlib.context import CryptContext
import sqlite3
from games_api.database import get_db_connection
from games_api.models import UserCreate, UserLogin, VideogameModel
from games_api.security import get_password_hash, verify_password
from games_api.auth import create_access_token, get_current_user, decode_token
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Dict
from datetime import datetime, timedelta
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from games_api.middleware import AuthMiddleware

app = FastAPI()

app.add_middleware(AuthMiddleware)

oauth2scheme = OAuth2PasswordBearer(tokenUrl="token")
blacklisted_tokens: List[Dict[str, datetime]] = []
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=template_dir)

@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db_connection()
    
    user = conn.execute('SELECT * FROM users WHERE username = ?', (form_data.username,)).fetchone()
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    if not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/", tags=["page"])
def home(request: Request):
    conn = get_db_connection()
    games = conn.execute('SELECT * FROM videogames').fetchall()
    conn.close()
    
    return templates.TemplateResponse("home.html", {"request": request, "games": games, "username": request.state.username})

def get_current_user(token: str = Depends(oauth2scheme)):
    now = datetime.utcnow()
    for entry in blacklisted_tokens:
        if entry["token"] == token:
            if entry["expiration"] > now:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")
    
    payload = decode_token(token)
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return username

@app.delete("/delete_all_users", tags=["admin"])
def delete_all_users(current_user: str = Depends(get_current_user)):
    conn = get_db_connection()
    
    db_user = conn.execute('SELECT * FROM users WHERE username = ?', (current_user,)).fetchone()
    
    if db_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You don't have permission to delete users")
    
    conn.execute('DELETE FROM users WHERE role != "admin"')
    conn.commit()
    conn.close()
    
    return {"msg": "All non-admin users have been deleted"}

@app.post("/register-by-admin", tags=["admin"])
def register_user(user: UserCreate, current_user: str = Depends(get_current_user)):
    conn = get_db_connection()
    db_user = conn.execute('SELECT * FROM users WHERE username = ?', (current_user,)).fetchone()
    
    if db_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You don't have permission to register new users")
    
    try:
        hashed_password = get_password_hash(user.password)
        conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
                     (user.username, hashed_password, user.role))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()
    
    return {"msg": "User registered successfully"}

@app.get("/register-user", tags=["page"])
def register_page(request: Request):
    token = request.cookies.get("access_token")
    
    if token:
        return RedirectResponse("/", status_code=302)

    return templates.TemplateResponse("register-user.html", {"request": request})

@app.post("/register-user", tags=["page"])
def register_new_user(username: str = Form(...), password: str = Form(...)):
    conn = get_db_connection()
    
    db_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if db_user:
        raise HTTPException(status_code=400, detail="El nombre de usuario ya existe")
    
    hashed_password = get_password_hash(password)
    
    conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
                 (username, hashed_password, 'user'))
    conn.commit()
    conn.close()
    
    return RedirectResponse("/login", status_code=302)

@app.get("/users", tags=["admin"])
def get_all_users(current_user: str = Depends(get_current_user)):
    print(f"Usuario actual: {current_user}")
    
    conn = get_db_connection()
    db_user = conn.execute('SELECT * FROM users WHERE username = ?', (current_user,)).fetchone()
    
    print(f"Usuario en base de datos: {db_user}")
    
    if db_user["role"] != "admin":
        print(f"Permiso denegado, el rol es: {db_user['role']}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You don't have permission to access this resource")
    
    users = conn.execute('SELECT username FROM users').fetchall()
    conn.close()
    
    return {"users": [user["username"] for user in users]}

@app.get("/login", tags=["page"])
def login_page(request: Request):
    token = request.cookies.get("access_token")
    
    if token:
        return RedirectResponse("/", status_code=302)
    
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", tags=["page"])
def login_user(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = get_db_connection()
    db_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if not db_user or not verify_password(password, db_user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": username})
    
    response = RedirectResponse("/", status_code=302)
    
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    
    return response

@app.post("/login-api")
def login_user(user: UserLogin):
    conn = get_db_connection()
    db_user = conn.execute('SELECT * FROM users WHERE username = ?', (user.username,)).fetchone()
    conn.close()
    
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/logout", tags=["page"])
def logout_user(request: Request):
    response = RedirectResponse("/login", status_code=302)
    
    response.delete_cookie(key="access_token")
    
    return response

@app.post("/logout-api")
def logout_user(token: str = Depends(oauth2scheme)):
    payload = decode_token(token)
    expiration = payload.get("exp")
    if token not in [entry['token'] for entry in blacklisted_tokens]:
        blacklisted_tokens.append({"token": token, "expiration": datetime.utcfromtimestamp(expiration)})
    return {"msg": "Successfully logged out"}

@app.post("/clear_blacklist", tags=["admin"])
def clear_blacklist(current_user: str = Depends(get_current_user)):
    conn = get_db_connection()
    db_user = conn.execute('SELECT * FROM users WHERE username = ?', (current_user,)).fetchone()

    if db_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You don't have permission to access this resource")

    blacklisted_tokens.clear()
    return {"msg": "Blacklist cleared successfully"}

@app.delete("/delete_user/{username}", tags=["admin"])
def delete_user(username: str, current_user: str = Depends(get_current_user)):
    print(f"Attempting to delete user: {username}")
    
    conn = get_db_connection()
    
    db_user = conn.execute('SELECT * FROM users WHERE username = ?', (current_user,)).fetchone()
    
    if db_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You don't have permission to delete users")
    
    try:
        result = conn.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()

        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")
    finally:
        conn.close()
    
    return {"msg": f"User '{username}' deleted successfully"}

@app.post("/add-videogame", status_code=201, tags=["videogames"])
def add_videogame(videogame: VideogameModel, current_user: str = Depends(get_current_user)):

    conn = get_db_connection()
    db_user = conn.execute('SELECT * FROM users WHERE username = ?', (current_user,)).fetchone()

    if db_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You don't have permission to add a videogame")
    
    conn.execute('INSERT INTO videogames (name, release_year, developer, image_url) VALUES (?, ?, ?, ?)',
                 (videogame.name, videogame.release_year, videogame.developer, videogame.image_url))
    conn.commit()
    conn.close()

    return {"msg": "Videogame added successfully!"}

@app.put("/update-videogame/{name}", tags=["videogames"])
def update_videogame_by_name(
    name: str,
    videogame: VideogameModel,
    current_user: str = Depends(get_current_user)
):
    conn = get_db_connection()
    db_user = conn.execute('SELECT * FROM users WHERE username = ?', (current_user,)).fetchone()

    if db_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You don't have permission to update a videogame")
    
    game = conn.execute('SELECT * FROM videogames WHERE name = ?', (name,)).fetchone()
    if not game:
        conn.close()
        raise HTTPException(status_code=404, detail="Videogame not found")
    
    conn.execute('''
        UPDATE videogames
        SET name = ?, release_year = ?, developer = ?, image_url = ?
        WHERE name = ?
    ''', (videogame.name, videogame.release_year, videogame.developer, videogame.image_url, name))
    
    conn.commit()
    conn.close()

    return {"msg": "Videogame updated successfully!"}