import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# تنظیمات
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-production-key-change-it")
ALGORITHM = "HS256"
DB_PATH = os.getenv("DB_PATH", "/data/todos.db")

# اطمینان از وجود پوشه دیتابیس
os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)

# مقداردهی اولیه دیتابیس SQLite
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                is_completed BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
        """)
        conn.commit()

init_db()

app = FastAPI(title="Minimal Todo App")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# مدل‌های Pydantic
class AuthSchema(BaseModel):
    username: str
    password: str

class TodoCreate(BaseModel):
    title: str

class TodoUpdate(BaseModel):
    is_completed: Optional[bool] = None
    title: Optional[str] = None

# توابع کمکی احراز هویت
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

def create_token(user_id: int, username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=30)
    return jwt.encode({"sub": str(user_id), "username": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="توکن ارسال نشده است")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"id": int(payload["sub"]), "username": payload["username"]}
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="توکن نامعتبر یا منقضی شده است")

# --- اندپوینت‌های Auth ---
@app.post("/api/auth/register")
def register(data: AuthSchema):
    username = data.username.strip().lower()
    if len(username) < 3 or len(data.password) < 4:
        raise HTTPException(status_code=400, detail="نام کاربری حداقل ۳ و رمز حداقل ۴ کاراکتر باشد")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="این نام کاربری قبلاً ثبت شده است")
    
    hashed = hash_password(data.password)
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    
    token = create_token(user_id, username)
    return {"token": token, "username": username}

@app.post("/api/auth/login")
def login(data: AuthSchema):
    username = data.username.strip().lower()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="نام کاربری یا رمز عبور اشتباه است")
    
    token = create_token(user["id"], username)
    return {"token": token, "username": username}

# --- اندپوینت‌های Todo ---
@app.get("/api/todos")
def get_todos(user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, is_completed, created_at FROM todos WHERE user_id = ? ORDER BY id DESC", (user["id"],))
    todos = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return todos

@app.post("/api/todos")
def create_todo(data: TodoCreate, user: dict = Depends(get_current_user)):
    title = data.title.strip()
    if not title:
        raise HTTPException(status_code=400, detail="عنوان کار نمی‌تواند خالی باشد")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO todos (user_id, title) VALUES (?, ?)", (user["id"], title))
    conn.commit()
    todo_id = cursor.lastrowid
    conn.close()
    return {"id": todo_id, "title": title, "is_completed": 0}

@app.patch("/api/todos/{todo_id}")
def update_todo(todo_id: int, data: TodoUpdate, user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM todos WHERE id = ? AND user_id = ?", (todo_id, user["id"]))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="کار یافت نشد")
    
    if data.is_completed is not None:
        cursor.execute("UPDATE todos SET is_completed = ? WHERE id = ?", (1 if data.is_completed else 0, todo_id))
    if data.title is not None:
        cursor.execute("UPDATE todos SET title = ? WHERE id = ?", (data.title.strip(), todo_id))
    
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.delete("/api/todos/{todo_id}")
def delete_todo(todo_id: int, user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM todos WHERE id = ? AND user_id = ?", (todo_id, user["id"]))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

# سرو فایل‌های استاتیک فرانت‌اند
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def serve_index():
    return FileResponse("static/index.html")