import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-production-key-change-it")
ALGORITHM = "HS256"
DB_PATH = os.getenv("DB_PATH", "/data/todos.db")

os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)

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
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                category_id INTEGER,
                title TEXT NOT NULL,
                tags TEXT DEFAULT '',
                order_index INTEGER DEFAULT 0,
                is_completed BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (category_id) REFERENCES categories (id) ON DELETE SET NULL
            );
        """)
        
        # بررسی و اضافه کردن ستون‌های جدید در صورت وجود دیتابیس قدیمی
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(todos);")
        columns = [row[1] for row in cursor.fetchall()]
        if "category_id" not in columns:
            cursor.execute("ALTER TABLE todos ADD COLUMN category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL;")
        if "tags" not in columns:
            cursor.execute("ALTER TABLE todos ADD COLUMN tags TEXT DEFAULT '';")
        if "order_index" not in columns:
            cursor.execute("ALTER TABLE todos ADD COLUMN order_index INTEGER DEFAULT 0;")
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

# مدل‌های اعتبارسنجی
class AuthSchema(BaseModel):
    username: str
    password: str

class CategoryCreate(BaseModel):
    name: str

class TodoCreate(BaseModel):
    title: str
    category_id: Optional[int] = None
    tags: Optional[str] = ""

class TodoUpdate(BaseModel):
    title: Optional[str] = None
    is_completed: Optional[bool] = None
    category_id: Optional[int] = None
    tags: Optional[str] = None

class ReorderSchema(BaseModel):
    ordered_ids: List[int]

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

# --- احراز هویت ---
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
    
    return {"token": create_token(user_id, username), "username": username}

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
    
    return {"token": create_token(user["id"], username), "username": username}

# --- دسته‌بندی‌ها ---
@app.get("/api/categories")
def get_categories(user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM categories WHERE user_id = ? ORDER BY id ASC", (user["id"],))
    categories = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return categories

@app.post("/api/categories")
def create_category(data: CategoryCreate, user: dict = Depends(get_current_user)):
    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="نام دسته‌بندی نمی‌تواند خالی باشد")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO categories (user_id, name) VALUES (?, ?)", (user["id"], name))
    conn.commit()
    cat_id = cursor.lastrowid
    conn.close()
    return {"id": cat_id, "name": name}

@app.delete("/api/categories/{cat_id}")
def delete_category(cat_id: int, user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM categories WHERE id = ? AND user_id = ?", (cat_id, user["id"]))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

# --- کارهای Todo ---
@app.get("/api/todos")
def get_todos(user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.id, t.title, t.is_completed, t.category_id, t.tags, t.order_index, c.name as category_name 
        FROM todos t
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = ? 
        ORDER BY t.order_index ASC, t.id DESC
    """, (user["id"],))
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
    # محاسبه کمترین order_index برای قرارگیری در بالای لیست
    cursor.execute("SELECT MIN(order_index) FROM todos WHERE user_id = ?", (user["id"],))
    min_order = cursor.fetchone()[0]
    new_order = (min_order - 1) if min_order is not None else 0

    cursor.execute(
        "INSERT INTO todos (user_id, title, category_id, tags, order_index) VALUES (?, ?, ?, ?, ?)",
        (user["id"], title, data.category_id, data.tags.strip() if data.tags else "", new_order)
    )
    conn.commit()
    todo_id = cursor.lastrowid
    
    category_name = None
    if data.category_id:
        cursor.execute("SELECT name FROM categories WHERE id = ?", (data.category_id,))
        cat = cursor.fetchone()
        if cat:
            category_name = cat[0]

    conn.close()
    return {
        "id": todo_id,
        "title": title,
        "is_completed": 0,
        "category_id": data.category_id,
        "category_name": category_name,
        "tags": data.tags or "",
        "order_index": new_order
    }

@app.patch("/api/todos/{todo_id}")
def update_todo(todo_id: int, data: TodoUpdate, user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM todos WHERE id = ? AND user_id = ?", (todo_id, user["id"]))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="کار یافت نشد")
    
    fields = []
    values = []
    if data.is_completed is not None:
        fields.append("is_completed = ?")
        values.append(1 if data.is_completed else 0)
    if data.title is not None:
        fields.append("title = ?")
        values.append(data.title.strip())
    if data.category_id is not None:
        fields.append("category_id = ?")
        values.append(data.category_id if data.category_id > 0 else None)
    if data.tags is not None:
        fields.append("tags = ?")
        values.append(data.tags.strip())

    if fields:
        values.append(todo_id)
        cursor.execute(f"UPDATE todos SET {', '.join(fields)} WHERE id = ?", tuple(values))
        conn.commit()

    conn.close()
    return {"status": "success"}

@app.put("/api/todos/reorder")
def reorder_todos(data: ReorderSchema, user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    for index, todo_id in enumerate(data.ordered_ids):
        cursor.execute("UPDATE todos SET order_index = ? WHERE id = ? AND user_id = ?", (index, todo_id, user["id"]))
    conn.commit()
    conn.close()
    return {"status": "reordered"}

@app.delete("/api/todos/{todo_id}")
def delete_todo(todo_id: int, user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM todos WHERE id = ? AND user_id = ?", (todo_id, user["id"]))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def serve_index():
    return FileResponse("static/index.html")