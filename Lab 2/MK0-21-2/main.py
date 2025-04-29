import os
import random
import hashlib
import logging
import time
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm 
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
import jwt
from psycopg2 import sql
from psycopg2.extras import execute_batch
import psycopg2
from tqdm import tqdm
import xml.etree.ElementTree as ET
import shutil

from recovery_checker import check_recovery_needed
from config_reader import config

os.makedirs(config.DATABASE_DIRECTORY, exist_ok=True)
os.makedirs(config.LOGS_DIRECTORY, exist_ok=True)

app = FastAPI()

check_recovery_needed()

templates = Jinja2Templates(directory=config.TEMPLATES_DIRECTORY)

Base = declarative_base()

user_db_path = config.USER_DB_FILE
admin_db_path = config.ADMIN_DB_FILE
queue_db_path = config.QUEUE_DB_FILE
vaccine_db_path = config.VACCINE_DB_FILE

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    vaccine_info = Column(String, nullable=True)

class Admin(Base):
    __tablename__ = "admins"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class Queue(Base):
    __tablename__ = "queue"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)

class Vaccine(Base):
    __tablename__ = "vaccines"
    id = Column(Integer, primary_key=True, index=True)
    vaccine_name = Column(String, unique=True, index=True)
    date_added = Column(String)
    added_by = Column(String)
    is_active = Column(Integer)
    last_modified = Column(String)
    modified_by = Column(String)

# PostgreSQL Database setup with connection pooling
user_engine = create_engine(
    config.USER_DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=3600
)
admin_engine = create_engine(
    config.ADMIN_DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=3600
)
queue_engine = create_engine(
    config.QUEUE_DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=3600
)
vaccine_engine = create_engine(
    config.VACCINE_DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=3600
)

Base.metadata.create_all(bind=user_engine)
Base.metadata.create_all(bind=admin_engine)
Base.metadata.create_all(bind=queue_engine)
Base.metadata.create_all(bind=vaccine_engine)

UserSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=user_engine)
AdminSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=admin_engine)
QueueSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=queue_engine)
VaccineSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=vaccine_engine)

# Security setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SERVER_MAINTENANCE_MODE = config.SERVER_MAINTENANCE_MODE
SERVER_QUARANTINE_MODE = config.SERVER_QUARANTINE_MODE
SECRET_KEY = config.SECRET_KEY
ADMIN_SECRET_KEY = config.ADMIN_SECRET_KEY

# Logging setup
def setup_logger(name, log_file, level=logging.INFO):
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler = logging.FileHandler(log_file)    
    handler.setFormatter(formatter)
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    
    return logger

# Create separate loggers for each database
user_logger = setup_logger('user_logger', config.USER_LOG_FILE)
admin_logger = setup_logger('admin_logger', config.ADMIN_LOG_FILE)
queue_logger = setup_logger('queue_logger', config.QUEUE_LOG_FILE)
vaccine_logger = setup_logger('vaccine_logger', config.VACCINE_LOG_FILE)

# PostgreSQL Utility functions
def get_pg_connection():
    """Get direct PostgreSQL connection using Psycopg"""
    return psycopg2.connect(
        dbname="vaccination_db",
        user="username",
        password="password",
        host="localhost",
        port="5432"
    )

async def bulk_insert_users(users_data: list):
    """Bulk insert users using Psycopg for better performance"""
    conn = None
    try:
        conn = get_pg_connection()
        cur = conn.cursor()
        
        query = sql.SQL("""
            INSERT INTO users (username, email, hashed_password, vaccine_info)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (username) DO NOTHING
        """)
        
        execute_batch(cur, query, users_data)
        conn.commit()
        return {"inserted": cur.rowcount}
    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            conn.close()

async def get_vaccine_stats():
    """Get vaccine statistics using PostgreSQL window functions"""
    conn = None
    try:
        conn = get_pg_connection()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT 
                vaccine_name,
                COUNT(*) as total_used,
                COUNT(*) FILTER (WHERE is_active = 1) as active_uses,
                COUNT(*) OVER () as total_vaccinations,
                ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
            FROM vaccines
            GROUP BY vaccine_name
            ORDER BY total_used DESC
        """)
        
        results = cur.fetchall()
        return {
            "stats": [
                {
                    "vaccine_name": row[0],
                    "total_used": row[1],
                    "active_uses": row[2],
                    "total_vaccinations": row[3],
                    "percentage": row[4]
                }
                for row in results
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            conn.close()

# Utility functions
def get_user_db():
    db = UserSessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_admin_db():
    db = AdminSessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_queue_db():
    db = QueueSessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_vaccine_db():
    db = VaccineSessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def authenticate_admin(db: Session, username: str, password: str):
    admin = db.query(Admin).filter(Admin.username == username).first()
    if not admin or not verify_password(password, admin.hashed_password):
        return False
    return admin

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, config.SECRET_KEY, algorithm=config.ALGORITHM)

def create_admin_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, config.ADMIN_SECRET_KEY, algorithm=config.ALGORITHM)

def log_action(db_type: str, username: str, action: str, response: str):
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"{timestamp} - {username} - {action} - {response}"
    
    if db_type == "user":
        user_logger.info(log_message)
    elif db_type == "admin":
        admin_logger.info(log_message)
    elif db_type == "queue":
        queue_logger.info(log_message)
    elif db_type == "vaccine":
        vaccine_logger.info(log_message)
    else:
        admin_logger.info(log_message)

def generate_and_hash_code():
    code = str(random.randint(100, 999))
    hashed_code = hashlib.sha256((config.ADMIN_SECRET_KEY + code).encode('utf-8')).hexdigest()
    print(f"Numeric security code: {code}, Hashed code: {hashed_code}")
    return code, hashed_code

generated_code, hashed_code = generate_and_hash_code()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_user_db)):
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def get_current_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_admin_db)):
    try:
        payload = jwt.decode(token, config.ADMIN_SECRET_KEY, algorithms=[config.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    admin = db.query(Admin).filter(Admin.username == username).first()
    if admin is None:
        raise HTTPException(status_code=401, detail="Admin not found")
    return admin

# Middleware
@app.middleware("http")
async def maintenance_middleware(request: Request, call_next):
    global SERVER_MAINTENANCE_MODE, SERVER_QUARANTINE_MODE
    
    if request.url.path == "/healthcheck":
        return await call_next(request)
    
    is_admin_endpoint = request.url.path.startswith("/admin")
    
    if SERVER_QUARANTINE_MODE and request.url.path != "/maintenance":
        return RedirectResponse(url="/maintenance")
    
    if SERVER_MAINTENANCE_MODE and not is_admin_endpoint and request.url.path != "/maintenance":
        return RedirectResponse(url="/maintenance")
    
    return await call_next(request)

# Core endpoints
@app.get("/", response_class=HTMLResponse)
async def welcome(request: Request):
    return templates.TemplateResponse("welcome.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/healthcheck")
async def healthcheck():
    return {"status": "ok"}

@app.get("/maintenance", response_class=HTMLResponse)
async def maintenance_page(request: Request):
    return templates.TemplateResponse("maintenance.html", {"request": request})

# User endpoints
class UserEndpoints:
    @app.post("/register")
    async def register(
        request: Request,
        username: str = Form(...),
        email: str = Form(...),
        password: str = Form(...),
        admin_key: str = Form(None),
        db: Session = Depends(get_user_db)
    ):
        if admin_key and hashlib.sha256((config.ADMIN_SECRET_KEY + admin_key).encode('utf-8')).hexdigest() == hashed_code:
            admin_db = AdminSessionLocal()
            try:
                new_admin = Admin(username=username, hashed_password=get_password_hash(password))
                admin_db.add(new_admin)
                admin_db.commit()
                log_action("admin", username, "register", "Admin registration successful")
                return RedirectResponse(url="/", status_code=303)
            finally:
                admin_db.close()

        if db.query(User).filter(User.username == username).first():
            log_action("user", username, "register", "Username already registered")
            error_message = "Username already registered"
            return templates.TemplateResponse("registration_error.html", {"request": request, "error_message": error_message})

        if db.query(User).filter(User.email == email).first():
            log_action("user", username, "register", "Email already registered")
            error_message = "Email already registered"
            return templates.TemplateResponse("registration_error.html", {"request": request, "error_message": error_message})

        new_user = User(username=username, email=email, hashed_password=get_password_hash(password))
        db.add(new_user)
        db.commit()
        log_action("user", username, "register", "Registration successful")

        return RedirectResponse(url="/", status_code=303)

    @app.post("/token")
    async def login(
        request: Request,
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_user_db)
    ):
        user = authenticate_user(db, form_data.username, form_data.password)
        if not user:
            raise HTTPException(status_code=401, detail="Incorrect username or password")

        access_token = create_access_token({"sub": user.username})
        log_action("user", user.username, "login", "User logged in successfully")
        
        return JSONResponse(content={"access_token": access_token})

    @app.get("/home", response_class=HTMLResponse)
    async def home_page(request: Request, current_user: User = Depends(get_current_user)):
        return templates.TemplateResponse("home.html", {"request": request, "username": current_user.username})

    @app.get("/edit-account-home", response_class=HTMLResponse)
    async def edit_account_home(request: Request, current_user: User = Depends(get_current_user)):
        return templates.TemplateResponse("edit_account.html", {"request": request, "username": current_user.username})

    @app.get("/edit-account-username", response_class=HTMLResponse)
    async def edit_account_username(request: Request, current_user: User = Depends(get_current_user)):
        return templates.TemplateResponse("edit_account_username.html", {"request": request, "username": current_user.username})

    @app.get("/edit-account-password", response_class=HTMLResponse)
    async def edit_account_password(request: Request, current_user: User = Depends(get_current_user)):
        return templates.TemplateResponse("edit_account_password.html", {"request": request, "username": current_user.username})

    @app.get("/edit-account-email", response_class=HTMLResponse)
    async def edit_account_email(request: Request, current_user: User = Depends(get_current_user)):
        return templates.TemplateResponse("edit_account_email.html", {"request": request, "username": current_user.username})

    @app.post("/update-username")
    async def update_username(
        new_username: str = Form(...),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_user_db)
    ):
        if new_username == current_user.username:
            raise HTTPException(status_code=406, detail="New username cannot be the same as the old one")

        if db.query(User).filter(User.username == new_username).first():
            raise HTTPException(status_code=400, detail="Username already taken")

        old_username = current_user.username
        current_user.username = new_username
        db.commit()

        log_action("user", old_username, "update-username", f"Username changed to {new_username}")

        return {"message": f"successfully updated to {new_username}"}

    @app.post("/update-password")
    async def update_password(
        old_password: str = Form(...),
        new_password: str = Form(...),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_user_db)
    ):
        if not verify_password(old_password, current_user.hashed_password):
            raise HTTPException(status_code=400, detail="Old password is incorrect")

        current_user.hashed_password = get_password_hash(new_password)
        db.commit()
        log_action("user", current_user.username, "update-password", "Password changed successfully")
        return {"message": "Password updated successfully"}

    @app.post("/update-email")
    async def update_email(
        new_email: str = Form(...),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_user_db)
    ):
        if db.query(User).filter(User.email == new_email).first():
            raise HTTPException(status_code=400, detail="Email already in use")

        current_user.email = new_email
        db.commit()
        log_action("user", current_user.username, "update-email", f"Email changed to {new_email}")
        return {"message": "Email updated successfully"}

    @app.post("/user/delete-account")
    async def delete_user_account(
        password: str = Form(...),
        current_user: User = Depends(get_current_user),
        db_user: Session = Depends(get_user_db),
        db_queue: Session = Depends(get_queue_db)
    ):
        if not verify_password(password, current_user.hashed_password):
            raise HTTPException(status_code=400, detail="Incorrect password")

        queue_entry = db_queue.query(Queue).filter(Queue.name == current_user.username).first()
        if queue_entry:
            db_queue.delete(queue_entry)
            db_queue.commit()

        db_user.delete(current_user)
        db_user.commit()

        log_action("user", current_user.username, "delete_account", "User deleted their own account")
        
        return {"message": "Account deleted successfully"}

# Queue endpoints
class QueueEndpoints:
    @app.get("/queue/position")
    async def get_user_position(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_queue_db)
    ):
        queue_entry = db.query(Queue).filter(Queue.name == current_user.username).first()
        if not queue_entry:
            raise HTTPException(status_code=204, detail="User not found in queue")

        log_action("queue", current_user.username, "get_position", f"User checked queue position: {queue_entry.id}")
        return {"id": queue_entry.id, "name": queue_entry.name}

    @app.post("/queue/add")
    async def add_to_queue(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_queue_db)
    ):
        existing_entry = db.query(Queue).filter(Queue.name == current_user.username).first()
        if existing_entry:
            raise HTTPException(status_code=400, detail="User already in queue")

        new_queue_entry = Queue(name=current_user.username)
        db.add(new_queue_entry)
        db.commit()
        db.refresh(new_queue_entry)

        log_action("queue", current_user.username, "add_to_queue", f"User added to queue with ID: {new_queue_entry.id}")
        return {"id": new_queue_entry.id, "name": new_queue_entry.name}

    @app.post("/queue/remove")
    async def remove_from_queue(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_queue_db)
    ):
        queue_entry = db.query(Queue).filter(Queue.name == current_user.username).first()
        if not queue_entry:
            raise HTTPException(status_code=404, detail="User not found in queue")

        db.delete(queue_entry)
        db.commit()

        remaining_entries = db.query(Queue).filter(Queue.id > queue_entry.id).all()
        for entry in remaining_entries:
            entry.id -= 1
        db.commit()

        log_action("queue", current_user.username, "remove_from_queue", f"User removed from queue, ID was: {queue_entry.id}")
        return {"message": "User removed", "id": queue_entry.id}

# Admin endpoints
class AdminEndpoints:
    @app.get("/admin-login", response_class=HTMLResponse)
    async def admin_login_page(request: Request):
        return templates.TemplateResponse("admin_login.html", {"request": request})

    @app.get("/admin-panel", response_class=HTMLResponse)
    async def admin_panel_page(request: Request, current_admin: Admin = Depends(get_current_admin)):
        return templates.TemplateResponse("admin_panel.html", {"request": request, "username": current_admin.username})

    @app.post("/admin/register")
    async def register_admin(
        username: str = Form(...),
        password: str = Form(...),
        admin_key: str = Form(...),
        db: Session = Depends(get_admin_db)
    ):
        print(admin_key)
        if hashed_code != admin_key:
            raise HTTPException(status_code=403, detail="Invalid admin key")
        if not admin_key:
            raise HTTPException(status_code=403, detail="Admin key is required")

        if db.query(Admin).filter(Admin.username == username).first():
            raise HTTPException(status_code=400, detail="Admin username already registered")
        new_admin = Admin(username=username, hashed_password=get_password_hash(password))
        db.add(new_admin)
        db.commit()
        
        log_action("admin", username, "register_admin", "New admin registered")
        return {"message": "Admin registered successfully"}  

    @app.post("/admin/token")
    async def login_admin(
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_admin_db)
    ):
        admin = authenticate_admin(db, form_data.username, form_data.password)
        if not admin:
            raise HTTPException(status_code=401, detail="Incorrect username or password")

        access_token = create_admin_access_token({"sub": admin.username})
        
        log_action("admin", admin.username, "admin_login", "Successful admin login")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "username": admin.username
        }

    @app.get("/admin/queue/user/{queue_id}")
    async def get_user_by_queue_id(
        queue_id: int,
        current_admin: Admin = Depends(get_current_admin),
        db: Session = Depends(get_queue_db)
    ):
        user_entry = db.query(Queue).filter(Queue.id == queue_id).first()
        if not user_entry:
            raise HTTPException(status_code=404, detail="User not found in queue")
        
        log_action("admin", current_admin.username, "get_queue_user", f"Retrieved user in queue with ID: {queue_id}")
        
        return {"id": user_entry.id, "name": user_entry.name}

    @app.post("/admin/queue/remove_first")
    async def admin_remove_first(
        vaccine_name: str = Form(...),
        current_admin: Admin = Depends(get_current_admin),
        db_queue: Session = Depends(get_queue_db),
        db_user: Session = Depends(get_user_db)
    ):
        first_entry = db_queue.query(Queue).order_by(Queue.id.asc()).first()
        if not first_entry:
            raise HTTPException(status_code=400, detail="Queue is empty")

        try:
            user = db_user.query(User).filter(User.username == first_entry.name).first()
            if user:
                current_time = datetime.now().strftime("%Y.%m.%d %H:%M:%S")
                vaccine_info = f"{vaccine_name} {current_time}"

                if not hasattr(user, 'vaccine_info') or user.vaccine_info is None:
                    user.vaccine_info = vaccine_info
                else:
                    user.vaccine_info = f"{user.vaccine_info}, {vaccine_info}"

                db_user.commit()

            db_queue.delete(first_entry)
            db_queue.commit()

            remaining_entries = db_queue.query(Queue).order_by(Queue.id).all()
            for index, entry in enumerate(remaining_entries, start=1):
                entry.id = index
            db_queue.commit()

            log_action("admin", current_admin.username, "remove_first_queue", 
                      f"Removed first in queue: {first_entry.name}, Vaccine: {vaccine_name}")
            log_action("queue", current_admin.username, "remove_first_queue", 
                      f"Removed first in queue: {first_entry.name}, Vaccine: {vaccine_name}")

            return {
                "message": "First entry removed and user vaccinated",
                "vaccinated_user": first_entry.name,
                "vaccine_info": vaccine_info,
                "updated_queue": [{"id": entry.id, "name": entry.name} for entry in remaining_entries]
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/admin/queue/clear")
    async def clear_queue(
        current_admin: Admin = Depends(get_current_admin),
        db: Session = Depends(get_queue_db)
    ):
        db.query(Queue).delete()
        db.commit()
        
        log_action("admin", current_admin.username, "clear_queue", "Cleared entire queue")
        log_action("queue", current_admin.username, "clear_queue", "Cleared entire queue")
        
        return {"message": "Queue cleared successfully"}

    @app.post("/admin/delete")
    async def delete_admin(
        username: str = Form(...),
        current_admin: Admin = Depends(get_current_admin),
        db: Session = Depends(get_admin_db)
    ):
        admin = db.query(Admin).filter(Admin.username == username).first()
        if not admin:
            raise HTTPException(status_code=404, detail="Admin not found")

        db.delete(admin)
        db.commit()

        log_action("admin", current_admin.username, "delete_admin", f"Deleted admin: {username}")
        
        return {"message": f"Admin '{username}' deleted successfully"}

    @app.get("/admin/data")
    async def get_admin_data(
        current_admin: Admin = Depends(get_current_admin),
        db: Session = Depends(get_admin_db)
    ):
        admins = db.query(Admin).all()
        
        admin_list = []
        for admin in admins:
            admin_list.append({
                "id": admin.id,
                "username": admin.username
            })
        
        log_action("admin", current_admin.username, "get_admin_data", "Retrieved all admin data")
        return {"admins": admin_list}

    @app.get("/admin/data/all")
    async def get_all_database_data(
        current_admin: Admin = Depends(get_current_admin),
        db_admin: Session = Depends(get_admin_db),
        db_user: Session = Depends(get_user_db),
        db_queue: Session = Depends(get_queue_db),
        db_vaccine: Session = Depends(get_vaccine_db)
    ):
        data = {
            "users": [],
            "admins": [],
            "queue": [],
            "vaccines": []
        }
        
        users = db_user.query(User).all()
        for user in users:
            data["users"].append({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "vaccine_info": user.vaccine_info
            })
        
        admins = db_admin.query(Admin).all()
        for admin in admins:
            data["admins"].append({
                "id": admin.id,
                "username": admin.username
            })
        
        queue_entries = db_queue.query(Queue).all()
        for entry in queue_entries:
            data["queue"].append({
                "id": entry.id,
                "name": entry.name
            })
        
        vaccines = db_vaccine.query(Vaccine).all()
        for vaccine in vaccines:
            data["vaccines"].append({
                "id": vaccine.id,
                "vaccine_name": vaccine.vaccine_name,
                "date_added": vaccine.date_added,
                "added_by": vaccine.added_by,
                "is_active": bool(vaccine.is_active),
                "last_modified": vaccine.last_modified,
                "modified_by": vaccine.modified_by
            })
        
        log_action("admin", current_admin.username, "get_all_data", "Retrieved all database data")
        
        return data

    @app.post("/admin/delete-user")
    async def admin_delete_user(
        username_to_delete: str = Form(...),
        current_admin: Admin = Depends(get_current_admin),
        db_admin: Session = Depends(get_admin_db),
        db_user: Session = Depends(get_user_db),
        db_queue: Session = Depends(get_queue_db)
    ):
        if current_admin.username == username_to_delete:
            raise HTTPException(status_code=400, detail="Cannot delete yourself")

        user = db_user.query(User).filter(User.username == username_to_delete).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        queue_entry = db_queue.query(Queue).filter(Queue.name == username_to_delete).first()
        if queue_entry:
            db_queue.delete(queue_entry)
            db_queue.commit()

        db_user.delete(user)
        db_user.commit()

        log_action("admin", current_admin.username, "admin_delete_user", 
                  f"Admin deleted user account: {username_to_delete}")
        log_action("user", current_admin.username, "admin_delete_user", 
                  f"Admin deleted user account: {username_to_delete}")
        
        return {"message": f"User '{username_to_delete}' deleted successfully"}

class VaccineEndpoints:
    @app.post("/admin/vaccines/add")
    async def add_vaccine(
        vaccine_name: str = Form(...),
        current_admin: Admin = Depends(get_current_admin),
        db_vaccine: Session = Depends(get_vaccine_db)
    ):
        existing_vaccine = db_vaccine.query(Vaccine).filter(Vaccine.vaccine_name == vaccine_name).first()
        if existing_vaccine:
            raise HTTPException(status_code=400, detail="Vaccine already exists")

        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        
        new_vaccine = Vaccine(
            vaccine_name=vaccine_name,
            date_added=current_time,
            added_by=current_admin.username,
            is_active=1,
            last_modified=current_time,
            modified_by=current_admin.username
        )
        
        db_vaccine.add(new_vaccine)
        db_vaccine.commit()
        
        log_action("vaccine", current_admin.username, "add_vaccine", f"Added vaccine: {vaccine_name}")
        log_action("admin", current_admin.username, "add_vaccine", f"Added vaccine: {vaccine_name}")
        
        return {
            "message": "Vaccine added successfully",
            "vaccine_name": vaccine_name,
            "date_added": current_time,
            "added_by": current_admin.username
        }

    @app.post("/admin/vaccines/update")
    async def update_vaccine(
        vaccine_name: str = Form(...),
        new_name: str = Form(None),
        is_active: int = Form(None),
        current_admin: Admin = Depends(get_current_admin),
        db_vaccine: Session = Depends(get_vaccine_db)
    ):
        vaccine = db_vaccine.query(Vaccine).filter(Vaccine.vaccine_name == vaccine_name).first()
        if not vaccine:
            raise HTTPException(status_code=404, detail="Vaccine not found")

        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        changes = []
        
        if new_name and new_name != vaccine.vaccine_name:
            existing = db_vaccine.query(Vaccine).filter(Vaccine.vaccine_name == new_name).first()
            if existing:
                raise HTTPException(status_code=400, detail="Vaccine name already exists")
            
            changes.append(f"name changed from {vaccine.vaccine_name} to {new_name}")
            vaccine.vaccine_name = new_name

        if is_active is not None and is_active != vaccine.is_active:
            changes.append(f"active status changed from {vaccine.is_active} to {is_active}")
            vaccine.is_active = is_active

        if changes:
            vaccine.last_modified = current_time
            vaccine.modified_by = current_admin.username
            db_vaccine.commit()
            
            log_action("vaccine", current_admin.username, "update_vaccine", 
                      f"Updated vaccine {vaccine_name}: " + ", ".join(changes))
            log_action("admin", current_admin.username, "update_vaccine", 
                      f"Updated vaccine {vaccine_name}: " + ", ".join(changes))
            
            return {
                "message": "Vaccine updated successfully",
                "changes": changes,
                "last_modified": current_time,
                "modified_by": current_admin.username
            }
        else:
            return {"message": "No changes detected"}

    @app.post("/admin/vaccines/delete")
    async def delete_vaccine(
        vaccine_name: str = Form(...),
        current_admin: Admin = Depends(get_current_admin),
        db_vaccine: Session = Depends(get_vaccine_db)
    ):
        vaccine = db_vaccine.query(Vaccine).filter(Vaccine.vaccine_name == vaccine_name).first()
        if not vaccine:
            raise HTTPException(status_code=404, detail="Vaccine not found")

        db_vaccine.delete(vaccine)
        db_vaccine.commit()
        
        log_action("vaccine", current_admin.username, "delete_vaccine", f"Deleted vaccine: {vaccine_name}")
        log_action("admin", current_admin.username, "delete_vaccine", f"Deleted vaccine: {vaccine_name}")
        
        return {"message": "Vaccine deleted successfully"}

    @app.post("/admin/vaccines/list")
    async def list_vaccines(
        current_admin: Admin = Depends(get_current_admin),
        db_vaccine: Session = Depends(get_vaccine_db)
    ):
        vaccines = db_vaccine.query(Vaccine).all()
        
        vaccine_list = []
        for vaccine in vaccines:
            vaccine_list.append({
                "id": vaccine.id,
                "vaccine_name": vaccine.vaccine_name,
                "date_added": vaccine.date_added,
                "added_by": vaccine.added_by,
                "is_active": bool(vaccine.is_active),
                "last_modified": vaccine.last_modified,
                "modified_by": vaccine.modified_by
            })
        
        log_action("vaccine", current_admin.username, "list_vaccines", "Retrieved list of all vaccines")
        log_action("admin", current_admin.username, "list_vaccines", "Retrieved list of all vaccines")
        return {"vaccines": vaccine_list}

class PostgresEndpoints:
    @app.post("/admin/bulk-import/users")
    async def bulk_import_users(
        users_data: list,
        current_admin: Admin = Depends(get_current_admin)
    ):
        """Bulk import users using PostgreSQL COPY command"""
        try:
            result = await bulk_insert_users(users_data)
            log_action("admin", current_admin.username, "bulk_import", 
                      f"Imported {result['inserted']} users")
            return result
        except Exception as e:
            log_action("admin", current_admin.username, "bulk_import_error", 
                      f"Failed to import users: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/admin/vaccines/stats")
    async def get_vaccine_statistics(
        current_admin: Admin = Depends(get_current_admin)
    ):
        """Get vaccine statistics with PostgreSQL analytics"""
        try:
            stats = await get_vaccine_stats()
            log_action("admin", current_admin.username, "vaccine_stats", 
                      "Retrieved vaccine statistics")
            return stats
        except Exception as e:
            log_action("admin", current_admin.username, "vaccine_stats_error", 
                      f"Failed to get stats: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/admin/database/optimize")
    async def optimize_database(
        current_admin: Admin = Depends(get_current_admin)
    ):
        """Run PostgreSQL maintenance operations"""
        conn = None
        try:
            conn = get_pg_connection()
            cur = conn.cursor()
            
            # Vacuum and analyze all tables
            cur.execute("VACUUM FULL ANALYZE")
            
            # Reindex database
            cur.execute("REINDEX DATABASE vaccination_db")
            
            conn.commit()
            
            log_action("admin", current_admin.username, "db_optimize", 
                      "Performed database optimization")
            return {"message": "Database optimization completed"}
        except Exception as e:
            if conn:
                conn.rollback()
            log_action("admin", current_admin.username, "db_optimize_error", 
                      f"Optimization failed: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            if conn:
                conn.close()

class ServiceEndpoints:
    def __init__(self):
        pass

    def update_web_config(self, key: str, value: str):
        """Helper method to update Web.config file"""
        config_file = "Web.config"
        if not os.path.exists(config_file):
            raise FileNotFoundError(f"Config file {config_file} not found")
        
        tree = ET.parse(config_file)
        root = tree.getroot()
        
        key_elements = root.findall(f".//add[@key='{key}']")
        if not key_elements:
            raise ValueError(f"{key} element not found in config")
        
        for elem in key_elements:
            elem.set('value', value)
        
        tree.write(config_file, encoding='utf-8', xml_declaration=True)

    def create_db_backup(self):
        """Create backup of all database files"""
        backup_dir = os.path.join(config.DATABASE_DIRECTORY, "backups")
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_files = []
        
        for db_file in [user_db_path, admin_db_path, queue_db_path, vaccine_db_path]:
            if os.path.exists(db_file):
                backup_path = os.path.join(backup_dir, f"{os.path.basename(db_file)}_{timestamp}.bak")
                shutil.copy2(db_file, backup_path)
                backup_files.append(backup_path)
        
        return backup_files

    def restore_db_from_backup(self):
        """Restore database files from the latest backup"""
        backup_dir = os.path.join(config.DATABASE_DIRECTORY, "backups")
        if not os.path.exists(backup_dir):
            return False
        
        backups = {}
        for file in os.listdir(backup_dir):
            if file.endswith(".bak"):
                base_name = file.split('_')[0]
                timestamp = file.split('_')[1] + '_' + file.split('_')[2].split('.')[0]
                if base_name not in backups or timestamp > backups[base_name]['timestamp']:
                    backups[base_name] = {
                        'path': os.path.join(backup_dir, file),
                        'timestamp': timestamp
                    }
        
        restored = False
        for base_name, backup_info in backups.items():
            original_path = os.path.join(config.DATABASE_DIRECTORY, base_name)
            if os.path.exists(backup_info['path']):
                shutil.copy2(backup_info['path'], original_path)
                restored = True
        
        return restored

    def check_recription_process(self):
        """Check if RECRIPTION_PROCESS is set to True in Web.config"""
        try:
            config_file = "Web.config"
            if not os.path.exists(config_file):
                return False
            
            tree = ET.parse(config_file)
            root = tree.getroot()
            
            process_elements = root.findall(".//add[@key='RECRIPTION_PROCESS']")
            if not process_elements:
                return False
            
            return process_elements[0].get('value', '').lower() == 'true'
        except:
            return False

    @app.post("/admin/server/maintenance")
    async def toggle_maintenance_mode(
        maintenance: bool = Form(...),
        current_admin: Admin = Depends(get_current_admin)
    ):
        global SERVER_MAINTENANCE_MODE
        SERVER_MAINTENANCE_MODE = maintenance
        
        log_action("admin", current_admin.username, "toggle_maintenance", 
                  f"Maintenance mode set to {maintenance}")
        
        if maintenance:
            return {"message": "Maintenance mode activated. All non-admin requests will be redirected."}
        else:
            return {"message": "Maintenance mode deactivated. Server is operational."}

    @app.post("/admin/server/quarantine")
    async def toggle_quarantine_mode(
        request: Request,
        maintenance: bool = Form(...),
        current_admin: Admin = Depends(get_current_admin)
    ):
        if not hasattr(request.state, 'internal_call'):
            raise HTTPException(status_code=423, detail="This endpoint is locked for external calls")
        
        global SERVER_QUARANTINE_MODE
        SERVER_QUARANTINE_MODE = maintenance
        
        log_action("admin", current_admin.username, "toggle_quarantine", 
                  f"Quarantine mode set to {maintenance}")
        
        if maintenance:
            return {"message": "Quarantine mode activated. All requests will be redirected."}
        else:
            return {"message": "Quarantine mode deactivated. Server is operational."}

    @app.post("/admin/security/rotate-key")
    async def rotate_security_key(
        current_admin: Admin = Depends(get_current_admin),
        db_user: Session = Depends(get_user_db),
        db_queue: Session = Depends(get_queue_db)
    ):
        global SECRET_KEY, SERVER_QUARANTINE_MODE
        
        service = ServiceEndpoints()
        
        try:
            if service.check_recription_process():
                if service.restore_db_from_backup():
                    log_action("admin", current_admin.username, "rotate_key_restore", "Restored databases from backup due to interrupted process")
                else:
                    log_action("admin", current_admin.username, "rotate_key_restore_fail", "Failed to restore databases from backup")

            backup_files = service.create_db_backup()
            log_action("admin", current_admin.username, "rotate_key_backup", f"Created backup files: {backup_files}")

            service.update_web_config('RECRIPTION_PROCESS', 'true')
            log_action("admin", current_admin.username, "rotate_key_start", "Set RECRIPTION_PROCESS to true")

            SERVER_QUARANTINE_MODE = True
            log_action("admin", current_admin.username, "rotate_key_start", "Starting key rotation")

            progress_bar = tqdm(total=4, desc="Rotating security key", unit="step")

            progress_bar.set_description("Generating new security key")
            new_code, new_hashed_code = generate_and_hash_code()
            new_secret_key = f"{hashlib.sha256(new_code.encode()).hexdigest()}"
            log_action("admin", current_admin.username, "rotate_key", f"Generated new code: {new_code[:2]}**")
            progress_bar.update(1)
            time.sleep(0.5)

            progress_bar.set_description("Clearing queue")
            try:
                queue_count = db_queue.query(Queue).count()
                db_queue.query(Queue).delete()
                db_queue.commit()
                log_action("admin", current_admin.username, "rotate_key", f"Cleared queue with {queue_count} entries")
                progress_bar.update(1)
                time.sleep(0.5)
            except Exception as e:
                log_action("admin", current_admin.username, "rotate_key_error", f"Queue clearance failed: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Queue clearance failed: {str(e)}"
                )

            progress_bar.set_description("Updating user passwords")
            users_updated = 0
            try:
                users = db_user.query(User).all()
                for user in tqdm(users, desc="Processing users", leave=False):
                    if user.hashed_password and pwd_context.verify(SECRET_KEY, user.hashed_password):
                        user.hashed_password = pwd_context.hash(new_secret_key)
                        users_updated += 1
                db_user.commit()
                log_action("admin", current_admin.username, "rotate_key", f"Updated {users_updated} user passwords")
                progress_bar.update(1)
                time.sleep(0.5)
            except Exception as e:
                log_action("admin", current_admin.username, "rotate_key_error", f"Password update failed: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Password update failed: {str(e)}"
                )

            old_secret_key = SECRET_KEY
            SECRET_KEY = new_secret_key
            progress_bar.set_description("Updating config file")
            try:
                service.update_web_config('SECRET_KEY', new_secret_key)
                log_action("admin", current_admin.username, "rotate_key", "Config file updated successfully")
                progress_bar.update(1)
                time.sleep(0.5)
            except Exception as e:
                SECRET_KEY = old_secret_key
                log_action("admin", current_admin.username, "rotate_key_error", f"Config update failed: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Config update failed: {str(e)}"
                )

            progress_bar.close()
            
            service.update_web_config('RECRIPTION_PROCESS', 'false')
            log_action("admin", current_admin.username, "rotate_key_end", "Set RECRIPTION_PROCESS to false")
            
            return {
                "message": "Security key rotated successfully",
                "details": {
                    "users_updated": users_updated,
                    "queue_cleared": True,
                    "config_updated": True,
                    "backup_files": backup_files
                }
            }
        except HTTPException:
            raise
        except Exception as e:
            log_action("admin", current_admin.username, "rotate_key_error", f"Unexpected error: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Key rotation failed: {str(e)}"
            )
        finally:
            SERVER_QUARANTINE_MODE = False
            log_action("admin", current_admin.username, "rotate_key_end", "Key rotation completed")

    @app.post("/admin/security/rotateadmins-key")
    async def rotate_admins_security_key(
        current_admin: Admin = Depends(get_current_admin),
        db_admin: Session = Depends(get_admin_db)
    ):
        global ADMIN_SECRET_KEY, SERVER_QUARANTINE_MODE
        
        service = ServiceEndpoints()
        
        try:
            if service.check_recription_process():
                if service.restore_db_from_backup():
                    log_action("admin", current_admin.username, "rotate_admins_key_restore", "Restored databases from backup due to interrupted process")
                else:
                    log_action("admin", current_admin.username, "rotate_admins_key_restore_fail", "Failed to restore databases from backup")

            backup_files = service.create_db_backup()
            log_action("admin", current_admin.username, "rotate_admins_key_backup", f"Created backup files: {backup_files}")

            service.update_web_config('RECRIPTION_PROCESS', 'true')
            log_action("admin", current_admin.username, "rotate_admins_key_start", "Set RECRIPTION_PROCESS to true")

            SERVER_QUARANTINE_MODE = True
            log_action("admin", current_admin.username, "rotate_admins_key_start", "Starting admin key rotation")

            progress_bar = tqdm(total=3, desc="Rotating admin security key", unit="step")

            progress_bar.set_description("Generating new admin key")
            new_code, new_hashed_code = generate_and_hash_code()
            new_admin_secret_key = f"{hashlib.sha256(new_code.encode()).hexdigest()}"
            log_action("admin", current_admin.username, "rotate_admins_key", f"Generated new admin code: {new_code[:2]}**")
            progress_bar.update(1)
            time.sleep(0.5)

            progress_bar.set_description("Updating admin passwords")
            admins_updated = 0
            try:
                admins = db_admin.query(Admin).all()
                for admin in tqdm(admins, desc="Processing admins", leave=False):
                    if admin.hashed_password and pwd_context.verify(ADMIN_SECRET_KEY, admin.hashed_password):
                        admin.hashed_password = pwd_context.hash(new_admin_secret_key)
                        admins_updated += 1
                db_admin.commit()
                log_action("admin", current_admin.username, "rotate_admins_key", f"Updated {admins_updated} admin passwords")
                progress_bar.update(1)
                time.sleep(0.5)
            except Exception as e:
                log_action("admin", current_admin.username, "rotate_admins_key_error", f"Admin password update failed: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Admin password update failed: {str(e)}"
                )

            old_admin_secret_key = ADMIN_SECRET_KEY
            ADMIN_SECRET_KEY = new_admin_secret_key
            progress_bar.set_description("Updating config file")
            try:
                service.update_web_config('ADMIN_SECRET_KEY', new_admin_secret_key)
                log_action("admin", current_admin.username, "rotate_admins_key", "Config file updated successfully")
                progress_bar.update(1)
                time.sleep(0.5)
            except Exception as e:
                ADMIN_SECRET_KEY = old_admin_secret_key
                log_action("admin", current_admin.username, "rotate_admins_key_error", f"Config update failed: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Config update failed: {str(e)}"
                )

            progress_bar.close()
            
            service.update_web_config('RECRIPTION_PROCESS', 'false')
            log_action("admin", current_admin.username, "rotate_admins_key_end", "Set RECRIPTION_PROCESS to false")
            
            return {
                "message": "Admin security key rotated successfully",
                "details": {
                    "admins_updated": admins_updated,
                    "config_updated": True,
                    "backup_files": backup_files
                }
            }
        except HTTPException:
            raise
        except Exception as e:
            log_action("admin", current_admin.username, "rotate_admins_key_error", f"Unexpected error: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Admin key rotation failed: {str(e)}"
            )
        finally:
            SERVER_QUARANTINE_MODE = False
            log_action("admin", current_admin.username, "rotate_admins_key_end", "Admin key rotation completed")