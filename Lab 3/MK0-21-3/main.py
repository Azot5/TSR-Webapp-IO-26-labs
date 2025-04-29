import random
import hashlib
import os
import logging
import time
import shutil
import jwt
from xml.etree import ElementTree as ET
from tqdm import tqdm
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, Request, Form, status
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from recovery_checker import check_recovery_needed
from config_reader import config

os.makedirs(config.DATABASE_DIRECTORY, exist_ok=True)
os.makedirs(config.LOGS_DIRECTORY, exist_ok=True)

app = FastAPI()

check_recovery_needed()

templates = Jinja2Templates(directory=config.TEMPLATES_DIRECTORY)

# MongoDB setup
mongo_client = MongoClient(config.MONGODB_URI)
db = mongo_client[config.MONGODB_DATABASE]

# Collections
class User:
    collection_name = "users"

class Admin:
    collection_name = "admins"

class Queue:
    collection_name = "queue"

class Vaccine:
    collection_name = "vaccines"

# Database access functions
def get_user_db():
    return db[User.collection_name]

def get_admin_db():
    return db[Admin.collection_name]

def get_queue_db():
    return db[Queue.collection_name]

def get_vaccine_db():
    return db[Vaccine.collection_name]

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

# Utility functions
def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(db, username: str, password: str):
    user = db.find_one({"username": username})
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return user

def authenticate_admin(db, username: str, password: str):
    admin = db.find_one({"username": username})
    if not admin or not verify_password(password, admin["hashed_password"]):
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

async def get_current_user(token: str = Depends(oauth2_scheme), db = Depends(get_user_db)):
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.find_one({"username": username})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def get_current_admin(token: str = Depends(oauth2_scheme), db = Depends(get_admin_db)):
    try:
        payload = jwt.decode(token, config.ADMIN_SECRET_KEY, algorithms=[config.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    admin = db.find_one({"username": username})
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
        user_db = Depends(get_user_db),
        admin_db = Depends(get_admin_db)
    ):
        if admin_key and hashlib.sha256((config.ADMIN_SECRET_KEY + admin_key).encode('utf-8')).hexdigest() == hashed_code:
            try:
                new_admin = {
                    "username": username,
                    "hashed_password": get_password_hash(password)
                }
                admin_db.insert_one(new_admin)
                log_action("admin", username, "register", "Admin registration successful")
                return RedirectResponse(url="/", status_code=303)
            except PyMongoError as e:
                raise HTTPException(status_code=500, detail=str(e))

        if user_db.find_one({"username": username}):
            log_action("user", username, "register", "Username already registered")
            error_message = "Username already registered"
            return templates.TemplateResponse("registration_error.html", {"request": request, "error_message": error_message})

        if user_db.find_one({"email": email}):
            log_action("user", username, "register", "Email already registered")
            error_message = "Email already registered"
            return templates.TemplateResponse("registration_error.html", {"request": request, "error_message": error_message})

        new_user = {
            "username": username,
            "email": email,
            "hashed_password": get_password_hash(password),
            "vaccine_info": None
        }
        user_db.insert_one(new_user)
        log_action("user", username, "register", "Registration successful")

        return RedirectResponse(url="/", status_code=303)

    @app.post("/token")
    async def login(
        request: Request,
        form_data: OAuth2PasswordRequestForm = Depends(),
        user_db = Depends(get_user_db)
    ):
        user = authenticate_user(user_db, form_data.username, form_data.password)
        if not user:
            raise HTTPException(status_code=401, detail="Incorrect username or password")

        access_token = create_access_token({"sub": user["username"]})
        log_action("user", user["username"], "login", "User logged in successfully")
        
        return JSONResponse(content={"access_token": access_token})

    @app.get("/home", response_class=HTMLResponse)
    async def home_page(request: Request, current_user: dict = Depends(get_current_user)):
        return templates.TemplateResponse("home.html", {"request": request, "username": current_user["username"]})

    @app.get("/edit-account-home", response_class=HTMLResponse)
    async def edit_account_home(request: Request, current_user: dict = Depends(get_current_user)):
        return templates.TemplateResponse("edit_account.html", {"request": request, "username": current_user["username"]})

    @app.get("/edit-account-username", response_class=HTMLResponse)
    async def edit_account_username(request: Request, current_user: dict = Depends(get_current_user)):
        return templates.TemplateResponse("edit_account_username.html", {"request": request, "username": current_user["username"]})

    @app.get("/edit-account-password", response_class=HTMLResponse)
    async def edit_account_password(request: Request, current_user: dict = Depends(get_current_user)):
        return templates.TemplateResponse("edit_account_password.html", {"request": request, "username": current_user["username"]})

    @app.get("/edit-account-email", response_class=HTMLResponse)
    async def edit_account_email(request: Request, current_user: dict = Depends(get_current_user)):
        return templates.TemplateResponse("edit_account_email.html", {"request": request, "username": current_user["username"]})

    @app.post("/update-username")
    async def update_username(
        new_username: str = Form(...),
        current_user: dict = Depends(get_current_user),
        user_db = Depends(get_user_db)
    ):
        if new_username == current_user["username"]:
            raise HTTPException(status_code=406, detail="New username cannot be the same as the old one")

        if user_db.find_one({"username": new_username}):
            raise HTTPException(status_code=400, detail="Username already taken")

        old_username = current_user["username"]
        user_db.update_one(
            {"username": old_username},
            {"$set": {"username": new_username}}
        )

        log_action("user", old_username, "update-username", f"Username changed to {new_username}")

        return {"message": f"successfully updated to {new_username}"}

    @app.post("/update-password")
    async def update_password(
        old_password: str = Form(...),
        new_password: str = Form(...),
        current_user: dict = Depends(get_current_user),
        user_db = Depends(get_user_db)
    ):
        if not verify_password(old_password, current_user["hashed_password"]):
            raise HTTPException(status_code=400, detail="Old password is incorrect")

        user_db.update_one(
            {"username": current_user["username"]},
            {"$set": {"hashed_password": get_password_hash(new_password)}}
        )
        log_action("user", current_user["username"], "update-password", "Password changed successfully")
        return {"message": "Password updated successfully"}

    @app.post("/update-email")
    async def update_email(
        new_email: str = Form(...),
        current_user: dict = Depends(get_current_user),
        user_db = Depends(get_user_db)
    ):
        if user_db.find_one({"email": new_email}):
            raise HTTPException(status_code=400, detail="Email already in use")

        user_db.update_one(
            {"username": current_user["username"]},
            {"$set": {"email": new_email}}
        )
        log_action("user", current_user["username"], "update-email", f"Email changed to {new_email}")
        return {"message": "Email updated successfully"}

    @app.post("/user/delete-account")
    async def delete_user_account(
        password: str = Form(...),
        current_user: dict = Depends(get_current_user),
        user_db = Depends(get_user_db),
        queue_db = Depends(get_queue_db)
    ):
        if not verify_password(password, current_user["hashed_password"]):
            raise HTTPException(status_code=400, detail="Incorrect password")

        queue_db.delete_one({"name": current_user["username"]})
        user_db.delete_one({"username": current_user["username"]})

        log_action("user", current_user["username"], "delete_account", "User deleted their own account")
        
        return {"message": "Account deleted successfully"}

# Queue endpoints
class QueueEndpoints:
    @app.get("/queue/position")
    async def get_user_position(
        current_user: dict = Depends(get_current_user),
        queue_db = Depends(get_queue_db)
    ):
        queue_entry = queue_db.find_one({"name": current_user["username"]})
        if not queue_entry:
            raise HTTPException(status_code=204, detail="User not found in queue")

        position = queue_db.count_documents({"_id": {"$lt": queue_entry["_id"]}}) + 1
        log_action("queue", current_user["username"], "get_position", f"User checked queue position: {position}")
        return {"position": position, "name": queue_entry["name"]}

    @app.post("/queue/add")
    async def add_to_queue(
        request: Request,
        current_user: dict = Depends(get_current_user),
        queue_db = Depends(get_queue_db)
    ):
        existing_entry = queue_db.find_one({"name": current_user["username"]})
        if existing_entry:
            raise HTTPException(status_code=400, detail="User already in queue")

        new_queue_entry = {
            "name": current_user["username"],
            "created_at": datetime.utcnow()
        }
        result = queue_db.insert_one(new_queue_entry)
        new_queue_entry["_id"] = result.inserted_id

        log_action("queue", current_user["username"], "add_to_queue", f"User added to queue with ID: {result.inserted_id}")
        return {"id": str(result.inserted_id), "name": new_queue_entry["name"]}

    @app.post("/queue/remove")
    async def remove_from_queue(
        current_user: dict = Depends(get_current_user),
        queue_db = Depends(get_queue_db)
    ):
        queue_entry = queue_db.find_one({"name": current_user["username"]})
        if not queue_entry:
            raise HTTPException(status_code=404, detail="User not found in queue")

        queue_db.delete_one({"_id": queue_entry["_id"]})
        log_action("queue", current_user["username"], "remove_from_queue", f"User removed from queue, ID was: {queue_entry['_id']}")
        return {"message": "User removed", "id": str(queue_entry["_id"])}

# Admin endpoints
class AdminEndpoints:
    @app.get("/admin-login", response_class=HTMLResponse)
    async def admin_login_page(request: Request):
        return templates.TemplateResponse("admin_login.html", {"request": request})

    @app.get("/admin-panel", response_class=HTMLResponse)
    async def admin_panel_page(request: Request, current_admin: dict = Depends(get_current_admin)):
        return templates.TemplateResponse("admin_panel.html", {"request": request, "username": current_admin["username"]})

    @app.post("/admin/register")
    async def register_admin(
        username: str = Form(...),
        password: str = Form(...),
        admin_key: str = Form(...),
        admin_db = Depends(get_admin_db)
    ):
        if hashed_code != admin_key:
            raise HTTPException(status_code=403, detail="Invalid admin key")
        if not admin_key:
            raise HTTPException(status_code=403, detail="Admin key is required")

        if admin_db.find_one({"username": username}):
            raise HTTPException(status_code=400, detail="Admin username already registered")
        
        new_admin = {
            "username": username,
            "hashed_password": get_password_hash(password)
        }
        admin_db.insert_one(new_admin)
        
        log_action("admin", username, "register_admin", "New admin registered")
        return {"message": "Admin registered successfully"}  

    @app.post("/admin/token")
    async def login_admin(
        form_data: OAuth2PasswordRequestForm = Depends(),
        admin_db = Depends(get_admin_db)
    ):
        admin = authenticate_admin(admin_db, form_data.username, form_data.password)
        if not admin:
            raise HTTPException(status_code=401, detail="Incorrect username or password")

        access_token = create_admin_access_token({"sub": admin["username"]})
        
        log_action("admin", admin["username"], "admin_login", "Successful admin login")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "username": admin["username"]
        }

    @app.get("/admin/queue/user/{queue_id}")
    async def get_user_by_queue_id(
        queue_id: str,
        current_admin: dict = Depends(get_current_admin),
        queue_db = Depends(get_queue_db)
    ):
        try:
            from bson import ObjectId
            user_entry = queue_db.find_one({"_id": ObjectId(queue_id)})
        except:
            user_entry = None
            
        if not user_entry:
            raise HTTPException(status_code=404, detail="User not found in queue")
        
        log_action("admin", current_admin["username"], "get_queue_user", f"Retrieved user in queue with ID: {queue_id}")
        
        return {"id": str(user_entry["_id"]), "name": user_entry["name"]}

    @app.post("/admin/queue/remove_first")
    async def admin_remove_first(
        vaccine_name: str = Form(...),
        current_admin: dict = Depends(get_current_admin),
        queue_db = Depends(get_queue_db),
        user_db = Depends(get_user_db)
    ):
        first_entry = queue_db.find_one(sort=[("_id", 1)])
        if not first_entry:
            raise HTTPException(status_code=400, detail="Queue is empty")

        try:
            user = user_db.find_one({"username": first_entry["name"]})
            if user:
                current_time = datetime.now().strftime("%Y.%m.%d %H:%M:%S")
                vaccine_info = f"{vaccine_name} {current_time}"

                update_data = {}
                if "vaccine_info" not in user or user["vaccine_info"] is None:
                    update_data["vaccine_info"] = vaccine_info
                else:
                    update_data["vaccine_info"] = f"{user['vaccine_info']}, {vaccine_info}"

                user_db.update_one(
                    {"username": first_entry["name"]},
                    {"$set": update_data}
                )

            queue_db.delete_one({"_id": first_entry["_id"]})

            log_action("admin", current_admin["username"], "remove_first_queue", 
                      f"Removed first in queue: {first_entry['name']}, Vaccine: {vaccine_name}")
            log_action("queue", current_admin["username"], "remove_first_queue", 
                      f"Removed first in queue: {first_entry['name']}, Vaccine: {vaccine_name}")

            return {
                "message": "First entry removed and user vaccinated",
                "vaccinated_user": first_entry["name"],
                "vaccine_info": vaccine_info
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/admin/queue/clear")
    async def clear_queue(
        current_admin: dict = Depends(get_current_admin),
        queue_db = Depends(get_queue_db)
    ):
        queue_db.delete_many({})
        
        log_action("admin", current_admin["username"], "clear_queue", "Cleared entire queue")
        log_action("queue", current_admin["username"], "clear_queue", "Cleared entire queue")
        
        return {"message": "Queue cleared successfully"}

    @app.post("/admin/delete")
    async def delete_admin(
        username: str = Form(...),
        current_admin: dict = Depends(get_current_admin),
        admin_db = Depends(get_admin_db)
    ):
        admin = admin_db.find_one({"username": username})
        if not admin:
            raise HTTPException(status_code=404, detail="Admin not found")

        if current_admin["username"] == username:
            raise HTTPException(status_code=400, detail="Cannot delete yourself")

        admin_db.delete_one({"username": username})

        log_action("admin", current_admin["username"], "delete_admin", f"Deleted admin: {username}")
        
        return {"message": f"Admin '{username}' deleted successfully"}

    @app.get("/admin/data")
    async def get_admin_data(
        current_admin: dict = Depends(get_current_admin),
        admin_db = Depends(get_admin_db)
    ):
        admins = list(admin_db.find({}, {"_id": 0, "hashed_password": 0}))
        
        log_action("admin", current_admin["username"], "get_admin_data", "Retrieved all admin data")
        return {"admins": admins}

    @app.get("/admin/data/all")
    async def get_all_database_data(
        current_admin: dict = Depends(get_current_admin),
        admin_db = Depends(get_admin_db),
        user_db = Depends(get_user_db),
        queue_db = Depends(get_queue_db),
        vaccine_db = Depends(get_vaccine_db)
    ):
        data = {
            "users": list(user_db.find({}, {"_id": 0, "hashed_password": 0})),
            "admins": list(admin_db.find({}, {"_id": 0, "hashed_password": 0})),
            "queue": list(queue_db.find({}, {"_id": 0})),
            "vaccines": list(vaccine_db.find({}, {"_id": 0}))
        }
        
        log_action("admin", current_admin["username"], "get_all_data", "Retrieved all database data")
        return data

    @app.post("/admin/delete-user")
    async def admin_delete_user(
        username_to_delete: str = Form(...),
        current_admin: dict = Depends(get_current_admin),
        admin_db = Depends(get_admin_db),
        user_db = Depends(get_user_db),
        queue_db = Depends(get_queue_db)
    ):
        if current_admin["username"] == username_to_delete:
            raise HTTPException(status_code=400, detail="Cannot delete yourself")

        user = user_db.find_one({"username": username_to_delete})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        queue_db.delete_one({"name": username_to_delete})
        user_db.delete_one({"username": username_to_delete})

        log_action("admin", current_admin["username"], "admin_delete_user", 
                  f"Admin deleted user account: {username_to_delete}")
        log_action("user", current_admin["username"], "admin_delete_user", 
                  f"Admin deleted user account: {username_to_delete}")
        
        return {"message": f"User '{username_to_delete}' deleted successfully"}

# Vaccine endpoints
class VaccineEndpoints:
    @app.post("/admin/vaccines/add")
    async def add_vaccine(
        vaccine_name: str = Form(...),
        current_admin: dict = Depends(get_current_admin),
        vaccine_db = Depends(get_vaccine_db)
    ):
        existing_vaccine = vaccine_db.find_one({"vaccine_name": vaccine_name})
        if existing_vaccine:
            raise HTTPException(status_code=400, detail="Vaccine already exists")

        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        
        new_vaccine = {
            "vaccine_name": vaccine_name,
            "date_added": current_time,
            "added_by": current_admin["username"],
            "is_active": True,
            "last_modified": current_time,
            "modified_by": current_admin["username"]
        }
        
        vaccine_db.insert_one(new_vaccine)
        
        log_action("vaccine", current_admin["username"], "add_vaccine", f"Added vaccine: {vaccine_name}")
        log_action("admin", current_admin["username"], "add_vaccine", f"Added vaccine: {vaccine_name}")
        
        return {
            "message": "Vaccine added successfully",
            "vaccine_name": vaccine_name,
            "date_added": current_time,
            "added_by": current_admin["username"]
        }

    @app.post("/admin/vaccines/update")
    async def update_vaccine(
        vaccine_name: str = Form(...),
        new_name: str = Form(None),
        is_active: bool = Form(None),
        current_admin: dict = Depends(get_current_admin),
        vaccine_db = Depends(get_vaccine_db)
    ):
        vaccine = vaccine_db.find_one({"vaccine_name": vaccine_name})
        if not vaccine:
            raise HTTPException(status_code=404, detail="Vaccine not found")

        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        changes = []
        update_data = {}
        
        if new_name and new_name != vaccine["vaccine_name"]:
            existing = vaccine_db.find_one({"vaccine_name": new_name})
            if existing:
                raise HTTPException(status_code=400, detail="Vaccine name already exists")
            
            changes.append(f"name changed from {vaccine['vaccine_name']} to {new_name}")
            update_data["vaccine_name"] = new_name

        if is_active is not None and is_active != vaccine["is_active"]:
            changes.append(f"active status changed from {vaccine['is_active']} to {is_active}")
            update_data["is_active"] = is_active

        if changes:
            update_data["last_modified"] = current_time
            update_data["modified_by"] = current_admin["username"]
            
            vaccine_db.update_one(
                {"vaccine_name": vaccine_name},
                {"$set": update_data}
            )
            
            log_action("vaccine", current_admin["username"], "update_vaccine", 
                      f"Updated vaccine {vaccine_name}: " + ", ".join(changes))
            log_action("admin", current_admin["username"], "update_vaccine", 
                      f"Updated vaccine {vaccine_name}: " + ", ".join(changes))
            
            return {
                "message": "Vaccine updated successfully",
                "changes": changes,
                "last_modified": current_time,
                "modified_by": current_admin["username"]
            }
        else:
            return {"message": "No changes detected"}

    @app.post("/admin/vaccines/delete")
    async def delete_vaccine(
        vaccine_name: str = Form(...),
        current_admin: dict = Depends(get_current_admin),
        vaccine_db = Depends(get_vaccine_db)
    ):
        vaccine = vaccine_db.find_one({"vaccine_name": vaccine_name})
        if not vaccine:
            raise HTTPException(status_code=404, detail="Vaccine not found")

        vaccine_db.delete_one({"vaccine_name": vaccine_name})
        
        log_action("vaccine", current_admin["username"], "delete_vaccine", f"Deleted vaccine: {vaccine_name}")
        log_action("admin", current_admin["username"], "delete_vaccine", f"Deleted vaccine: {vaccine_name}")
        
        return {"message": "Vaccine deleted successfully"}

    @app.post("/admin/vaccines/list")
    async def list_vaccines(
        current_admin: dict = Depends(get_current_admin),
        vaccine_db = Depends(get_vaccine_db)
    ):
        vaccines = list(vaccine_db.find({}, {"_id": 0}))
        
        log_action("vaccine", current_admin["username"], "list_vaccines", "Retrieved list of all vaccines")
        log_action("admin", current_admin["username"], "list_vaccines", "Retrieved list of all vaccines")
        return {"vaccines": vaccines}

    # New MongoDB-specific feature: Text search for vaccines
    @app.get("/vaccines/search")
    async def search_vaccines(
        query: str,
        current_user: dict = Depends(get_current_user),
        vaccine_db = Depends(get_vaccine_db)
    ):
        try:
            # Create text index if not exists
            vaccine_db.create_index([("vaccine_name", "text")])
            
            results = vaccine_db.find(
                {"$text": {"$search": query}},
                {"score": {"$meta": "textScore"}}
            ).sort([("score", {"$meta": "textScore"})])
            
            return {"results": list(results)}
        except PyMongoError as e:
            raise HTTPException(status_code=500, detail=str(e))

# Service endpoints
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
        
        for db_file in [config.USER_DB_FILE, config.ADMIN_DB_FILE, config.QUEUE_DB_FILE, config.VACCINE_DB_FILE]:
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
        current_admin: dict = Depends(get_current_admin)
    ):
        global SERVER_MAINTENANCE_MODE
        SERVER_MAINTENANCE_MODE = maintenance
        
        log_action("admin", current_admin["username"], "toggle_maintenance", 
                  f"Maintenance mode set to {maintenance}")
        
        if maintenance:
            return {"message": "Maintenance mode activated. All non-admin requests will be redirected."}
        else:
            return {"message": "Maintenance mode deactivated. Server is operational."}

    @app.post("/admin/server/quarantine")
    async def toggle_quarantine_mode(
        request: Request,
        maintenance: bool = Form(...),
        current_admin: dict = Depends(get_current_admin)
    ):
        if not hasattr(request.state, 'internal_call'):
            raise HTTPException(status_code=423, detail="This endpoint is locked for external calls")
        
        global SERVER_QUARANTINE_MODE
        SERVER_QUARANTINE_MODE = maintenance
        
        log_action("admin", current_admin["username"], "toggle_quarantine", 
                  f"Quarantine mode set to {maintenance}")
        
        if maintenance:
            return {"message": "Quarantine mode activated. All requests will be redirected."}
        else:
            return {"message": "Quarantine mode deactivated. Server is operational."}

    @app.post("/admin/security/rotate-key")
    async def rotate_security_key(
        current_admin: dict = Depends(get_current_admin),
        user_db = Depends(get_user_db),
        queue_db = Depends(get_queue_db)
    ):
        global SECRET_KEY, SERVER_QUARANTINE_MODE
        
        service = ServiceEndpoints()
        
        try:
            if service.check_recription_process():
                if service.restore_db_from_backup():
                    log_action("admin", current_admin["username"], "rotate_key_restore", "Restored databases from backup due to interrupted process")
                else:
                    log_action("admin", current_admin["username"], "rotate_key_restore_fail", "Failed to restore databases from backup")

            backup_files = service.create_db_backup()
            log_action("admin", current_admin["username"], "rotate_key_backup", f"Created backup files: {backup_files}")

            service.update_web_config('RECRIPTION_PROCESS', 'true')
            log_action("admin", current_admin["username"], "rotate_key_start", "Set RECRIPTION_PROCESS to true")

            SERVER_QUARANTINE_MODE = True
            log_action("admin", current_admin["username"], "rotate_key_start", "Starting key rotation")

            progress_bar = tqdm(total=4, desc="Rotating security key", unit="step")

            progress_bar.set_description("Generating new security key")
            new_code, new_hashed_code = generate_and_hash_code()
            new_secret_key = f"{hashlib.sha256(new_code.encode()).hexdigest()}"
            log_action("admin", current_admin["username"], "rotate_key", f"Generated new code: {new_code[:2]}**")
            progress_bar.update(1)
            time.sleep(0.5)

            progress_bar.set_description("Clearing queue")
            try:
                queue_count = queue_db.count_documents({})
                queue_db.delete_many({})
                log_action("admin", current_admin["username"], "rotate_key", f"Cleared queue with {queue_count} entries")
                progress_bar.update(1)
                time.sleep(0.5)
            except Exception as e:
                log_action("admin", current_admin["username"], "rotate_key_error", f"Queue clearance failed: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Queue clearance failed: {str(e)}"
                )

            progress_bar.set_description("Updating user passwords")
            users_updated = 0
            try:
                users = user_db.find({})
                for user in tqdm(list(users), desc="Processing users", leave=False):
                    if user["hashed_password"] and pwd_context.verify(SECRET_KEY, user["hashed_password"]):
                        user_db.update_one(
                            {"_id": user["_id"]},
                            {"$set": {"hashed_password": pwd_context.hash(new_secret_key)}}
                        )
                        users_updated += 1
                log_action("admin", current_admin["username"], "rotate_key", f"Updated {users_updated} user passwords")
                progress_bar.update(1)
                time.sleep(0.5)
            except Exception as e:
                log_action("admin", current_admin["username"], "rotate_key_error", f"Password update failed: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Password update failed: {str(e)}"
                )

            old_secret_key = SECRET_KEY
            SECRET_KEY = new_secret_key
            progress_bar.set_description("Updating config file")
            try:
                service.update_web_config('SECRET_KEY', new_secret_key)
                log_action("admin", current_admin["username"], "rotate_key", "Config file updated successfully")
                progress_bar.update(1)
                time.sleep(0.5)
            except Exception as e:
                SECRET_KEY = old_secret_key
                log_action("admin", current_admin["username"], "rotate_key_error", f"Config update failed: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Config update failed: {str(e)}"
                )

            progress_bar.close()
            
            service.update_web_config('RECRIPTION_PROCESS', 'false')
            log_action("admin", current_admin["username"], "rotate_key_end", "Set RECRIPTION_PROCESS to false")
            
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
            log_action("admin", current_admin["username"], "rotate_key_error", f"Unexpected error: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Key rotation failed: {str(e)}"
            )
        finally:
            SERVER_QUARANTINE_MODE = False
            log_action("admin", current_admin["username"], "rotate_key_end", "Key rotation completed")

    @app.post("/admin/security/rotateadmins-key")
    async def rotate_admins_security_key(
        current_admin: dict = Depends(get_current_admin),
        admin_db = Depends(get_admin_db)
    ):
        global ADMIN_SECRET_KEY, SERVER_QUARANTINE_MODE
        
        service = ServiceEndpoints()
        
        try:
            if service.check_recription_process():
                if service.restore_db_from_backup():
                    log_action("admin", current_admin["username"], "rotate_admins_key_restore", "Restored databases from backup due to interrupted process")
                else:
                    log_action("admin", current_admin["username"], "rotate_admins_key_restore_fail", "Failed to restore databases from backup")

            backup_files = service.create_db_backup()
            log_action("admin", current_admin["username"], "rotate_admins_key_backup", f"Created backup files: {backup_files}")

            service.update_web_config('RECRIPTION_PROCESS', 'true')
            log_action("admin", current_admin["username"], "rotate_admins_key_start", "Set RECRIPTION_PROCESS to true")

            SERVER_QUARANTINE_MODE = True
            log_action("admin", current_admin["username"], "rotate_admins_key_start", "Starting admin key rotation")

            progress_bar = tqdm(total=3, desc="Rotating admin security key", unit="step")

            progress_bar.set_description("Generating new admin key")
            new_code, new_hashed_code = generate_and_hash_code()
            new_admin_secret_key = f"{hashlib.sha256(new_code.encode()).hexdigest()}"
            log_action("admin", current_admin["username"], "rotate_admins_key", f"Generated new admin code: {new_code[:2]}**")
            progress_bar.update(1)
            time.sleep(0.5)

            progress_bar.set_description("Updating admin passwords")
            admins_updated = 0
            try:
                admins = admin_db.find({})
                for admin in tqdm(list(admins), desc="Processing admins", leave=False):
                    if admin["hashed_password"] and pwd_context.verify(ADMIN_SECRET_KEY, admin["hashed_password"]):
                        admin_db.update_one(
                            {"_id": admin["_id"]},
                            {"$set": {"hashed_password": pwd_context.hash(new_admin_secret_key)}}
                        )
                        admins_updated += 1
                log_action("admin", current_admin["username"], "rotate_admins_key", f"Updated {admins_updated} admin passwords")
                progress_bar.update(1)
                time.sleep(0.5)
            except Exception as e:
                log_action("admin", current_admin["username"], "rotate_admins_key_error", f"Admin password update failed: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Admin password update failed: {str(e)}"
                )

            old_admin_secret_key = ADMIN_SECRET_KEY
            ADMIN_SECRET_KEY = new_admin_secret_key
            progress_bar.set_description("Updating config file")
            try:
                service.update_web_config('ADMIN_SECRET_KEY', new_admin_secret_key)
                log_action("admin", current_admin["username"], "rotate_admins_key", "Config file updated successfully")
                progress_bar.update(1)
                time.sleep(0.5)
            except Exception as e:
                ADMIN_SECRET_KEY = old_admin_secret_key
                log_action("admin", current_admin["username"], "rotate_admins_key_error", f"Config update failed: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Config update failed: {str(e)}"
                )

            progress_bar.close()
            
            service.update_web_config('RECRIPTION_PROCESS', 'false')
            log_action("admin", current_admin["username"], "rotate_admins_key_end", "Set RECRIPTION_PROCESS to false")
            
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
            log_action("admin", current_admin["username"], "rotate_admins_key_error", f"Unexpected error: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Admin key rotation failed: {str(e)}"
            )
        finally:
            SERVER_QUARANTINE_MODE = False
            log_action("admin", current_admin["username"], "rotate_admins_key_end", "Admin key rotation completed")

    # New MongoDB-specific feature: Queue statistics with aggregation
    @app.get("/admin/queue/stats")
    async def get_queue_stats(
        current_admin: dict = Depends(get_current_admin),
        queue_db = Depends(get_queue_db)
    ):
        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "average_wait_time": {
                        "$avg": {
                            "$subtract": [datetime.utcnow(), "$created_at"]
                        }
                    },
                    "oldest_entry": {"$min": "$created_at"},
                    "newest_entry": {"$max": "$created_at"}
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "total": 1,
                    "average_wait_time": {
                        "$divide": ["$average_wait_time", 1000]  # Convert to seconds
                    },
                    "oldest_entry": 1,
                    "newest_entry": 1
                }
            }
        ]
        
        try:
            stats = list(queue_db.aggregate(pipeline))
            if stats:
                # Format the results
                stats[0]["average_wait_time"] = round(stats[0]["average_wait_time"], 2)
                return {"stats": stats[0]}
            return {"stats": {}}
        except PyMongoError as e:
            raise HTTPException(status_code=500, detail=str(e))

    # New MongoDB-specific feature: User vaccination history
    @app.get("/user/vaccine-history")
    async def get_vaccine_history(
        current_user: dict = Depends(get_current_user),
        user_db = Depends(get_user_db)
    ):
        try:
            user = user_db.find_one(
                {"username": current_user["username"]},
                {"vaccine_info": 1, "_id": 0}
            )
            if not user or "vaccine_info" not in user:
                return {"history": []}
            
            # Parse vaccine info string into structured data
            history = []
            entries = user["vaccine_info"].split(", ")
            for entry in entries:
                parts = entry.split(" ")
                if len(parts) >= 2:
                    vaccine_name = " ".join(parts[:-1])
                    timestamp = parts[-1]
                    history.append({
                        "vaccine": vaccine_name,
                        "timestamp": timestamp
                    })
            
            return {"history": history}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

# New MongoDB-specific feature: Bulk operations for admin
class BulkOperations:
    @app.post("/admin/users/bulk-deactivate")
    async def bulk_deactivate_users(
        usernames: list = Form(...),
        current_admin: dict = Depends(get_current_admin),
        user_db = Depends(get_user_db)
    ):
        try:
            result = user_db.update_many(
                {"username": {"$in": usernames}},
                {"$set": {"is_active": False}}
            )
            log_action("admin", current_admin["username"], "bulk_deactivate", f"Deactivated {result.modified_count} users")
            return {
                "message": f"Successfully deactivated {result.modified_count} users",
                "modified_count": result.modified_count
            }
        except PyMongoError as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/admin/vaccines/bulk-update")
    async def bulk_update_vaccines(
        vaccine_names: list = Form(...),
        is_active: bool = Form(...),
        current_admin: dict = Depends(get_current_admin),
        vaccine_db = Depends(get_vaccine_db)
    ):
        try:
            current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            result = vaccine_db.update_many(
                {"vaccine_name": {"$in": vaccine_names}},
                {"$set": {
                    "is_active": is_active,
                    "last_modified": current_time,
                    "modified_by": current_admin["username"]
                }}
            )
            log_action("admin", current_admin["username"], "bulk_update_vaccines", 
                      f"Updated {result.modified_count} vaccines to active={is_active}")
            return {
                "message": f"Updated {result.modified_count} vaccines",
                "modified_count": result.modified_count
            }
        except PyMongoError as e:
            raise HTTPException(status_code=500, detail=str(e))

# New MongoDB-specific feature: Index management
class IndexManagement:
    @app.post("/admin/db/ensure-indexes")
    async def ensure_indexes(
        current_admin: dict = Depends(get_current_admin),
        user_db = Depends(get_user_db),
        admin_db = Depends(get_admin_db),
        queue_db = Depends(get_queue_db),
        vaccine_db = Depends(get_vaccine_db)
    ):
        try:
            # Create indexes for all collections
            user_db.create_index("username", unique=True)
            user_db.create_index("email", unique=True)
            
            admin_db.create_index("username", unique=True)
            
            queue_db.create_index("name", unique=True)
            
            vaccine_db.create_index("vaccine_name", unique=True)
            vaccine_db.create_index([("vaccine_name", "text")])
            
            log_action("admin", current_admin["username"], "ensure_indexes", "Created all database indexes")
            return {"message": "Database indexes created successfully"}
        except PyMongoError as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/admin/db/index-info")
    async def get_index_info(
        current_admin: dict = Depends(get_current_admin),
        user_db = Depends(get_user_db),
        admin_db = Depends(get_admin_db),
        queue_db = Depends(get_queue_db),
        vaccine_db = Depends(get_vaccine_db)
    ):
        try:
            indexes = {
                "users": list(user_db.index_information()),
                "admins": list(admin_db.index_information()),
                "queue": list(queue_db.index_information()),
                "vaccines": list(vaccine_db.index_information())
            }
            return {"indexes": indexes}
        except PyMongoError as e:
            raise HTTPException(status_code=500, detail=str(e))