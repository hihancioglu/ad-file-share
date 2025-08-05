import os
import secrets
import json
from datetime import datetime
from fastapi import FastAPI, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import ldap3
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

LDAP_SERVER = os.getenv("LDAP_SERVER")
LDAP_DOMAIN = os.getenv("LDAP_DOMAIN")

SHARE_LINKS_FILE = os.path.join(DATA_DIR, "share_links.json")
DOWNLOAD_LOGS_FILE = os.path.join(DATA_DIR, "download_logs.json")


def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f)


# Kalıcı public paylaşım linklerini tutmak için { token: {username, filename} }
SHARE_LINKS = load_json(SHARE_LINKS_FILE)
# İndirme loglarını tutmak için { username: [ {filename, timestamp} ] }
DOWNLOAD_LOGS = load_json(DOWNLOAD_LOGS_FILE)


def find_share_token(username: str, filename: str):
    for token, info in SHARE_LINKS.items():
        if info["username"] == username and info["filename"] == filename:
            return token
    return None


def log_download(username: str, filename: str):
    logs = DOWNLOAD_LOGS.setdefault(username, [])
    logs.append({"filename": filename, "timestamp": datetime.utcnow().isoformat()})
    save_json(DOWNLOAD_LOGS_FILE, DOWNLOAD_LOGS)

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    server = ldap3.Server(LDAP_SERVER)
    user_dn = f"{LDAP_DOMAIN}\\{username}"
    try:
        conn = ldap3.Connection(server, user=user_dn, password=password, authentication=ldap3.NTLM)
        if not conn.bind():
            return {"success": False, "error": "Kullanıcı adı veya şifre hatalı"}
        return {"success": True, "username": username}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/upload")
def upload_file(file: UploadFile = File(...), username: str = Form(...)):
    user_dir = os.path.join(DATA_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    file_path = os.path.join(user_dir, file.filename)
    with open(file_path, "wb") as f:
        f.write(file.file.read())
    return {"success": True, "filename": file.filename}

@app.post("/list")
def list_files(username: str = Form(...)):
    user_dir = os.path.join(DATA_DIR, username)
    if not os.path.exists(user_dir):
        return {"files": []}
    files = os.listdir(user_dir)
    return {"files": files}

@app.post("/download")
def download_file(username: str = Form(...), filename: str = Form(...)):
    user_dir = os.path.join(DATA_DIR, username)
    file_path = os.path.join(user_dir, filename)
    if not os.path.exists(file_path):
        return {"success": False, "error": "Dosya bulunamadı"}
    log_download(username, filename)
    return FileResponse(file_path, filename=filename)

@app.post("/delete")
def delete_file(username: str = Form(...), filename: str = Form(...)):
    user_dir = os.path.join(DATA_DIR, username)
    file_path = os.path.join(user_dir, filename)
    if not os.path.exists(file_path):
        return {"success": False, "error": "Dosya bulunamadı"}
    os.remove(file_path)
    return {"success": True}

@app.post("/share")
def share_file(username: str = Form(...), filename: str = Form(...)):
    token = find_share_token(username, filename)
    if token is None:
        token = secrets.token_urlsafe(16)
        SHARE_LINKS[token] = {"username": username, "filename": filename}
        save_json(SHARE_LINKS_FILE, SHARE_LINKS)
    # Public link örneği: /public/{token}
    return {"success": True, "link": f"/public/{token}"}

@app.get("/public/{token}")
def public_download(token: str):
    item = SHARE_LINKS.get(token)
    if not item:
        return {"success": False, "error": "Link geçersiz"}
    username = item["username"]
    filename = item["filename"]
    user_dir = os.path.join(DATA_DIR, username)
    file_path = os.path.join(user_dir, filename)
    if not os.path.exists(file_path):
        return {"success": False, "error": "Dosya bulunamadı"}
    log_download(username, filename)
    return FileResponse(file_path, filename=filename)


@app.post("/stats")
def stats(username: str = Form(...)):
    user_dir = os.path.join(DATA_DIR, username)
    file_count = len(os.listdir(user_dir)) if os.path.exists(user_dir) else 0
    logs = DOWNLOAD_LOGS.get(username, [])
    return {
        "file_count": file_count,
        "download_count": len(logs),
        "download_logs": logs,
    }
