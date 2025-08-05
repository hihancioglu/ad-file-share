import os
import secrets
from datetime import datetime
from fastapi import FastAPI, File, UploadFile, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
import ldap3
from dotenv import load_dotenv
from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
def read_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

LDAP_SERVER = os.getenv("LDAP_SERVER")
LDAP_DOMAIN = os.getenv("LDAP_DOMAIN")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://admin:secret@postgres:5432/filesharedb",
)
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class ShareLink(Base):
    __tablename__ = "share_links"

    token = Column(String, primary_key=True, index=True)
    username = Column(String, index=True)
    filename = Column(String)


class DownloadLog(Base):
    __tablename__ = "download_logs"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    filename = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(engine)


def find_share_token(username: str, filename: str):
    db = SessionLocal()
    try:
        link = (
            db.query(ShareLink)
            .filter_by(username=username, filename=filename)
            .first()
        )
        return link.token if link else None
    finally:
        db.close()


def create_share_link(token: str, username: str, filename: str):
    db = SessionLocal()
    try:
        db.add(ShareLink(token=token, username=username, filename=filename))
        db.commit()
    finally:
        db.close()


def log_download(username: str, filename: str):
    db = SessionLocal()
    try:
        db.add(DownloadLog(username=username, filename=filename))
        db.commit()
    finally:
        db.close()

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
        create_share_link(token, username, filename)
    # Public link örneği: /public/{token}
    return {"success": True, "link": f"/public/{token}"}

@app.get("/public/{token}")
def public_download(token: str):
    db = SessionLocal()
    try:
        link = db.query(ShareLink).filter_by(token=token).first()
    finally:
        db.close()
    if not link:
        return {"success": False, "error": "Link geçersiz"}
    username = link.username
    filename = link.filename
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
    db = SessionLocal()
    try:
        logs = db.query(DownloadLog).filter_by(username=username).all()
        logs_data = [
            {"filename": l.filename, "timestamp": l.timestamp.isoformat()}
            for l in logs
        ]
    finally:
        db.close()
    return {
        "file_count": file_count,
        "download_count": len(logs_data),
        "download_logs": logs_data,
    }
