import os
import secrets
from datetime import datetime

from flask import Flask, jsonify, render_template, request, send_file
from flask_cors import CORS
import ldap3
from dotenv import load_dotenv
from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv()

app = Flask(__name__)
CORS(app)

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
        link = db.query(ShareLink).filter_by(username=username, filename=filename).first()
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


@app.route("/", methods=["GET"])
def read_index():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    server = ldap3.Server(LDAP_SERVER)
    user_dn = f"{LDAP_DOMAIN}\\{username}"
    try:
        conn = ldap3.Connection(
            server, user=user_dn, password=password, authentication=ldap3.NTLM
        )
        if not conn.bind():
            return jsonify(success=False, error="Kullanıcı adı veya şifre hatalı")
        return jsonify(success=True, username=username)
    except Exception as e:
        return jsonify(success=False, error=str(e))


@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files["file"]
    username = request.form.get("username")
    user_dir = os.path.join(DATA_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    file_path = os.path.join(user_dir, file.filename)
    file.save(file_path)
    return jsonify(success=True, filename=file.filename)


@app.route("/list", methods=["POST"])
def list_files():
    username = request.form.get("username")
    user_dir = os.path.join(DATA_DIR, username)
    if not os.path.exists(user_dir):
        return jsonify(files=[])
    files = os.listdir(user_dir)
    return jsonify(files=files)


@app.route("/download", methods=["POST"])
def download_file():
    username = request.form.get("username")
    filename = request.form.get("filename")
    user_dir = os.path.join(DATA_DIR, username)
    file_path = os.path.join(user_dir, filename)
    if not os.path.exists(file_path):
        return jsonify(success=False, error="Dosya bulunamadı")
    log_download(username, filename)
    return send_file(file_path, as_attachment=True, download_name=filename)


@app.route("/delete", methods=["POST"])
def delete_file():
    username = request.form.get("username")
    filename = request.form.get("filename")
    user_dir = os.path.join(DATA_DIR, username)
    file_path = os.path.join(user_dir, filename)
    if not os.path.exists(file_path):
        return jsonify(success=False, error="Dosya bulunamadı")
    os.remove(file_path)
    return jsonify(success=True)


@app.route("/share", methods=["POST"])
def share_file():
    username = request.form.get("username")
    filename = request.form.get("filename")
    token = find_share_token(username, filename)
    if token is None:
        token = secrets.token_urlsafe(16)
        create_share_link(token, username, filename)
    return jsonify(success=True, link=f"/public/{token}")


@app.route("/public/<token>", methods=["GET"])
def public_download(token):
    db = SessionLocal()
    try:
        link = db.query(ShareLink).filter_by(token=token).first()
    finally:
        db.close()
    if not link:
        return jsonify(success=False, error="Link geçersiz")
    username = link.username
    filename = link.filename
    user_dir = os.path.join(DATA_DIR, username)
    file_path = os.path.join(user_dir, filename)
    if not os.path.exists(file_path):
        return jsonify(success=False, error="Dosya bulunamadı")
    log_download(username, filename)
    return send_file(file_path, as_attachment=True, download_name=filename)


@app.route("/stats", methods=["POST"])
def stats():
    username = request.form.get("username")
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
    return jsonify(
        file_count=file_count,
        download_count=len(logs_data),
        download_logs=logs_data,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

