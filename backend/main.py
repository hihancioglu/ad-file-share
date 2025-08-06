import os
import secrets
from datetime import datetime

from flask import Flask, jsonify, render_template, request, send_file
from flask_cors import CORS
import ldap3
from dotenv import load_dotenv
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    ForeignKey,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv()

app = Flask(__name__)
CORS(app)

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

LDAP_SERVER = os.getenv("LDAP_SERVER")
LDAP_DOMAIN = os.getenv("LDAP_DOMAIN")
LDAP_USER = os.getenv("LDAP_USER")
LDAP_PASSWORD = os.getenv("LDAP_PASSWORD")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "")
LDAP_SEARCH_FILTER = os.getenv(
    "LDAP_SEARCH_FILTER", "(&(objectClass=user)(sAMAccountName=*{query}*))"
)

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


class Team(Base):
    __tablename__ = "teams"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    creator = Column(String, index=True)


class TeamMember(Base):
    __tablename__ = "team_members"

    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id"), index=True)
    username = Column(String, index=True)


class TeamFile(Base):
    __tablename__ = "team_files"

    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id"), index=True)
    username = Column(String, index=True)
    filename = Column(String)
    expires_at = Column(DateTime)


class UserShare(Base):
    __tablename__ = "user_shares"

    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String, index=True)
    recipient = Column(String, index=True)
    filename = Column(String)
    expires_at = Column(DateTime)


class UserFile(Base):
    __tablename__ = "user_files"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    filename = Column(String)
    expires_at = Column(DateTime)


Base.metadata.create_all(engine)


def add_missing_columns():
    inspector = inspect(engine)

    team_cols = [col["name"] for col in inspector.get_columns("team_files")]
    if "expires_at" not in team_cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE team_files ADD COLUMN expires_at TIMESTAMP"))


add_missing_columns()


def get_user_names(username: str):
    server = ldap3.Server(LDAP_SERVER)
    user_dn = f"{LDAP_DOMAIN}\\{LDAP_USER}"
    try:
        conn = ldap3.Connection(
            server,
            user=user_dn,
            password=LDAP_PASSWORD,
            authentication=ldap3.NTLM,
        )
        if not conn.bind():
            return "", ""
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        conn.search(LDAP_BASE_DN, search_filter, attributes=["givenName", "sn"])
        if conn.entries:
            entry = conn.entries[0]
            given = getattr(entry, "givenName", None)
            sn = getattr(entry, "sn", None)
            return (
                given.value if given else "",
                sn.value if sn else "",
            )
    except Exception:
        pass
    finally:
        try:
            conn.unbind()
        except Exception:
            pass
    return "", ""


def get_full_name(username: str):
    given, sn = get_user_names(username)
    full_name = f"{given} {sn}".strip()
    return full_name or username


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


def set_file_expiry(username: str, filename: str, expires_dt):
    db = SessionLocal()
    try:
        meta = (
            db.query(UserFile)
            .filter_by(username=username, filename=filename)
            .first()
        )
        if meta:
            meta.expires_at = expires_dt
        else:
            db.add(
                UserFile(
                    username=username, filename=filename, expires_at=expires_dt
                )
            )
        db.commit()
    finally:
        db.close()


@app.route("/", methods=["GET"])
def read_index():
    return render_template("login.html")


@app.route("/app", methods=["GET"])
def read_app():
    return render_template("app.html")


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
        conn.unbind()
        given, sn = get_user_names(username)
        return jsonify(success=True, username=username, givenName=given, sn=sn)
    except Exception as e:
        return jsonify(success=False, error=str(e))


@app.route("/users/list", methods=["GET"])
def list_users():
    query = request.args.get("q", "")
    server = ldap3.Server(LDAP_SERVER)
    user_dn = f"{LDAP_DOMAIN}\\{LDAP_USER}"
    try:
        conn = ldap3.Connection(
            server,
            user=user_dn,
            password=LDAP_PASSWORD,
            authentication=ldap3.NTLM,
        )
        if not conn.bind():
            return jsonify(success=False, error="LDAP bağlantısı başarısız")
        search_filter = LDAP_SEARCH_FILTER.format(query=query)
        conn.search(LDAP_BASE_DN, search_filter, attributes=["sAMAccountName"])
        users = [e.sAMAccountName.value for e in conn.entries]
        return jsonify(users=users)
    except Exception as e:
        return jsonify(success=False, error=str(e))
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def _list_users_in_dn(conn, dn: str):
    conn.search(
        dn,
        "(objectClass=user)",
        search_scope=ldap3.LEVEL,
        attributes=["sAMAccountName", "givenName", "sn"],
    )
    users = []
    for e in conn.entries:
        username = getattr(e, "sAMAccountName", None)
        given = getattr(e, "givenName", None)
        sn = getattr(e, "sn", None)
        users.append(
            {
                "username": username.value if username else "",
                "givenName": given.value if given else "",
                "sn": sn.value if sn else "",
            }
        )
    return users


def _build_ou_tree(conn, base_dn: str):
    conn.search(
        base_dn,
        "(objectClass=organizationalUnit)",
        search_scope=ldap3.LEVEL,
        attributes=["ou"],
    )
    entries = list(conn.entries)
    tree = []
    for entry in entries:
        name = entry.ou.value if "ou" in entry else ""
        if "pc" in name.lower():
            continue
        dn = entry.entry_dn
        node = {
            "name": name,
            "users": _list_users_in_dn(conn, dn),
            "children": _build_ou_tree(conn, dn),
        }
        tree.append(node)
    return tree


@app.route("/users/tree", methods=["GET"])
def users_tree():
    server = ldap3.Server(LDAP_SERVER)
    user_dn = f"{LDAP_DOMAIN}\\{LDAP_USER}"
    try:
        conn = ldap3.Connection(
            server,
            user=user_dn,
            password=LDAP_PASSWORD,
            authentication=ldap3.NTLM,
        )
        if not conn.bind():
            return jsonify(success=False, error="LDAP bağlantısı başarısız")
        tree = _build_ou_tree(conn, LDAP_BASE_DN)
        return jsonify(tree=tree)
    except Exception as e:
        return jsonify(success=False, error=str(e))
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@app.route("/upload", methods=["POST"])
def upload_file():
    """Upload endpoint supporting chunked uploads.

    Chunks are uploaded with fields:
    - username: owner of the file
    - filename: original file name
    - chunk_index: index of this chunk (0-based)
    - total_chunks: total number of chunks
    - file: binary data for this chunk

    Legacy single-request uploads are still supported for small files.
    """

    username = request.form.get("username")
    expires_at = request.form.get("expires_at")
    expires_dt = datetime.strptime(expires_at, "%Y-%m-%d") if expires_at else None
    user_dir = os.path.join(DATA_DIR, username)
    os.makedirs(user_dir, exist_ok=True)

    # Parameters for chunked upload
    filename = request.form.get("filename")
    chunk = request.files.get("file")
    chunk_index = request.form.get("chunk_index")
    total_chunks = request.form.get("total_chunks")

    if filename and chunk and chunk_index is not None and total_chunks:
        chunk_index = int(chunk_index)
        total_chunks = int(total_chunks)
        file_path = os.path.join(user_dir, filename)
        mode = "wb" if chunk_index == 0 else "ab"
        with open(file_path, mode) as f:
            f.write(chunk.read())
        # If this was the last chunk, respond with completion info
        if chunk_index + 1 == total_chunks:
            set_file_expiry(username, filename, expires_dt)
            return jsonify(success=True, filenames=[filename])
        return jsonify(success=True, chunk_index=chunk_index)

    # Fallback to legacy upload for already assembled files
    files = request.files.getlist("files")
    if not files:
        file = request.files.get("file")
        files = [file] if file else []

    uploaded = []
    for file in files:
        if file and file.filename:
            file_path = os.path.join(user_dir, file.filename)
            file.save(file_path)
            uploaded.append(file.filename)
            set_file_expiry(username, file.filename, expires_dt)

    return jsonify(success=True, filenames=uploaded)


@app.route("/list", methods=["POST"])
def list_files():
    username = request.form.get("username")
    user_dir = os.path.join(DATA_DIR, username)
    if not os.path.exists(user_dir):
        return jsonify(files=[])

    db = SessionLocal()
    try:
        metas = {
            m.filename: m.expires_at
            for m in db.query(UserFile).filter_by(username=username).all()
        }
    finally:
        db.close()

    files = []
    for filename in os.listdir(user_dir):
        file_path = os.path.join(user_dir, filename)
        stat = os.stat(file_path)
        exp = metas.get(filename)
        files.append(
            {
                "title": filename,
                "added": datetime.fromtimestamp(stat.st_mtime).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "extension": os.path.splitext(filename)[1].lstrip("."),
                "description": "",
                "size": stat.st_size,
                "expires_at": exp.strftime("%Y-%m-%d") if exp else "",
            }
        )

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
    db = SessionLocal()
    try:
        db.query(UserFile).filter_by(username=username, filename=filename).delete()
        db.commit()
    finally:
        db.close()
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


@app.route("/share/user", methods=["POST"])
def share_with_user():
    sender = request.form.get("username")
    recipient = request.form.get("recipient")
    filename = request.form.get("filename")
    expires_at = request.form.get("expires_at")
    expires_dt = datetime.strptime(expires_at, "%Y-%m-%d") if expires_at else None
    db = SessionLocal()
    try:
        db.add(
            UserShare(
                sender=sender,
                recipient=recipient,
                filename=filename,
                expires_at=expires_dt,
            )
        )
        db.commit()
        return jsonify(success=True)
    finally:
        db.close()


@app.route("/incoming", methods=["POST"])
def incoming_files():
    username = request.form.get("username")
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        shares = db.query(UserShare).filter_by(recipient=username).all()
        files = []
        for s in shares:
            if s.expires_at and s.expires_at < now:
                continue
            files.append(
                {
                    "filename": s.filename,
                    "sender": get_full_name(s.sender),
                    "expires_at": s.expires_at.strftime("%Y-%m-%d")
                    if s.expires_at
                    else "",
                }
            )
        return jsonify(files=files)
    finally:
        db.close()


@app.route("/outgoing", methods=["POST"])
def outgoing_files():
    username = request.form.get("username")
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        files = []
        shares = db.query(UserShare).filter_by(sender=username).all()
        for s in shares:
            if s.expires_at and s.expires_at < now:
                continue
            files.append(
                {
                    "filename": s.filename,
                    "target": get_full_name(s.recipient),
                    "target_id": s.recipient,
                    "type": "user",
                    "expires_at": s.expires_at.strftime("%Y-%m-%d")
                    if s.expires_at
                    else "",
                }
            )
        team_shares = db.query(TeamFile).filter_by(username=username).all()
        team_ids = [t.team_id for t in team_shares]
        teams = db.query(Team).filter(Team.id.in_(team_ids)).all() if team_ids else []
        team_names = {t.id: t.name for t in teams}
        for t in team_shares:
            if t.expires_at and t.expires_at < now:
                continue
            files.append(
                {
                    "filename": t.filename,
                    "target": team_names.get(t.team_id, ""),
                    "target_id": t.team_id,
                    "type": "team",
                    "expires_at": t.expires_at.strftime("%Y-%m-%d")
                    if t.expires_at
                    else "",
                }
            )
        return jsonify(files=files)
    finally:
        db.close()


@app.route("/outgoing/delete", methods=["POST"])
def delete_outgoing():
    username = request.form.get("username")
    filename = request.form.get("filename")
    target = request.form.get("target")
    target_type = request.form.get("type")
    db = SessionLocal()
    try:
        if target_type == "user":
            db.query(UserShare).filter_by(
                sender=username, recipient=target, filename=filename
            ).delete()
        elif target_type == "team":
            db.query(TeamFile).filter_by(
                team_id=int(target), username=username, filename=filename
            ).delete()
        db.commit()
        return jsonify(success=True)
    finally:
        db.close()


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


@app.route("/teams/create", methods=["POST"])
def create_team():
    username = request.form.get("username")
    team_name = request.form.get("team_name")
    members = request.form.get("members", "")
    member_list = [m.strip() for m in members.split(",") if m.strip()]
    db = SessionLocal()
    try:
        team = Team(name=team_name, creator=username)
        db.add(team)
        db.commit()
        db.refresh(team)
        db.add(TeamMember(team_id=team.id, username=username))
        for m in member_list:
            db.add(TeamMember(team_id=team.id, username=m))
        db.commit()
        return jsonify(success=True, team_id=team.id)
    finally:
        db.close()


@app.route("/teams/delete", methods=["POST"])
def delete_team():
    username = request.form.get("username")
    team_id = request.form.get("team_id")
    db = SessionLocal()
    try:
        team = db.query(Team).filter_by(id=team_id).first()
        if not team:
            return jsonify(success=False, error="Ekip bulunamadı")
        if team.creator != username:
            return jsonify(success=False, error="Yetkiniz yok")
        db.query(TeamMember).filter_by(team_id=team_id).delete()
        db.query(TeamFile).filter_by(team_id=team_id).delete()
        db.delete(team)
        db.commit()
        return jsonify(success=True)
    finally:
        db.close()


@app.route("/teams/leave", methods=["POST"])
def leave_team():
    username = request.form.get("username")
    team_id = request.form.get("team_id")
    db = SessionLocal()
    try:
        membership = (
            db.query(TeamMember)
            .filter_by(team_id=team_id, username=username)
            .first()
        )
        if membership:
            db.delete(membership)
            db.commit()
        return jsonify(success=True)
    finally:
        db.close()


@app.route("/teams/remove_member", methods=["POST"])
def remove_member():
    requester = request.form.get("username")
    team_id = request.form.get("team_id")
    member = request.form.get("member")
    db = SessionLocal()
    try:
        team = db.query(Team).filter_by(id=team_id).first()
        if not team:
            return jsonify(success=False, error="Ekip bulunamadı")
        if member == team.creator:
            return jsonify(success=False, error="Kurucu silinemez")
        if requester != member and team.creator != requester:
            return jsonify(success=False, error="Yetkiniz yok")
        membership = (
            db.query(TeamMember)
            .filter_by(team_id=team_id, username=member)
            .first()
        )
        if membership:
            db.delete(membership)
            db.commit()
        return jsonify(success=True)
    finally:
        db.close()


@app.route("/teams/list", methods=["POST"])
def list_teams():
    username = request.form.get("username")
    db = SessionLocal()
    try:
        memberships = db.query(TeamMember).filter_by(username=username).all()
        team_ids = [m.team_id for m in memberships]
        teams = db.query(Team).filter(Team.id.in_(team_ids)).all()
        data = []
        for t in teams:
            members = db.query(TeamMember).filter_by(team_id=t.id).all()
            data.append(
                {
                    "id": t.id,
                    "name": t.name,
                    "creator": t.creator,
                    "members": [
                        {"username": m.username, "name": get_full_name(m.username)}
                        for m in members
                    ],
                }
            )
        return jsonify(teams=data)
    finally:
        db.close()


@app.route("/teams/add_files", methods=["POST"])
def add_files_to_team():
    username = request.form.get("username")
    team_id = request.form.get("team_id")
    filenames = request.form.getlist("filenames")
    expires_at = request.form.get("expires_at")
    expires_dt = datetime.strptime(expires_at, "%Y-%m-%d") if expires_at else None
    db = SessionLocal()
    try:
        membership = (
            db.query(TeamMember)
            .filter_by(team_id=team_id, username=username)
            .first()
        )
        if not membership:
            return jsonify(success=False, error="Yetkiniz yok")
        for fname in filenames:
            db.add(
                TeamFile(
                    team_id=team_id,
                    username=username,
                    filename=fname,
                    expires_at=expires_dt,
                )
            )
        db.commit()
        return jsonify(success=True)
    finally:
        db.close()


@app.route("/teams/details", methods=["POST"])
def team_details():
    username = request.form.get("username")
    team_id = request.form.get("team_id")
    db = SessionLocal()
    try:
        team = db.query(Team).filter_by(id=team_id).first()
        if not team:
            return jsonify(success=False, error="Ekip bulunamadı")
        membership = (
            db.query(TeamMember)
            .filter_by(team_id=team_id, username=username)
            .first()
        )
        if not membership:
            return jsonify(success=False, error="Yetkiniz yok")
        members = db.query(TeamMember).filter_by(team_id=team_id).all()
        files = db.query(TeamFile).filter_by(team_id=team_id).all()
        return jsonify(
            success=True,
            team={
                "id": team.id,
                "name": team.name,
                "creator": team.creator,
                "members": [
                    {"username": m.username, "name": get_full_name(m.username)}
                    for m in members
                ],
                "files": [
                    {"filename": f.filename, "username": f.username} for f in files
                ],
            },
        )
    finally:
        db.close()


@app.route("/teams/add_member", methods=["POST"])
def add_member_to_team():
    username = request.form.get("username")
    team_id = request.form.get("team_id")
    new_member = request.form.get("new_member")
    db = SessionLocal()
    try:
        team = db.query(Team).filter_by(id=team_id).first()
        if not team:
            return jsonify(success=False, error="Ekip bulunamadı")
        if team.creator != username:
            return jsonify(success=False, error="Yetkiniz yok")
        exists = (
            db.query(TeamMember)
            .filter_by(team_id=team_id, username=new_member)
            .first()
        )
        if exists:
            return jsonify(success=False, error="Kullanıcı zaten ekipte")
        db.add(TeamMember(team_id=team_id, username=new_member))
        db.commit()
        return jsonify(success=True)
    finally:
        db.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

