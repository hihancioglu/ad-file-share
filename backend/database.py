import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine.url import make_url
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://admin:secret@postgres:5432/filesharedb"
)

DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "20"))
DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "30"))
DB_POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))
DB_POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "1800"))

engine_kwargs = {}
db_url = make_url(DATABASE_URL)
if db_url.get_backend_name() != "sqlite":
    engine_kwargs = {
        "pool_size": DB_POOL_SIZE,
        "max_overflow": DB_MAX_OVERFLOW,
        "pool_timeout": DB_POOL_TIMEOUT,
        "pool_pre_ping": True,
        "pool_recycle": DB_POOL_RECYCLE,
    }

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


def add_missing_columns():
    inspector = inspect(engine)

    team_cols = [col["name"] for col in inspector.get_columns("team_files")]
    if "expires_at" not in team_cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE team_files ADD COLUMN expires_at TIMESTAMP"))

    share_cols = [col["name"] for col in inspector.get_columns("share_links")]
    if "expires_at" not in share_cols:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE share_links ADD COLUMN expires_at TIMESTAMP")
            )
    if "approved" not in share_cols:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "ALTER TABLE share_links ADD COLUMN approved BOOLEAN DEFAULT FALSE"
                )
            )
    if "rejected" not in share_cols:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "ALTER TABLE share_links ADD COLUMN rejected BOOLEAN DEFAULT FALSE"
                )
            )
    if "approve_token" not in share_cols:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE share_links ADD COLUMN approve_token VARCHAR")
            )
    if "reject_token" not in share_cols:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE share_links ADD COLUMN reject_token VARCHAR")
            )
    if "purpose" not in share_cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE share_links ADD COLUMN purpose VARCHAR"))
    if "max_downloads" not in share_cols:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE share_links ADD COLUMN max_downloads INTEGER")
            )
    if "download_count" not in share_cols:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "ALTER TABLE share_links ADD COLUMN download_count INTEGER DEFAULT 0"
                )
            )

    member_cols = [col["name"] for col in inspector.get_columns("team_members")]
    if "accepted" not in member_cols:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "ALTER TABLE team_members ADD COLUMN accepted BOOLEAN DEFAULT FALSE"
                )
            )

    download_cols = [col["name"] for col in inspector.get_columns("download_logs")]
    if "ip_address" not in download_cols:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE download_logs ADD COLUMN ip_address VARCHAR")
            )
    if "country" not in download_cols:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE download_logs ADD COLUMN country VARCHAR")
            )
    if "token" not in download_cols:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE download_logs ADD COLUMN token VARCHAR")
            )

    userfile_cols = [col["name"] for col in inspector.get_columns("user_files")]
    if "description" not in userfile_cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE user_files ADD COLUMN description VARCHAR"))
    if "deleted_at" not in userfile_cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE user_files ADD COLUMN deleted_at TIMESTAMP"))
    if "original_filename" not in userfile_cols:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE user_files ADD COLUMN original_filename VARCHAR")
            )

    usershare_cols = [col["name"] for col in inspector.get_columns("user_shares")]
    if "sender_name" not in usershare_cols:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE user_shares ADD COLUMN sender_name VARCHAR")
            )
    if "recipient_name" not in usershare_cols:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE user_shares ADD COLUMN recipient_name VARCHAR")
            )
    if "deleted_at" not in usershare_cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE user_shares ADD COLUMN deleted_at TIMESTAMP"))

    activity_cols = [col["name"] for col in inspector.get_columns("activities")]
    if "category" not in activity_cols:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "ALTER TABLE activities ADD COLUMN category VARCHAR DEFAULT 'general'"
                )
            )
