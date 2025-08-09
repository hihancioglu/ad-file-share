import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://admin:secret@postgres:5432/filesharedb"
)

engine = create_engine(DATABASE_URL)
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

    member_cols = [col["name"] for col in inspector.get_columns("team_members")]
    if "accepted" not in member_cols:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "ALTER TABLE team_members ADD COLUMN accepted BOOLEAN DEFAULT FALSE"
                )
            )
