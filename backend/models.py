from datetime import datetime, timedelta
from sqlalchemy import Column, DateTime, Integer, String, ForeignKey, Boolean

from database import Base, engine


class ShareLink(Base):
    __tablename__ = "share_links"

    token = Column(String, primary_key=True, index=True)
    approve_token = Column(String, unique=True, index=True, nullable=True)
    reject_token = Column(String, unique=True, index=True, nullable=True)
    username = Column(String, index=True)
    filename = Column(String)
    expires_at = Column(DateTime)
    approved = Column(Boolean, default=False)
    rejected = Column(Boolean, default=False)


class DownloadLog(Base):
    __tablename__ = "download_logs"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    filename = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String)
    country = Column(String)


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
    accepted = Column(Boolean, default=False)


class TeamFile(Base):
    __tablename__ = "team_files"

    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id"), index=True)
    username = Column(String, index=True)
    filename = Column(String)
    expires_at = Column(DateTime)


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    message = Column(String)
    created_at = Column(
        DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3)
    )
    read = Column(Boolean, default=False)
    team_id = Column(Integer, ForeignKey("teams.id"), nullable=True)


class Activity(Base):
    __tablename__ = "activities"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    message = Column(String)
    category = Column(String, index=True, default="general")
    created_at = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))


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
    description = Column(String, default="")
    deleted_at = Column(DateTime)


Base.metadata.create_all(engine)
