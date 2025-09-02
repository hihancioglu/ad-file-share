from datetime import datetime
from typing import Union

from sqlalchemy.orm import Session

from models import UserFile, DocumentVersion, UserFileStatusHistory

STATUS_DRAFT = "draft"
STATUS_REVIEW = "review"
STATUS_APPROVED = "approved"
STATUS_PUBLISHED = "published"

VALID_STATUSES = {
    STATUS_DRAFT,
    STATUS_REVIEW,
    STATUS_APPROVED,
    STATUS_PUBLISHED,
}


def change_userfile_status(db: Session, user_file_id: int, new_status: str) -> UserFile:
    """Change the status of a UserFile and record the transition history."""
    if new_status not in VALID_STATUSES:
        raise ValueError("Invalid status")
    user_file = db.query(UserFile).filter_by(id=user_file_id).first()
    if not user_file:
        raise ValueError("UserFile not found")

    user_file.status = new_status
    history = UserFileStatusHistory(
        user_file_id=user_file_id, status=new_status, changed_at=datetime.utcnow()
    )
    db.add(history)
    db.commit()
    db.refresh(user_file)
    return user_file


def set_active_version(db: Session, version: Union[DocumentVersion, int]) -> DocumentVersion:
    """Mark given DocumentVersion as active and update its parent UserFile."""
    if isinstance(version, int):
        version = db.query(DocumentVersion).filter_by(id=version).first()
    if not version:
        raise ValueError("DocumentVersion not found")

    db.query(DocumentVersion).filter(
        DocumentVersion.document_id == version.document_id
    ).update({"is_active": False})
    version.is_active = True

    user_file = db.query(UserFile).filter_by(id=version.document_id).first()
    if user_file:
        user_file.active_version_id = version.id

    db.commit()
    db.refresh(version)
    return version
