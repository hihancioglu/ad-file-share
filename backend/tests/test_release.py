import io
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["FLASK_SECRET_KEY"] = "test-secret"

import main  # noqa: E402
from release_service import NexusUploadError  # noqa: E402


@pytest.fixture
def client():
    main.app.config.update(TESTING=True)
    return main.app.test_client()


def login(client, username="publisher"):
    with client.session_transaction() as flask_session:
        flask_session["username"] = username


def publish_form(**overrides):
    values = {
        "application": "Waterworks",
        "version": "2.6.1",
        "visibility": "public",
        "latest_filename": "setup.exe",
        "nexus_password": "never-store-this",
        "file": (io.BytesIO(b"setup-content"), "WaterworksSetup.exe"),
    }
    values.update(overrides)
    return values


def latest_form(**overrides):
    values = publish_form(**overrides)
    values.pop("version")
    return values


def test_publish_requires_session(client):
    response = client.post("/release/publish", data=publish_form())
    assert response.status_code == 401


def test_publish_requires_release_uploader(client):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=False):
        response = client.post("/release/publish", data=publish_form())
    assert response.status_code == 403


@pytest.mark.parametrize(
    "overrides",
    [
        {"visibility": "private"},
        {"application": "../Waterworks"},
        {"version": "../../2.6.1"},
        {"latest_filename": "../setup.exe"},
    ],
)
def test_publish_rejects_invalid_paths_and_visibility(client, overrides):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "upload_to_nexus"
    ) as upload:
        response = client.post("/release/publish", data=publish_form(**overrides))
    assert response.status_code == 400
    upload.assert_not_called()


def test_publish_uploads_archive_then_latest(client):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main,
        "upload_to_nexus",
        side_effect=["https://repo/archive", "https://repo/latest"],
    ) as upload, patch.object(main, "log_activity") as audit:
        response = client.post("/release/publish", data=publish_form())

    assert response.status_code == 200
    assert response.get_json() == {
        "success": True,
        "partial": False,
        "application": "Waterworks",
        "version": "2.6.1",
        "visibility": "public",
        "archive_url": "https://repo/archive",
        "latest_url": "https://repo/latest",
    }
    assert [call.kwargs["repository"] for call in upload.call_args_list] == [
        "apps-public",
        "apps-public-latest",
    ]
    assert all(call.kwargs["username"] == "publisher" for call in upload.call_args_list)
    audit.assert_called_once()


def test_archive_failure_does_not_upload_latest(client):
    login(client)
    error = NexusUploadError("Nexus sunucusunda hata oluştu.", 502)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "upload_to_nexus", side_effect=error
    ) as upload:
        response = client.post("/release/publish", data=publish_form())
    assert response.status_code == 502
    assert upload.call_count == 1


def test_latest_failure_returns_partial_without_deleting_archive(client):
    login(client)
    latest_error = NexusUploadError(
        "Nexus üzerinde yayınlama yetkiniz bulunmuyor.", 403
    )
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "upload_to_nexus", side_effect=["https://repo/archive", latest_error]
    ), patch.object(main, "log_activity") as audit:
        response = client.post("/release/publish", data=publish_form())
    assert response.status_code == 403
    assert response.get_json()["partial"] is True
    assert response.get_json()["archive_uploaded"] is True
    assert audit.call_args.kwargs["category"] == "release_publish_partial"


def test_publish_latest_only_uses_latest_repository(client):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "upload_to_nexus", return_value="https://repo/latest"
    ) as upload, patch.object(main, "log_activity"):
        response = client.post("/release/publish-latest", data=latest_form())
    assert response.status_code == 200
    assert upload.call_count == 1
    assert upload.call_args.kwargs["repository"] == "apps-public-latest"


@pytest.mark.parametrize(
    ("error", "status", "message"),
    [
        (
            NexusUploadError("Nexus kullanıcı adı veya parola hatalı.", 401),
            401,
            "Nexus kullanıcı adı veya parola hatalı.",
        ),
        (
            NexusUploadError("Nexus üzerinde yayınlama yetkiniz bulunmuyor.", 403),
            403,
            "Nexus üzerinde yayınlama yetkiniz bulunmuyor.",
        ),
        (
            NexusUploadError("Bu uygulama sürümü daha önce yayınlanmış.", 409),
            409,
            "Bu uygulama sürümü daha önce yayınlanmış.",
        ),
    ],
)
def test_nexus_errors_are_returned_safely(client, error, status, message):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "upload_to_nexus", side_effect=error
    ):
        response = client.post("/release/publish", data=publish_form())
    assert response.status_code == status
    assert response.get_json()["error"] == message
    assert "never-store-this" not in response.get_data(as_text=True)
