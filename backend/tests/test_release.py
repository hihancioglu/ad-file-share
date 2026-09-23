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
from release_service import (  # noqa: E402
    NexusSettings,
    NexusUploadError,
    asset_exists_on_nexus,
    resolve_latest_filename,
    upload_to_nexus,
)


@pytest.fixture
def client():
    main.app.config.update(TESTING=True)
    item = {
        "application": "Waterworks",
        "visibility": "public",
        "latest_files": [{"filename": "setup.exe"}],
        "versions": [],
    }
    with patch.object(main, "get_release_catalog", return_value=[item]):
        yield main.app.test_client()


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
        main, "asset_exists_on_nexus", return_value=False
    ) as exists, patch.object(
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
        "latest_filename": "setup.exe",
    }
    assert [call.kwargs["repository"] for call in upload.call_args_list] == [
        "apps-public",
        "apps-public-latest",
    ]
    assert all(call.kwargs["username"] == "publisher" for call in upload.call_args_list)
    exists.assert_called_once()
    assert exists.call_args.kwargs["repository"] == "apps-public"
    audit.assert_called_once()


def test_archive_failure_does_not_upload_latest(client):
    login(client)
    error = NexusUploadError("Nexus sunucusunda hata oluştu.", 502)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "asset_exists_on_nexus", return_value=False
    ), patch.object(
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
        main, "asset_exists_on_nexus", return_value=False
    ), patch.object(
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
        main, "asset_exists_on_nexus", return_value=False
    ), patch.object(
        main, "upload_to_nexus", side_effect=error
    ):
        response = client.post("/release/publish", data=publish_form())
    assert response.status_code == status
    assert response.get_json()["error"] == message
    assert "never-store-this" not in response.get_data(as_text=True)


def test_existing_archive_returns_conflict_without_put(client):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "asset_exists_on_nexus", return_value=True
    ) as exists, patch.object(main, "upload_to_nexus") as upload:
        response = client.post("/release/publish", data=publish_form())

    assert response.status_code == 409
    assert response.get_json() == {
        "success": False,
        "partial": False,
        "archive_uploaded": False,
        "latest_uploaded": False,
        "error": "Bu uygulama sürümü daha önce yayınlanmış.",
    }
    exists.assert_called_once()
    upload.assert_not_called()


def test_latest_publish_does_not_check_asset_existence(client):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "asset_exists_on_nexus"
    ) as exists, patch.object(
        main, "upload_to_nexus", return_value="https://repo/latest"
    ), patch.object(main, "log_activity"):
        response = client.post("/release/publish-latest", data=latest_form())
    assert response.status_code == 200
    exists.assert_not_called()


def test_publish_ignores_client_latest_filename(client):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "asset_exists_on_nexus", return_value=False
    ), patch.object(main, "upload_to_nexus", side_effect=["archive", "latest"]) as upload, patch.object(
        main, "log_activity"
    ):
        response = client.post(
            "/release/publish",
            data=publish_form(latest_filename="attacker.exe"),
        )
    assert response.status_code == 200
    assert upload.call_args_list[1].kwargs["asset_path"] == "Waterworks/setup.exe"
    assert response.get_json()["latest_filename"] == "setup.exe"


def test_resolve_latest_filename_rules():
    assert resolve_latest_filename("App", "new.zip", {"latest_files": [{"filename": "stable.exe"}]}) == "stable.exe"
    assert resolve_latest_filename("Waterworks", "WaterworksSetup-2.7.0.exe", {"latest_files": []}) == "Waterworks.exe"
    assert resolve_latest_filename("App", "new.exe", {"latest_files": [{"filename": "setup.exe"}, {"filename": "portable.zip"}]}) == "setup.exe"
    with pytest.raises(ValueError, match="otomatik belirlenemedi"):
        resolve_latest_filename("App", "README", {"latest_files": []})
    with pytest.raises(ValueError, match="Bu uygulama için"):
        resolve_latest_filename("App", "new.exe", {"latest_files": [{"filename": "a.exe"}, {"filename": "b.exe"}]})


def test_catalog_cache_cleared_after_success_and_partial(client):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "asset_exists_on_nexus", return_value=False
    ), patch.object(main, "clear_catalog_cache") as clear, patch.object(
        main, "upload_to_nexus", side_effect=["archive", "latest"]
    ), patch.object(main, "log_activity"):
        assert client.post("/release/publish", data=publish_form()).status_code == 200
    assert clear.call_count == 2

    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "asset_exists_on_nexus", return_value=False
    ), patch.object(main, "clear_catalog_cache") as clear, patch.object(
        main, "upload_to_nexus", side_effect=["archive", NexusUploadError("failed")]
    ), patch.object(main, "log_activity"):
        response = client.post("/release/publish", data=publish_form())
    assert response.get_json()["partial"] is True
    clear.assert_called_once()


def test_catalog_cache_cleared_after_latest_retry(client):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "upload_to_nexus", return_value="latest"
    ), patch.object(main, "clear_catalog_cache") as clear, patch.object(main, "log_activity"):
        assert client.post("/release/publish-latest", data=latest_form()).status_code == 200
    clear.assert_called_once()


@pytest.fixture
def nexus_settings():
    return NexusSettings(
        upload_base_url="https://nexus.example",
        public_base_url="https://repo.example",
        repositories={"public": ("archive", "latest")},
        verify="/ca.pem",
        timeout=(3.0, 7.0),
    )


@pytest.mark.parametrize(("status", "expected"), [(200, True), (204, True), (404, False)])
def test_asset_exists_on_nexus_statuses(nexus_settings, status, expected):
    with patch("release_service.requests.head") as head:
        head.return_value.status_code = status
        assert asset_exists_on_nexus(
            settings=nexus_settings,
            repository="archive",
            asset_path="App/1.0/setup.exe",
            username="publisher",
            password="secret",
        ) is expected
    head.assert_called_once_with(
        "https://nexus.example/repository/archive/App/1.0/setup.exe",
        auth=("publisher", "secret"),
        verify="/ca.pem",
        timeout=(3.0, 7.0),
    )


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (401, "Nexus kullanıcı adı veya parola hatalı."),
        (403, "Nexus üzerinde yayınlama yetkiniz bulunmuyor."),
    ],
)
def test_asset_exists_translates_auth_errors(nexus_settings, status, message):
    with patch("release_service.requests.head") as head:
        head.return_value.status_code = status
        with pytest.raises(NexusUploadError, match=message) as caught:
            asset_exists_on_nexus(
                settings=nexus_settings,
                repository="archive",
                asset_path="App/1.0/setup.exe",
                username="publisher",
                password="secret",
            )
    assert caught.value.status_code == status


def test_asset_exists_translates_timeout_safely(nexus_settings):
    with patch("release_service.requests.head", side_effect=main.requests.Timeout):
        with pytest.raises(NexusUploadError) as caught:
            asset_exists_on_nexus(
                settings=nexus_settings,
                repository="archive",
                asset_path="App/1.0/setup.exe",
                username="publisher",
                password="secret",
            )
    assert caught.value.status_code == 504
    assert caught.value.message == "Nexus bağlantısı zaman aşımına uğradı."


@pytest.mark.parametrize(
    "body",
    [
        "Repository does not allow updating assets",
        "Asset already exists",
        "Cannot be modified",
    ],
)
def test_archive_put_recognizes_additional_duplicate_messages(nexus_settings, body):
    with patch("release_service.requests.put") as put:
        put.return_value.status_code = 400
        put.return_value.text = body
        with pytest.raises(NexusUploadError) as caught:
            upload_to_nexus(
                settings=nexus_settings,
                repository="archive",
                asset_path="App/1.0/setup.exe",
                stream=io.BytesIO(b"content"),
                username="publisher",
                password="secret",
            )
    assert caught.value.status_code == 409
    assert caught.value.message == "Bu uygulama sürümü daha önce yayınlanmış."
