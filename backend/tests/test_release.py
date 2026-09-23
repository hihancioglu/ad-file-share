import io
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["FLASK_SECRET_KEY"] = "test-secret"

import main  # noqa: E402
from release_service import (  # noqa: E402
    _NexusStreamBody,
    NexusSettings,
    NexusUploadError,
    asset_exists_on_nexus,
    promote_nexus_asset,
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
    with patch.object(main, "get_release_catalog", return_value=[item]), patch.object(
        main, "upload_release_metadata", return_value="https://repo/metadata"
    ):
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


def promote_catalog(visibility="public"):
    return [{
        "application": "Waterworks", "visibility": visibility,
        "latest_files": [{"filename": "setup.exe", "checksum_algorithm": "sha256", "checksum_value": "new"}],
        "versions": [{"version": "2.5.0", "files": [{
            "filename": "Waterworks-2.5.0.exe", "content_type": "application/x-msdownload",
            "file_size": 123, "checksum_algorithm": "sha256", "checksum_value": "old",
        }]}],
    }]


def promote_form(**overrides):
    values = {"application": "Waterworks", "visibility": "public", "version": "2.5.0", "filename": "Waterworks-2.5.0.exe", "nexus_password": "never-store-this"}
    values.update(overrides)
    return values


def test_promote_requires_session(client):
    assert client.post("/release/promote-latest", data=promote_form()).status_code == 401


def test_promote_requires_release_uploader(client):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=False):
        assert client.post("/release/promote-latest", data=promote_form()).status_code == 403


@pytest.mark.parametrize("field,value", [("visibility", "private"), ("application", "../x"), ("version", "../1"), ("filename", "../x.exe")])
def test_promote_validates_all_path_inputs(client, field, value):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(main, "promote_nexus_asset") as promote:
        response = client.post("/release/promote-latest", data=promote_form(**{field: value}))
    assert response.status_code == 400
    promote.assert_not_called()


def test_promote_resolves_target_and_credentials_server_side(client):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(main, "get_release_catalog", return_value=promote_catalog()), patch.object(main, "promote_nexus_asset", return_value="https://repo/latest/Waterworks/setup.exe") as promote, patch.object(main, "clear_catalog_cache") as clear, patch.object(main, "log_activity") as audit:
        response = client.post("/release/promote-latest", data=promote_form(latest_filename="attacker.exe", target="evil"))
    assert response.status_code == 200
    assert promote.call_args.kwargs["archive_repository"] == "apps-public"
    assert promote.call_args.kwargs["latest_repository"] == "apps-public-latest"
    assert promote.call_args.kwargs["latest_path"] == "Waterworks/setup.exe"
    assert promote.call_args.kwargs["username"] == "publisher"
    assert promote.call_args.kwargs["password"] == "never-store-this"
    clear.assert_called_once()
    assert audit.call_args.kwargs["category"] == "release_promote_latest"
    assert "never-store-this" not in str(audit.call_args)


def test_promote_current_checksum_does_no_network_work(client):
    login(client)
    catalog = promote_catalog()
    catalog[0]["versions"][0]["files"][0]["checksum_value"] = "new"
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(main, "get_release_catalog", return_value=catalog), patch.object(main, "promote_nexus_asset") as promote:
        response = client.post("/release/promote-latest", data=promote_form())
    assert response.status_code == 409
    assert response.get_json()["error"] == "Bu sürüm zaten güncel sürüm."
    promote.assert_not_called()


@pytest.mark.parametrize("change,message", [
    ({"application": "Missing"}, "Uygulama bulunamadı."),
    ({"version": "9.9"}, "Arşiv sürümü bulunamadı."),
    ({"filename": "missing.exe"}, "Arşiv dosyası bulunamadı."),
])
def test_promote_requires_exact_catalog_asset(client, change, message):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(main, "get_release_catalog", return_value=promote_catalog()), patch.object(main, "promote_nexus_asset") as promote:
        response = client.post("/release/promote-latest", data=promote_form(**change))
    assert response.status_code == 404
    assert response.get_json()["error"] == message
    promote.assert_not_called()


def test_sized_nexus_stream_body_prepares_and_streams_without_using_raw():
    source = Mock()
    source.raw = type("HTTPResponse", (), {})()
    source.iter_content.return_value = iter([b"a" * 12, b"", b"b" * 25])
    body = _NexusStreamBody(source, 37)

    prepared = requests.Request("PUT", "https://repo.example/file", data=body).prepare()

    assert prepared.headers["Content-Length"] == "37"
    assert "Transfer-Encoding" not in prepared.headers
    assert prepared.body is body
    assert list(body) == [b"a" * 12, b"b" * 25]
    source.iter_content.assert_called_once_with(chunk_size=1024 * 1024)


@pytest.mark.parametrize(
    ("file_size", "expected_body", "expected_length"),
    [(37, "sized", "37"), (0, b"", "0"), (None, "unsized", None)],
)
def test_promote_helper_streams_and_always_closes(
    nexus_settings, file_size, expected_body, expected_length
):
    source = type("Source", (), {})()
    source.status_code = 200
    source.raw = type("HTTPResponse", (), {})()
    source.iter_content = Mock(return_value=iter([b"one", b"", b"two"]))
    source.close = Mock()
    target = type("Target", (), {"status_code": 201})()
    with patch("release_service.requests.get", return_value=source) as get, patch("release_service.requests.put", return_value=target) as put:
        url = promote_nexus_asset(settings=nexus_settings, archive_repository="archive", archive_path="App/1/a.exe", latest_repository="latest", latest_path="App/setup.exe", username="publisher", password="secret", file_size=file_size)
    assert url == "https://repo.example/repository/latest/App/setup.exe"
    assert get.call_args.kwargs["stream"] is True
    assert get.call_args.kwargs["headers"] == {"Accept-Encoding": "identity"}
    assert get.call_args.kwargs["auth"] == ("", "")
    assert put.call_args.kwargs["auth"] == ("publisher", "secret")
    assert "Content-Length" not in put.call_args.kwargs["headers"]
    body = put.call_args.kwargs["data"]
    assert body is not source.raw
    if expected_body == "sized":
        prepared = requests.Request("PUT", "https://repo.example/file", data=body).prepare()
        assert prepared.headers["Content-Length"] == expected_length
        assert list(body) == [b"one", b"two"]
    elif expected_body == "unsized":
        prepared = requests.Request("PUT", "https://repo.example/file", data=body).prepare()
        assert prepared.headers["Transfer-Encoding"] == "chunked"
        assert "Content-Length" not in prepared.headers
        assert list(body) == [b"one", b"two"]
    else:
        assert body == expected_body
    source.close.assert_called_once()


def test_promote_helper_closes_source_when_put_fails(nexus_settings):
    source = Mock(status_code=200)
    source.iter_content.return_value = iter([b"content"])
    with patch("release_service.requests.get", return_value=source), patch(
        "release_service.requests.put",
        side_effect=requests.exceptions.ChunkedEncodingError("broken"),
    ):
        with pytest.raises(NexusUploadError) as error:
            promote_nexus_asset(settings=nexus_settings, archive_repository="archive", archive_path="App/1/a.exe", latest_repository="latest", latest_path="App/setup.exe", username="publisher", password="secret", file_size=None)
    assert error.value.status_code == 502
    assert "secret" not in str(error.value)
    source.close.assert_called_once()


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


def test_publish_writes_identity_metadata_with_request_credentials(client):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "asset_exists_on_nexus", return_value=False
    ), patch.object(main, "upload_to_nexus", side_effect=["archive", "latest"]), patch.object(
        main, "upload_release_metadata", return_value="metadata"
    ) as metadata, patch.object(main, "log_activity"):
        response = client.post("/release/publish", data=publish_form())
    assert response.status_code == 200
    assert metadata.call_args.kwargs == {
        "settings": metadata.call_args.kwargs["settings"],
        "repository": "apps-public-latest",
        "application": "Waterworks",
        "version": "2.6.1",
        "source_filename": "WaterworksSetup.exe",
        "latest_filename": "setup.exe",
        "username": "publisher",
        "password": "never-store-this",
    }


def test_publish_metadata_failure_reports_binary_partial_success(client):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "asset_exists_on_nexus", return_value=False
    ), patch.object(main, "upload_to_nexus", side_effect=["archive", "latest"]), patch.object(
        main, "upload_release_metadata", side_effect=NexusUploadError("secret raw response", 502)
    ), patch.object(main, "log_activity"):
        response = client.post("/release/publish", data=publish_form())
    data = response.get_json()
    assert response.status_code == 502
    assert data["partial"] is True and data["latest_uploaded"] is True
    assert data["error"] == "Latest dosya güncellendi ancak sürüm metadata bilgisi güncellenemedi."
    assert "never-store-this" not in response.get_data(as_text=True)
    assert "secret raw response" not in response.get_data(as_text=True)


def test_promote_writes_metadata_after_binary_with_user_credentials(client):
    login(client)
    order = []
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "get_release_catalog", return_value=promote_catalog()
    ), patch.object(main, "promote_nexus_asset", side_effect=lambda **_: order.append("binary") or "latest"), patch.object(
        main, "upload_release_metadata", side_effect=lambda **_: order.append("metadata") or "metadata"
    ) as metadata, patch.object(main, "log_activity"):
        response = client.post("/release/promote-latest", data=promote_form())
    assert response.status_code == 200
    assert order == ["binary", "metadata"]
    assert metadata.call_args.kwargs["repository"] == "apps-public-latest"
    assert metadata.call_args.kwargs["username"] == "publisher"
    assert metadata.call_args.kwargs["password"] == "never-store-this"


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
    assert clear.call_count == 3

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
