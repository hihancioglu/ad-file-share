import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["FLASK_SECRET_KEY"] = "test-secret"

import main  # noqa: E402
from release_service import (  # noqa: E402
    NexusCatalogError,
    NexusSettings,
    build_release_catalog,
    clear_catalog_cache,
    search_nexus_assets,
)


def settings(**values):
    defaults = dict(
        upload_base_url="https://nexus.example",
        public_base_url="https://public.example",
        repositories={
            "public": ("pub", "pub-latest"),
            "internal": ("int", "int-latest"),
        },
        verify="/ca.pem",
        timeout=(2, 5),
        catalog_username="catalog",
        catalog_password="top-secret",
        catalog_cache_ttl=30,
    )
    defaults.update(values)
    return NexusSettings(**defaults)


def response(items=(), token=None, status=200, text="raw secret body"):
    result = Mock(status_code=status, text=text)
    result.json.return_value = {"items": list(items), "continuationToken": token}
    return result


def asset(path, checksum=None, repository="pub", **extra):
    value = {
        "path": path,
        "repository": repository,
        "downloadUrl": "http://insecure.example/must-not-leak",
        "checksum": checksum or {},
        "contentType": "application/test",
        "fileSize": 37,
        "lastModified": "2026-09-23T10:35:02.163+00:00",
    }
    value.update(extra)
    return value


def test_search_normalizes_paginates_and_selects_checksum():
    first = asset("/App/1.0/a.bin", {"sha512": "512", "sha256": "256"})
    second = asset("/App/2.0/b.bin", {"md5": "md5", "sha1": "sha1"})
    with patch("release_service.requests.get", side_effect=[response([first], "next"), response([second])]) as get:
        found = search_nexus_assets(settings(), "pub")
    assert [item["path"] for item in found] == ["App/1.0/a.bin", "App/2.0/b.bin"]
    assert [(item["checksum_algorithm"], item["checksum_value"]) for item in found] == [("sha256", "256"), ("sha1", "sha1")]
    assert get.call_args_list[0].kwargs["params"] == {"repository": "pub"}
    assert get.call_args_list[1].kwargs["params"] == {"repository": "pub", "continuationToken": "next"}
    assert get.call_args.kwargs["verify"] == "/ca.pem"
    assert get.call_args.kwargs["timeout"] == (2, 5)
    assert all("downloadUrl" not in item for item in found)


@pytest.mark.parametrize(
    ("failure", "message", "status"),
    [
        (response(status=401), "Nexus katalog hesabı doğrulanamadı.", 401),
        (response(status=403), "Nexus katalog hesabının repository erişim yetkisi yok.", 403),
        (response(status=500), "Nexus katalog sunucusunda hata oluştu.", 502),
    ],
)
def test_search_safe_http_errors(failure, message, status):
    with patch("release_service.requests.get", return_value=failure), pytest.raises(NexusCatalogError) as caught:
        search_nexus_assets(settings(), "pub")
    assert caught.value.message == message
    assert caught.value.status_code == status
    assert "raw secret body" not in str(caught.value)
    assert "top-secret" not in str(caught.value)


@pytest.mark.parametrize(
    ("failure", "message", "status"),
    [
        (main.requests.Timeout(), "Nexus katalog bağlantısı zaman aşımına uğradı.", 504),
        (main.requests.ConnectionError(), "Nexus katalog sunucusuna ulaşılamıyor.", 502),
    ],
)
def test_search_safe_network_errors(failure, message, status):
    with patch("release_service.requests.get", side_effect=failure), pytest.raises(NexusCatalogError) as caught:
        search_nexus_assets(settings(), "pub")
    assert (caught.value.message, caught.value.status_code) == (message, status)


def test_catalog_paths_files_urls_versions_and_ambiguous_detection():
    scanned = {
        "pub": [
            asset("/App/1.0/setup.exe", {"sha256": "same"}),
            asset("/App/1.0/readme.txt", {"sha256": "same"}),
            asset("/App/2.0/other.exe", {"sha256": "same"}),
            asset("/App/broken/nested/file", {"sha256": "x"}),
            asset("/App/not-semver/z.bin", {"md5": "z"}),
        ],
        "pub-latest": [asset("/App/portable.zip", {"sha256": "same"}, repository="pub-latest")],
        "int": [asset("/App/3.0/internal.bin", {"sha512": "internal"}, repository="int")],
        "int-latest": [asset("/App/current.bin", {"sha512": "internal"}, repository="int-latest")],
    }
    def normalized(_, repo):
        result = []
        for item in scanned[repo]:
            algorithm = next((name for name in ("sha256", "sha512", "sha1", "md5") if item["checksum"].get(name)), None)
            result.append({
                "repository": item["repository"], "path": item["path"].lstrip("/"),
                "filename": item["path"].rsplit("/", 1)[-1],
                "content_type": item["contentType"], "file_size": item["fileSize"],
                "last_modified": item["lastModified"], "checksum_algorithm": algorithm,
                "checksum_value": item["checksum"].get(algorithm) if algorithm else None,
            })
        return result

    with patch("release_service.search_nexus_assets", side_effect=normalized):
        catalog = build_release_catalog(settings())
    assert [(x["application"], x["visibility"]) for x in catalog] == [("App", "internal"), ("App", "public")]
    public = next(x for x in catalog if x["visibility"] == "public")
    assert [v["version"] for v in public["versions"]] == ["2.0", "1.0", "not-semver"]
    assert len(public["versions"][1]["files"]) == 2
    latest = public["latest_files"][0]
    assert latest["version"] is None
    assert latest["detection"] == "ambiguous"
    assert latest["matching_versions"] == ["2.0", "1.0"]
    assert latest["url"] == "https://public.example/repository/pub-latest/App/portable.zip"
    assert "insecure.example" not in str(catalog)
    assert latest["file_size"] == 37
    assert latest["last_modified"].startswith("2026-09-23")
    internal = next(x for x in catalog if x["visibility"] == "internal")
    assert internal["latest_files"][0]["version"] == "3.0"


@pytest.fixture
def client():
    clear_catalog_cache()
    main.app.config.update(TESTING=True)
    return main.app.test_client()


def login(client):
    with client.session_transaction() as session:
        session["username"] = "publisher"


def test_catalog_endpoints_authorization_success_and_not_found(client):
    assert client.get("/release/apps").status_code == 401
    login(client)
    with patch.object(main, "is_release_uploader", return_value=False):
        assert client.get("/release/apps").status_code == 403
    item = {
        "application": "App",
        "visibility": "public",
        "latest_files": [{"filename": "setup.exe", "version": "1.0", "detection": "checksum"}],
        "versions": [{"version": "1.0", "files": []}],
    }
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(main, "get_release_catalog", return_value=[item]):
        listing = client.get("/release/apps")
        detail = client.get("/release/apps/public/App")
        missing = client.get("/release/apps/public/Missing")
    assert listing.status_code == 200
    assert listing.get_json()["applications"][0]["latest_version"] == "1.0"
    assert detail.status_code == 200 and detail.get_json() == item
    assert missing.status_code == 404
