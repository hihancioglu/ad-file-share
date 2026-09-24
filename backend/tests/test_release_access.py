from unittest.mock import Mock, patch

import pytest

import main


@pytest.fixture
def client():
    main.app.config.update(TESTING=True)
    return main.app.test_client()


def login(client, username="support"):
    with client.session_transaction() as session:
        session["username"] = username


def catalog_item():
    file_data = {
        "filename": "setup.exe",
        "content_type": "application/octet-stream",
        "file_size": 4,
        "last_modified": "2026-09-23T10:35:02+00:00",
        "checksum_algorithm": "sha256",
        "checksum_value": "abc",
    }
    return {
        "application": "App",
        "visibility": "public",
        "latest_files": [dict(file_data, detection="checksum", version="1.0", url="https://example/latest")],
        "versions": [{"version": "1.0", "files": [file_data]}],
    }


def test_release_access_requires_login(client):
    assert client.get("/release/access").status_code == 401


@pytest.mark.parametrize(
    ("uploader", "viewer", "expected"),
    [
        (False, True, {"allowed": True, "can_read": True, "can_write": False}),
        (True, False, {"allowed": True, "can_read": True, "can_write": True}),
        (False, False, {"allowed": False, "can_read": False, "can_write": False}),
    ],
)
def test_release_access_capabilities(client, uploader, viewer, expected):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=uploader), patch.object(
        main, "is_release_viewer", return_value=viewer
    ):
        response = client.get("/release/access")
    assert response.status_code == 200
    assert response.get_json() == expected


def test_viewer_can_list_and_read_details(client):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=False), patch.object(
        main, "is_release_viewer", return_value=True
    ), patch.object(main, "get_release_catalog", return_value=[catalog_item()]):
        listing = client.get("/release/apps")
        detail = client.get("/release/apps/public/App")
    assert listing.status_code == 200
    assert detail.status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "/release/download/archive/public/App/1.0/setup.exe",
        "/release/download/latest/public/App/setup.exe",
    ],
)
def test_viewer_can_download_archive_and_latest_with_catalog_account(client, path):
    login(client)
    upstream = Mock(status_code=200)
    upstream.iter_content.return_value = iter([b"data"])
    settings = main.NexusSettings(
        upload_base_url="https://nexus.example",
        public_base_url="https://public.example",
        repositories={"public": ("apps-public", "apps-public-latest"), "internal": ("apps-internal", "apps-internal-latest")},
        verify=True,
        timeout=(2, 5),
        catalog_username="catalog",
        catalog_password="catalog-secret",
        catalog_cache_ttl=30,
    )
    with patch.object(main, "is_release_uploader", return_value=False), patch.object(
        main, "is_release_viewer", return_value=True
    ), patch.object(main, "get_release_catalog", return_value=[catalog_item()]), patch.object(
        main.NexusSettings, "from_environment", return_value=settings
    ), patch.object(
        main.requests, "get", return_value=upstream
    ) as get:
        response = client.get(path, buffered=False)
        assert b"".join(response.response) == b"data"
    assert response.status_code == 200
    assert get.call_args.kwargs["auth"] == ("catalog", "catalog-secret")


@pytest.mark.parametrize(
    "path",
    [
        "/release/apps/create",
        "/release/publish",
        "/release/publish-latest",
        "/release/promote-latest",
    ],
)
def test_viewer_cannot_use_write_endpoints(client, path):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=False), patch.object(
        main, "is_release_viewer", return_value=True
    ):
        response = client.post(path)
    assert response.status_code == 403
    assert response.get_json() == {"error": "Yayınlama yetkiniz bulunmuyor"}


def test_neither_role_cannot_read_catalog_or_write(client):
    login(client)
    with patch.object(main, "is_release_uploader", return_value=False), patch.object(
        main, "is_release_viewer", return_value=False
    ):
        assert client.get("/release/apps").status_code == 403
        assert client.post("/release/publish").status_code == 403


def test_uploader_inherits_catalog_read_access(client):
    login(client, "publisher")
    with patch.object(main, "is_release_uploader", return_value=True), patch.object(
        main, "is_release_viewer"
    ) as viewer, patch.object(main, "get_release_catalog", return_value=[catalog_item()]):
        assert client.get("/release/apps").status_code == 200
    viewer.assert_not_called()


@pytest.mark.parametrize(
    ("helper", "group_name"),
    [
        ("is_release_viewer", "release-viewer"),
        ("is_release_uploader", "release-uploader"),
    ],
)
def test_release_groups_use_recursive_ad_membership(helper, group_name):
    connection = Mock()
    connection.bind.return_value = True

    def search(_base, ldap_filter, attributes):
        if "objectClass=group" in ldap_filter:
            connection.entries = [Mock(entry_dn=f"CN={group_name},OU=Groups,DC=example,DC=com")]
        else:
            connection.entries = [Mock()]
            assert "memberOf:1.2.840.113556.1.4.1941:=" in ldap_filter
        return True

    connection.search.side_effect = search
    with patch.object(main.ldap3, "Server"), patch.object(
        main.ldap3, "Connection", return_value=connection
    ):
        assert getattr(main, helper)("support") is True
    assert group_name in connection.search.call_args_list[0].args[1]
