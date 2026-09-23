"""Validation, repository selection, and Nexus uploads for release publishing."""

from dataclasses import dataclass
import io
import json
import os
import re
import threading
import time
from urllib.parse import quote

import requests
from packaging.version import InvalidVersion, Version
from werkzeug.utils import secure_filename

_RELEASE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")
_METADATA_DIRECTORY = ".baylan-release"
_METADATA_MAX_BYTES = 64 * 1024


class ReleaseValidationError(ValueError):
    """Raised when release form data cannot safely form a Nexus path."""


class NexusUploadError(Exception):
    """A safe, user-facing representation of a Nexus upload failure."""

    def __init__(self, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class NexusCatalogError(Exception):
    """A credential-free, user-facing Nexus catalog failure."""

    def __init__(self, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class _NexusStreamBody:
    """A sized iterable that streams a response without exposing its raw socket."""

    def __init__(self, response: requests.Response, content_length: int) -> None:
        self.response = response
        self.content_length = int(content_length)
        if self.content_length < 0:
            raise ValueError("content_length must not be negative")

    def __iter__(self):
        yield from _iter_nexus_response(self.response)

    def __len__(self) -> int:
        return self.content_length


def _iter_nexus_response(response: requests.Response):
    """Yield non-empty response chunks for an upload request body."""
    for chunk in response.iter_content(chunk_size=1024 * 1024):
        if chunk:
            yield chunk


@dataclass(frozen=True)
class NexusSettings:
    upload_base_url: str
    public_base_url: str
    repositories: dict[str, tuple[str, str]]
    verify: bool | str
    timeout: tuple[float, float]
    catalog_username: str = ""
    catalog_password: str = ""
    catalog_cache_ttl: float = 30

    @classmethod
    def from_environment(cls) -> "NexusSettings":
        verify_tls = os.getenv("NEXUS_VERIFY_TLS", "true").strip().lower()
        verify: bool | str = verify_tls not in {"false", "0", "no", "off"}
        ca_file = os.getenv("NEXUS_CA_CERT_FILE", "").strip()
        if verify and ca_file:
            verify = ca_file

        return cls(
            upload_base_url=os.getenv("NEXUS_UPLOAD_BASE_URL", "").rstrip("/"),
            public_base_url=os.getenv(
                "NEXUS_PUBLIC_BASE_URL", "https://repo.baylan.info.tr"
            ).rstrip("/"),
            repositories={
                "public": (
                    os.getenv("NEXUS_REPO_PUBLIC", "apps-public"),
                    os.getenv("NEXUS_REPO_PUBLIC_LATEST", "apps-public-latest"),
                ),
                "internal": (
                    os.getenv("NEXUS_REPO_INTERNAL", "apps-internal"),
                    os.getenv("NEXUS_REPO_INTERNAL_LATEST", "apps-internal-latest"),
                ),
            },
            verify=verify,
            timeout=(
                float(os.getenv("NEXUS_CONNECT_TIMEOUT", "10")),
                float(os.getenv("NEXUS_READ_TIMEOUT", "3600")),
            ),
            catalog_username=os.getenv("NEXUS_CATALOG_USERNAME", ""),
            catalog_password=os.getenv("NEXUS_CATALOG_PASSWORD", ""),
            catalog_cache_ttl=float(os.getenv("NEXUS_CATALOG_CACHE_TTL", "30")),
        )


def sanitize_release_segment(value: str | None, field_name: str) -> str:
    """Validate an application/version path segment without silently changing it."""
    value = (value or "").strip()
    if (
        not value
        or value in {".", ".."}
        or ".." in value
        or "\x00" in value
        or not _RELEASE_SEGMENT.fullmatch(value)
    ):
        raise ReleaseValidationError(f"Geçersiz {field_name}.")
    return value


def sanitize_release_filename(value: str | None, field_name: str) -> str:
    """Return a safe filename, rejecting paths rather than flattening them."""
    value = (value or "").strip()
    if (
        not value
        or "\x00" in value
        or "/" in value
        or "\\" in value
        or ".." in value
        or value in {".", ".."}
    ):
        raise ReleaseValidationError(f"Geçersiz {field_name}.")
    filename = secure_filename(value)
    if not filename or filename in {".", ".."}:
        raise ReleaseValidationError(f"Geçersiz {field_name}.")
    return filename


def get_repository_mapping(
    visibility: str | None, settings: NexusSettings
) -> tuple[str, str]:
    visibility = (visibility or "").strip().lower()
    if visibility not in settings.repositories:
        raise ReleaseValidationError(
            "visibility yalnızca public veya internal olabilir."
        )
    return settings.repositories[visibility]


def build_nexus_url(base_url: str, repository: str, asset_path: str) -> str:
    if not base_url:
        raise NexusUploadError("Nexus yükleme adresi yapılandırılmamış.", 500)
    encoded_repository = quote(repository.strip("/"), safe="")
    encoded_path = "/".join(quote(part, safe="") for part in asset_path.split("/"))
    return f"{base_url.rstrip('/')}/repository/{encoded_repository}/{encoded_path}"


def _catalog_error(response: requests.Response) -> NexusCatalogError:
    if response.status_code == 401:
        return NexusCatalogError("Nexus katalog hesabı doğrulanamadı.", 401)
    if response.status_code == 403:
        return NexusCatalogError(
            "Nexus katalog hesabının repository erişim yetkisi yok.", 403
        )
    if response.status_code >= 500:
        return NexusCatalogError("Nexus katalog sunucusunda hata oluştu.", 502)
    return NexusCatalogError("Nexus katalog isteği başarısız oldu.", 502)


def search_nexus_assets(settings: NexusSettings, repository: str) -> list[dict]:
    """Read every Nexus search page and return only the safe normalized fields."""
    endpoint = f"{settings.upload_base_url.rstrip('/')}/service/rest/v1/search/assets"
    token = None
    assets = []
    while True:
        params = {"repository": repository}
        if token:
            params["continuationToken"] = token
        try:
            response = requests.get(
                endpoint,
                params=params,
                auth=(settings.catalog_username, settings.catalog_password),
                verify=settings.verify,
                timeout=settings.timeout,
            )
        except requests.Timeout as exc:
            raise NexusCatalogError(
                "Nexus katalog bağlantısı zaman aşımına uğradı.", 504
            ) from exc
        except requests.ConnectionError as exc:
            raise NexusCatalogError(
                "Nexus katalog sunucusuna ulaşılamıyor.", 502
            ) from exc
        except requests.RequestException as exc:
            raise NexusCatalogError("Nexus katalog isteği başarısız oldu.", 502) from exc
        if not 200 <= response.status_code < 300:
            raise _catalog_error(response)
        try:
            payload = response.json()
        except (ValueError, TypeError) as exc:
            raise NexusCatalogError("Nexus katalog yanıtı geçersiz.", 502) from exc
        for item in payload.get("items", []):
            path = str(item.get("path") or "").lstrip("/")
            checksum = item.get("checksum") or {}
            algorithm = next(
                (name for name in ("sha256", "sha512", "sha1", "md5") if checksum.get(name)),
                None,
            )
            assets.append(
                {
                    "repository": str(item.get("repository") or repository),
                    "path": path,
                    "filename": path.rsplit("/", 1)[-1],
                    "content_type": item.get("contentType"),
                    "file_size": item.get("fileSize"),
                    "last_modified": item.get("lastModified"),
                    "checksum_algorithm": algorithm,
                    "checksum_value": checksum.get(algorithm) if algorithm else None,
                }
            )
        token = payload.get("continuationToken")
        if not token:
            return assets


def _valid_segment(value: str, label: str) -> bool:
    try:
        sanitize_release_segment(value, label)
        return True
    except ReleaseValidationError:
        return False


def _version_sort(versions: list[str]) -> list[str]:
    valid, invalid = [], []
    for value in versions:
        try:
            valid.append((Version(value), value))
        except InvalidVersion:
            invalid.append(value)
    return [v for _, v in sorted(valid, reverse=True)] + sorted(invalid)


def release_metadata_path(application: str, latest_filename: str) -> str:
    """Return the internal sidecar path for a latest asset."""
    return f"{application}/{_METADATA_DIRECTORY}/{latest_filename}.json"


def _read_release_metadata(
    settings: NexusSettings, repository: str, asset_path: str
) -> dict | None:
    """Read a small sidecar with the catalog account; malformed data is optional."""
    try:
        response = requests.get(
            build_nexus_url(settings.upload_base_url, repository, asset_path),
            stream=True,
            auth=(settings.catalog_username, settings.catalog_password),
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
            verify=settings.verify,
            timeout=settings.timeout,
        )
        if not 200 <= response.status_code < 300:
            return None
        body = bytearray()
        for chunk in response.iter_content(chunk_size=8192):
            body.extend(chunk)
            if len(body) > _METADATA_MAX_BYTES:
                return None
        value = json.loads(body)
        return value if isinstance(value, dict) else None
    except (requests.RequestException, ValueError, TypeError, UnicodeDecodeError):
        return None
    finally:
        if "response" in locals():
            response.close()


def upload_release_metadata(
    *, settings: NexusSettings, repository: str, application: str,
    version: str, source_filename: str, latest_filename: str,
    username: str, password: str,
) -> str:
    """Write only validated release identity fields to the latest repository."""
    application = sanitize_release_segment(application, "application")
    version = sanitize_release_segment(version, "version")
    source_filename = sanitize_release_filename(source_filename, "kaynak dosya adı")
    latest_filename = sanitize_release_filename(latest_filename, "latest filename")
    payload = json.dumps(
        {"version": version, "source_filename": source_filename,
         "latest_filename": latest_filename},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return upload_to_nexus(
        settings=settings,
        repository=repository,
        asset_path=release_metadata_path(application, latest_filename),
        stream=io.BytesIO(payload),
        username=username,
        password=password,
        content_type="application/json",
    )


def build_release_catalog(settings: NexusSettings) -> list[dict]:
    """Scan configured repositories and construct application/visibility records."""
    catalog = []
    for visibility, (archive_repo, latest_repo) in settings.repositories.items():
        grouped: dict[str, dict] = {}
        for asset in search_nexus_assets(settings, archive_repo):
            parts = asset["path"].split("/")
            if len(parts) != 3 or not _valid_segment(parts[0], "application") or not _valid_segment(parts[1], "version") or not parts[2]:
                continue
            app, version, filename = parts
            entry = grouped.setdefault(app, {"archive": {}, "latest": []})
            file_data = {key: asset[key] for key in ("content_type", "file_size", "last_modified", "checksum_algorithm", "checksum_value")}
            file_data.update(filename=filename, url=build_nexus_url(settings.public_base_url, archive_repo, asset["path"]))
            entry["archive"].setdefault(version, []).append(file_data)
        latest_assets = search_nexus_assets(settings, latest_repo)
        metadata_assets = {
            asset["path"]: asset
            for asset in latest_assets
            if len(asset["path"].split("/")) == 3
            and asset["path"].split("/")[1] == _METADATA_DIRECTORY
        }
        for asset in latest_assets:
            parts = asset["path"].split("/")
            if len(parts) != 2 or not _valid_segment(parts[0], "application") or not parts[1]:
                continue
            app, filename = parts
            entry = grouped.setdefault(app, {"archive": {}, "latest": []})
            metadata = None
            metadata_path = release_metadata_path(app, filename)
            if metadata_path in metadata_assets:
                candidate = _read_release_metadata(settings, latest_repo, metadata_path)
                try:
                    if candidate is not None:
                        metadata_version = sanitize_release_segment(candidate.get("version"), "version")
                        source_filename = sanitize_release_filename(candidate.get("source_filename"), "kaynak dosya adı")
                        metadata_filename = sanitize_release_filename(candidate.get("latest_filename"), "latest filename")
                        if metadata_filename == filename and any(
                            item["filename"] == source_filename
                            for item in entry["archive"].get(metadata_version, [])
                        ):
                            metadata = (metadata_version, source_filename)
                except (ReleaseValidationError, AttributeError):
                    metadata = None
            matches = set()
            if asset["checksum_algorithm"] and asset["checksum_value"]:
                for version, files in entry["archive"].items():
                    if any(f["checksum_algorithm"] == asset["checksum_algorithm"] and f["checksum_value"] == asset["checksum_value"] for f in files):
                        matches.add(version)
            latest = {key: asset[key] for key in ("content_type", "file_size", "last_modified", "checksum_algorithm", "checksum_value")}
            latest.update(filename=filename, url=build_nexus_url(settings.public_base_url, latest_repo, asset["path"]))
            if metadata is not None:
                latest.update(version=metadata[0], source_filename=metadata[1], detection="metadata")
            elif len(matches) == 1:
                latest.update(version=next(iter(matches)), detection="checksum")
            elif len(matches) > 1:
                latest.update(version=None, detection="ambiguous", matching_versions=_version_sort(list(matches)))
            else:
                latest.update(version=None, detection="unknown")
            entry["latest"].append(latest)
        for application, data in grouped.items():
            versions = [{"version": version, "files": sorted(data["archive"][version], key=lambda f: f["filename"])} for version in _version_sort(list(data["archive"]))]
            catalog.append({"application": application, "visibility": visibility, "latest_files": sorted(data["latest"], key=lambda f: f["filename"]), "versions": versions})
    return sorted(catalog, key=lambda item: (item["application"].lower(), item["visibility"]))


_catalog_cache_lock = threading.Lock()
_catalog_cache: dict[tuple, tuple[float, list[dict]]] = {}


def clear_catalog_cache() -> None:
    with _catalog_cache_lock:
        _catalog_cache.clear()


def resolve_latest_filename(
    application: str, uploaded_filename: str, catalog_item: dict | None
) -> str:
    """Choose the existing stable asset safely, or derive it for a new app."""
    latest_files = (catalog_item or {}).get("latest_files") or []
    if len(latest_files) == 1:
        return sanitize_release_filename(
            latest_files[0].get("filename"), "latest filename"
        )

    extension = os.path.splitext(uploaded_filename)[1]
    if not extension:
        if latest_files:
            raise ReleaseValidationError(
                "Bu uygulama için sabit link dosyası otomatik belirlenemedi."
            )
        raise ReleaseValidationError("Sabit link dosya adı otomatik belirlenemedi.")

    if not latest_files:
        return sanitize_release_filename(f"{application}{extension}", "latest filename")

    matches = [
        item.get("filename")
        for item in latest_files
        if os.path.splitext(item.get("filename") or "")[1].lower() == extension.lower()
    ]
    if len(matches) == 1:
        return sanitize_release_filename(matches[0], "latest filename")
    raise ReleaseValidationError(
        "Bu uygulama için sabit link dosyası otomatik belirlenemedi."
    )


def get_release_catalog(settings: NexusSettings) -> list[dict]:
    """Return a process-local TTL-cached catalog (credentials are never cached)."""
    key = (settings.upload_base_url, settings.public_base_url, tuple(sorted(settings.repositories.items())), settings.verify, settings.timeout)
    now = time.monotonic()
    with _catalog_cache_lock:
        cached = _catalog_cache.get(key)
        if cached and now - cached[0] < max(0, settings.catalog_cache_ttl):
            return cached[1]
        value = build_release_catalog(settings)
        _catalog_cache[key] = (now, value)
        return value


def _nexus_error(response: requests.Response) -> NexusUploadError:
    status = response.status_code
    # Some Nexus versions report an immutable/redeploy conflict as HTTP 400.
    body = response.text.lower()[:4096] if status in {400, 409} else ""
    if status == 409 or any(
        marker in body
        for marker in (
            "redeploy",
            "already exists",
            "cannot be updated",
            "already been uploaded",
            "repository does not allow updating assets",
            "asset already exists",
            "cannot be modified",
        )
    ):
        return NexusUploadError("Bu uygulama sürümü daha önce yayınlanmış.", 409)
    if status == 401:
        return NexusUploadError("Nexus kullanıcı adı veya parola hatalı.", 401)
    if status == 403:
        return NexusUploadError("Nexus üzerinde yayınlama yetkiniz bulunmuyor.", 403)
    if status == 400:
        return NexusUploadError("Nexus isteği kabul etmedi.", 400)
    if status >= 500:
        return NexusUploadError("Nexus sunucusunda hata oluştu.", 502)
    return NexusUploadError("Nexus yükleme işlemi başarısız oldu.", 502)


def asset_exists_on_nexus(
    *,
    settings: NexusSettings,
    repository: str,
    asset_path: str,
    username: str,
    password: str,
) -> bool:
    """Check whether a raw asset exists without exposing Nexus response details."""
    asset_url = build_nexus_url(settings.upload_base_url, repository, asset_path)
    try:
        response = requests.head(
            asset_url,
            auth=(username, password),
            verify=settings.verify,
            timeout=settings.timeout,
        )
    except requests.Timeout as exc:
        raise NexusUploadError("Nexus bağlantısı zaman aşımına uğradı.", 504) from exc
    except requests.ConnectionError as exc:
        raise NexusUploadError("Nexus sunucusuna ulaşılamıyor.", 502) from exc
    except requests.RequestException as exc:
        raise NexusUploadError("Nexus yükleme işlemi başarısız oldu.", 502) from exc

    if 200 <= response.status_code < 300:
        return True
    if response.status_code == 404:
        return False
    if response.status_code == 401:
        raise NexusUploadError("Nexus kullanıcı adı veya parola hatalı.", 401)
    if response.status_code == 403:
        raise NexusUploadError("Nexus üzerinde yayınlama yetkiniz bulunmuyor.", 403)
    if response.status_code >= 500:
        raise NexusUploadError("Nexus sunucusunda hata oluştu.", 502)
    raise NexusUploadError("Nexus yükleme işlemi başarısız oldu.", 502)


def upload_to_nexus(
    *,
    settings: NexusSettings,
    repository: str,
    asset_path: str,
    stream,
    username: str,
    password: str,
    content_type: str | None = None,
) -> str:
    """Stream a file object to a Nexus raw hosted repository with HTTP PUT."""
    upload_url = build_nexus_url(settings.upload_base_url, repository, asset_path)
    headers = {"Content-Type": content_type or "application/octet-stream"}
    try:
        response = requests.put(
            upload_url,
            data=stream,
            auth=(username, password),
            headers=headers,
            verify=settings.verify,
            timeout=settings.timeout,
        )
    except requests.Timeout as exc:
        raise NexusUploadError("Nexus bağlantısı zaman aşımına uğradı.", 504) from exc
    except requests.ConnectionError as exc:
        raise NexusUploadError("Nexus sunucusuna ulaşılamıyor.", 502) from exc
    except requests.RequestException as exc:
        raise NexusUploadError("Nexus yükleme işlemi başarısız oldu.", 502) from exc

    if not 200 <= response.status_code < 300:
        raise _nexus_error(response)
    return build_nexus_url(settings.public_base_url, repository, asset_path)


def promote_nexus_asset(
    *,
    settings: NexusSettings,
    archive_repository: str,
    archive_path: str,
    latest_repository: str,
    latest_path: str,
    username: str,
    password: str,
    content_type: str | None = None,
    file_size: int | None = None,
) -> str:
    """Copy an archive asset to latest without buffering it in this process."""
    source_url = build_nexus_url(
        settings.upload_base_url, archive_repository, archive_path
    )
    source = None
    try:
        try:
            source = requests.get(
                source_url,
                stream=True,
                auth=(settings.catalog_username, settings.catalog_password),
                headers={"Accept-Encoding": "identity"},
                verify=settings.verify,
                timeout=settings.timeout,
            )
        except requests.Timeout as exc:
            raise NexusUploadError(
                "Nexus arşiv bağlantısı zaman aşımına uğradı.", 504
            ) from exc
        except requests.ConnectionError as exc:
            raise NexusUploadError("Nexus sunucusuna ulaşılamıyor.", 502) from exc
        except requests.RequestException as exc:
            raise NexusUploadError("Nexus arşiv dosyası okunamadı.", 502) from exc

        if not 200 <= source.status_code < 300:
            if source.status_code in {401, 403}:
                raise NexusUploadError(
                    "Nexus katalog hesabının arşiv dosyasını okuma yetkisi yok.",
                    502,
                )
            if source.status_code == 404:
                raise NexusUploadError(
                    "Arşiv dosyası Nexus üzerinde bulunamadı.", 404
                )
            if source.status_code >= 500:
                raise NexusUploadError("Nexus sunucusunda hata oluştu.", 502)
            raise NexusUploadError("Nexus arşiv dosyası okunamadı.", 502)

        headers = {"Content-Type": content_type or "application/octet-stream"}
        if file_size == 0:
            body = b""
        elif file_size is None:
            # An unsized iterator makes requests use chunked transfer encoding.
            body = _iter_nexus_response(source)
        else:
            # A sized iterable lets requests derive Content-Length itself, without
            # treating urllib3's HTTPResponse as a seekable file object.
            body = _NexusStreamBody(source, file_size)
        target_url = build_nexus_url(
            settings.upload_base_url, latest_repository, latest_path
        )
        try:
            target = requests.put(
                target_url,
                data=body,
                auth=(username, password),
                headers=headers,
                verify=settings.verify,
                timeout=settings.timeout,
            )
        except requests.Timeout as exc:
            raise NexusUploadError("Nexus bağlantısı zaman aşımına uğradı.", 504) from exc
        except requests.ConnectionError as exc:
            raise NexusUploadError("Nexus sunucusuna ulaşılamıyor.", 502) from exc
        except requests.RequestException as exc:
            raise NexusUploadError("Nexus yükleme işlemi başarısız oldu.", 502) from exc
        if not 200 <= target.status_code < 300:
            raise _nexus_error(target)
        return build_nexus_url(
            settings.public_base_url, latest_repository, latest_path
        )
    finally:
        if source is not None:
            source.close()
