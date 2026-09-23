"""Validation, repository selection, and Nexus uploads for release publishing."""

from dataclasses import dataclass
import os
import re
from urllib.parse import quote

import requests
from werkzeug.utils import secure_filename

_RELEASE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")


class ReleaseValidationError(ValueError):
    """Raised when release form data cannot safely form a Nexus path."""


class NexusUploadError(Exception):
    """A safe, user-facing representation of a Nexus upload failure."""

    def __init__(self, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True)
class NexusSettings:
    upload_base_url: str
    public_base_url: str
    repositories: dict[str, tuple[str, str]]
    verify: bool | str
    timeout: tuple[float, float]

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
