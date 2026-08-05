"""API client for the AgentScan Trusted Distribution.

The CLI never talks HTTP directly — every command goes through this client.
Swapping the mock for the production backend is a one-line URL change.

Endpoints (Next.js route handlers on the website):

    POST /api/verify-license     activate a license key
    GET  /api/packages           catalog of available packages
    GET  /api/packages/{id}      single package manifest
    GET  /api/download/{id}      tarball download (authenticated)

Errors raise ApiError with a human-readable message; commands catch it and
print a clean failure instead of a traceback.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from .models import Catalog, License, Package

DEFAULT_TIMEOUT = 30


class ApiError(Exception):
    """A failed request, with a message safe to show the user."""

    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class Client:
    def __init__(self, base_url: str, license_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.license_key = license_key

    # -- low level ---------------------------------------------------------

    def _request(self, method: str, path: str, payload: Optional[dict] = None) -> dict:
        url = self.base_url + path
        data = None
        headers = {"Accept": "application/json", "User-Agent": "agentscan-cli"}
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        if self.license_key:
            headers["Authorization"] = "Bearer " + self.license_key
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            detail = _error_detail(e)
            raise ApiError(detail, status=e.code) from None
        except urllib.error.URLError as e:
            raise ApiError(f"cannot reach {self.base_url}: {e.reason}") from None
        except ValueError:
            raise ApiError("server returned non-JSON response") from None

    def _download(self, path: str, dest: Path) -> None:
        url = self.base_url + path
        headers = {"Accept": "application/octet-stream", "User-Agent": "agentscan-cli"}
        if self.license_key:
            headers["Authorization"] = "Bearer " + self.license_key
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as fh:
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    fh.write(chunk)
        except urllib.error.HTTPError as e:
            raise ApiError(_error_detail(e), status=e.code) from None
        except urllib.error.URLError as e:
            raise ApiError(f"cannot reach {self.base_url}: {e.reason}") from None

    # -- commands ----------------------------------------------------------

    def activate(self, license_key: str) -> License:
        body = self._request("POST", "/api/verify-license", {"license_key": license_key})
        if not body.get("valid"):
            raise ApiError(body.get("error", "license rejected by server"))
        return License.from_dict(body)

    def search(self) -> Catalog:
        return Catalog.from_dict(self._request("GET", "/api/packages"))

    def package(self, package_id: str) -> Package:
        body = self._request("GET", "/api/packages/" + package_id)
        return Package.from_dict(body.get("package", body))

    def download(self, package_id: str, dest: Path) -> None:
        self._download("/api/download/" + package_id, dest)


def _error_detail(e: urllib.error.HTTPError) -> str:
    try:
        body = json.loads(e.read().decode())
        return body.get("error", body.get("detail", f"HTTP {e.code}"))
    except (ValueError, OSError):
        return f"HTTP {e.code}"
