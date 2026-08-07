"""API client for the AgentScan Trusted Distribution.

Two backends:

  Polar (license activation) — the CLI talks to Polar DIRECTLY.
  Polar's /v1/customer-portal/license-keys/validate endpoint is public and
  explicitly safe for desktop apps: no secret, no server in the middle.
  The organization id is public (embedded in every license key response).

  agentscan.baldbee.me (catalog + downloads) — the site's route handlers:

    GET  /api/packages           catalog of available packages
    GET  /api/download/{id}      tarball download (license-gated)

Errors raise ApiError with a human-readable message; commands catch it and
print a clean failure instead of a traceback.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from .models import Catalog, License, Package

DEFAULT_TIMEOUT = 30

POLAR_VALIDATE_URL = os.environ.get(
    "AGENTSCAN_POLAR_VALIDATE_URL",
    "https://api.polar.sh/v1/customer-portal/license-keys/validate",
)


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
        url = path if path.startswith("http") else self.base_url + path
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

    def _download(self, path: str, dest: Path, progress=None) -> None:
        url = self.base_url + path
        headers = {"Accept": "application/octet-stream", "User-Agent": "agentscan-cli"}
        if self.license_key:
            headers["Authorization"] = "Bearer " + self.license_key
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as fh:
                total = int(resp.headers.get("Content-Length") or 0)
                done = 0
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    fh.write(chunk)
                    done += len(chunk)
                    if progress:
                        progress(done, total)
        except urllib.error.HTTPError as e:
            raise ApiError(_error_detail(e), status=e.code) from None
        except urllib.error.URLError as e:
            raise ApiError(f"cannot reach {self.base_url}: {e.reason}") from None

    # -- commands ----------------------------------------------------------

    def activate(self, license_key: str, organization_id: str) -> License:
        """Validate a license key against Polar directly (public endpoint).

        Returns a License with the fields the CLI stores locally. Raises
        ApiError when the key is invalid, revoked, disabled, or expired.
        """
        try:
            body = self._request(
                "POST",
                POLAR_VALIDATE_URL,
                {"key": license_key, "organization_id": organization_id},
            )
        except ApiError as e:
            # Polar returns 404/422 for unknown or malformed keys — the
            # raw body ("ResourceNotFound") is noise; say what happened.
            if e.status in (401, 404, 422):
                raise ApiError("invalid license key — check it and try again") from None
            raise
        status = body.get("status", "invalid")
        if status != "granted":
            raise ApiError(f"license {status}")
        return License.from_dict(body)

    def search(self) -> Catalog:
        return Catalog.from_dict(self._request("GET", "/api/packages"))

    def download(self, package_id: str, dest: Path, progress=None) -> None:
        self._download("/api/download/" + package_id, dest, progress=progress)


def _error_detail(e: urllib.error.HTTPError) -> str:
    try:
        body = json.loads(e.read().decode())
        return body.get("error", body.get("detail", f"HTTP {e.code}"))
    except (ValueError, OSError):
        return f"HTTP {e.code}"
