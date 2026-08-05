"""Typed models for the Trusted Distribution. Pure dataclasses — no pydantic,
no magic. The same shapes are used by the API client, the installer, and the
verifier, so a broken field fails loudly at parse time, not mid-install."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Package:
    """One entry from packages.json / GET /api/packages."""

    id: str
    title: str
    version: str
    description: str
    sha256: str
    release: str
    asset: str

    @classmethod
    def from_dict(cls, d: dict) -> "Package":
        return cls(
            id=d["id"],
            title=d["title"],
            version=d["version"],
            description=d.get("description", ""),
            sha256=d.get("sha256", ""),
            release=d.get("release", ""),
            asset=d.get("asset", ""),
        )


@dataclass(frozen=True)
class Catalog:
    """GET /api/packages response."""

    packages: List[Package] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "Catalog":
        return cls(packages=[Package.from_dict(p) for p in d.get("packages", [])])

    def find(self, package_id: str) -> Optional[Package]:
        for p in self.packages:
            if p.id == package_id:
                return p
        return None


@dataclass(frozen=True)
class License:
    """What activation stores locally in ~/.agentscan/license."""

    key: str
    customer: str
    plan: str
    expires_at: Optional[str]  # ISO date or None for perpetual

    @classmethod
    def from_dict(cls, d: dict) -> "License":
        return cls(
            key=d["license_key"],
            customer=d.get("customer", "Unknown"),
            plan=d.get("plan", "trusted-distribution"),
            expires_at=d.get("expires_at"),
        )

    def to_dict(self) -> dict:
        return {
            "license_key": self.key,
            "customer": self.customer,
            "plan": self.plan,
            "expires_at": self.expires_at,
        }
