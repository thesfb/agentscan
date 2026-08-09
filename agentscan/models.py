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

    def resolve(self, query: str):
        """Resolve a user-supplied package query to a package.

        Matching is forgiving: whitespace, hyphens, underscores and case
        are all normalized ("trust-pack", "Trust Pack",
        "TRUST PACK" and "trust" all resolve to trust-pack).

        Returns a 4-tuple:
            (package, note, candidates, suggestion)

        - package:   the resolved package, or None.
        - note:      a friendly "matched X → id" line when the match was
                     not exact, else "".
        - candidates: list of package ids when the query is ambiguous
                     (more than one match); empty otherwise.
        - suggestion: a single best-guess id when nothing matched (for
                     "did you mean"), else None.
        """
        q = normalize_name(query)
        if not q:
            return None, "", [], None

        def norm(p: Package) -> tuple[str, str]:
            return normalize_name(p.id), normalize_name(p.title)

        # 1. exact id or title
        for p in self.packages:
            nid, ntitle = norm(p)
            if nid == q or ntitle == q:
                return p, "", [], None

        # 2. prefix (id or title starts with the query)
        prefix = [p for p in self.packages if norm(p)[0].startswith(q) or norm(p)[1].startswith(q)]
        if len(prefix) == 1:
            return prefix[0], f"matched '{query}' → {prefix[0].id}", [], None
        if len(prefix) > 1:
            return None, "", [p.id for p in prefix], None

        # 2b. word match (query is a whole word of the id/title:
        #     "trust" → trust-pack, "pack" → ambiguous)
        word_matches = [
            p for p in self.packages
            if q in norm(p)[0].split() or q in norm(p)[1].split()
        ]
        if len(word_matches) == 1:
            return word_matches[0], f"matched '{query}' → {word_matches[0].id}", [], None
        if len(word_matches) > 1:
            return None, "", [p.id for p in word_matches], None

        # 3. fuzzy (typos: "trustpac" → trust-pack)
        import difflib

        pool: dict[str, Package] = {}
        for p in self.packages:
            nid, ntitle = norm(p)
            pool.setdefault(nid, p)
            pool.setdefault(ntitle, p)
        close = difflib.get_close_matches(q, list(pool), n=3, cutoff=0.5)
        ids: list[str] = []
        for key in close:
            pid = pool[key].id
            if pid not in ids:
                ids.append(pid)
        if len(ids) == 1:
            return pool[close[0]], f"matched '{query}' → {ids[0]}", [], None
        if len(ids) > 1:
            return None, "", ids, None

        # 4. total miss: single best guess for "did you mean"
        guess = difflib.get_close_matches(q, list(pool), n=1, cutoff=0.4)
        return None, "", [], (pool[guess[0]].id if guess else None)


def normalize_name(name: str) -> str:
    """Lowercase and collapse separators: hyphens, underscores, spaces.

    "Trust Pack", "trust-pack", "TRUST_PACK" and
    "  trust  pack " all normalize to "trust pack".
    """
    return " ".join(name.lower().replace("_", " ").replace("-", " ").split())


@dataclass(frozen=True)
class License:
    """What activation stores locally in ~/.agentscan/license."""

    key: str
    customer: str
    plan: str
    expires_at: Optional[str]  # ISO date or None for perpetual

    @classmethod
    def from_dict(cls, d: dict) -> "License":
        # Polar returns customer as an object ({email, name, ...}) on the
        # customer-portal validate endpoint; our mock returned a string.
        customer = d.get("customer")
        if isinstance(customer, dict):
            customer = customer.get("name") or customer.get("email") or "Trusted Distribution Customer"
        return cls(
            key=d.get("license_key") or d.get("key") or "",
            customer=customer or "Trusted Distribution Customer",
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
