"""CycloneDX SBOM generation and OSV vulnerability lookup (v2 layer 14).

--sbom: emit a CycloneDX 1.5 JSON document from the scanner's
        dependency list (agent-artifact SBOM — a differentiator).
--osv:  opt-in lookup against the OSV API (keyless, free). Offline or
        on error the scanner degrades with an explicit note, never a
        silent gap.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

_ECOSYSTEM = {"PyPI": "PyPI", "npm": "npm", "system": "Debian"}

_SEV_MAP = {
    "CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
    "MEDIUM": "medium", "LOW": "low", "": "medium",
}


def cyclonedx(target_name, components, tool_name="agentscan", tool_version=""):
    """Build a CycloneDX 1.5 JSON dict from dependency records."""
    comps = []
    for dep in components:
        eco = _ECOSYSTEM.get(dep.get("ecosystem", ""), "generic")
        name = dep.get("name", "")
        version = dep.get("version") or ""
        if eco == "PyPI":
            purl = f"pkg:pypi/{name}" + (f"@{version}" if version else "")
        elif eco == "npm":
            purl = f"pkg:npm/{name}" + (f"@{version}" if version else "")
        else:
            purl = f"pkg:generic/{name}" + (f"@{version}" if version else "")
        comps.append({
            "type": "library",
            "name": name,
            "version": version if version else None,
            "purl": purl,
            "bom-ref": purl,
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": target_name},
            "tools": [{"vendor": "agentscan", "name": tool_name,
                       "version": tool_version}],
        },
        "components": comps,
    }


def query_osv(components, timeout=30):
    """Batch query OSV. Returns (vulns, errors) where vulns is a list of
    {id, summary, severity, package, version, affected}. Errors lists
    components that could not be checked."""
    queries = []
    for dep in components:
        eco = _ECOSYSTEM.get(dep.get("ecosystem", ""))
        if not eco:
            continue
        q = {"package": {"name": dep.get("name", ""), "ecosystem": eco}}
        if dep.get("version"):
            q["version"] = dep["version"]
        queries.append(q)
    if not queries:
        return [], []
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "agentscan-cli"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError):
        return [], ["osv lookup failed — results are incomplete"]

    vulns = []
    results = data.get("results", [])
    for i, res in enumerate(results):
        if i >= len(queries):
            break
        pkg = queries[i]["package"]
        for v in res.get("vulns", []):
            sev = "medium"
            for s in v.get("severity", []):
                sev = _SEV_MAP.get(s.get("severity", "").upper(), sev)
            vulns.append({
                "id": v.get("id", "OSV-?"),
                "summary": v.get("summary", "")[:160],
                "severity": sev,
                "package": pkg.get("name", ""),
                "ecosystem": pkg.get("ecosystem", ""),
                "modified": v.get("modified", ""),
            })
    return vulns, []
