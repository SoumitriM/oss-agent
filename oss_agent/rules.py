"""Deterministic rules. Code, not the LLM, decides these, so they are
repeatable and explainable."""

PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense", "Zlib", "PSF-2.0"}
WEAK_COPYLEFT = {"LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0", "LGPL-3.0-only",
                 "LGPL-3.0-or-later", "MPL-2.0", "EPL-2.0"}
STRONG_COPYLEFT = {"GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later"}
NETWORK_COPYLEFT = {"AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later"}

RANK = {"green": 0, "not_checked": 0, "yellow": 1, "red": 2}


def licence_rule(spdx: str | None, has_licence_file: bool) -> tuple[str, str] | None:
    """(status, note) from the SPDX id, or None if the LLM must judge from the licence text."""
    if not has_licence_file and spdx in (None, "NONE"):
        return "red", "No licence file: by default there is no permission to use the code."
    if spdx in PERMISSIVE:
        return "green", f"{spdx} is a permissive licence (keep the copyright notice)."
    if spdx in WEAK_COPYLEFT:
        return "green", f"{spdx} is weak copyleft: changes to the library itself must be shared."
    if spdx in STRONG_COPYLEFT:
        return "yellow", f"{spdx} is strong copyleft: distributing your product may require releasing its source."
    if spdx in NETWORK_COPYLEFT:
        return "yellow", f"{spdx} is network copyleft: offering it as a service may require releasing your source."
    return None  # NOASSERTION, custom or source-available: the LLM must read the licence file


def overall(areas: dict) -> str:
    """Overall verdict = worst area status. not_checked does not make it better or worse."""
    statuses = [a["status"] for a in areas.values()]
    worst = max(statuses, key=lambda s: RANK.get(s, 0), default="not_checked")
    if all(s == "not_checked" for s in statuses):
        return "not_checked"
    return worst if worst != "not_checked" else "green"
