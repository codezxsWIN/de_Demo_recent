"""Pure, data-minimising interpretation of one bounded HTTP HEAD response.

No networking, crawling, credentials, page bodies, or canonical scoring. Retained
bytes are explicitly a metadata projection, not the original wire response.
"""

from __future__ import annotations

import json
import re

from vulnassess.errors import NeedsReview

FORMAT = "website_metadata.v1"
PREFIX = "Metadata-only HTTP HEAD evidence."
LIMIT = 8192
HEADER_NAMES = {
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "strict-transport-security": "Strict-Transport-Security",
    "referrer-policy": "Referrer-Policy",
}


def minimise(raw: bytes) -> dict[str, str]:
    """Retain only typed security metadata; discard all arbitrary header values."""
    head, separator, _body = raw.partition(b"\r\n\r\n")
    if not separator or len(head) + 4 > LIMIT:
        raise NeedsReview("Needs review: incomplete or oversized HTTP response headers")
    lines = head.decode("iso-8859-1").split("\r\n")
    status = re.fullmatch(r"HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\r\n]*)?", lines[0])
    if status is None or int(status[1]) < 200 or len(lines) > 129:
        raise NeedsReview("Needs review: invalid HTTP status or header count")
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if not colon or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise NeedsReview("Needs review: malformed or folded HTTP header")
        if any(ord(char) < 32 and char != "\t" for char in value):
            raise NeedsReview("Needs review: HTTP header contains control characters")
        headers.setdefault(name.lower(), []).append(value.strip())
    cookies = {
        "issued": len(headers.get("set-cookie", [])),
        "without_secure": 0,
        "without_httponly": 0,
        "without_recognised_samesite": 0,
        "attributes_unverified": 0,
    }
    for cookie in headers.get("set-cookie", []):
        pair, *attributes = cookie.split(";")
        if "=" not in pair or '"' in cookie or not pair.partition("=")[0].strip():
            cookies["attributes_unverified"] += 1
            continue
        attrs = [value.strip().lower() for value in attributes]
        cookies["without_secure"] += int("secure" not in attrs)
        cookies["without_httponly"] += int("httponly" not in attrs)
        same = [value.partition("=")[2].strip() for value in attrs if value.startswith("samesite=")]
        cookies["without_recognised_samesite"] += int(
            len(same) != 1 or same[0] not in {"lax", "strict", "none"}
        )
    media = headers.get("content-type", [""])[0].split(";", 1)[0].strip().lower()
    family = (
        "html"
        if media in {"text/html", "application/xhtml+xml"}
        else "json"
        if media == "application/json" or media.endswith("+json")
        else "other"
        if media
        else "unknown"
    )
    states = {key: "not observed" if key not in headers else "observed" for key in HEADER_NAMES}
    for key, accepted in (
        ("x-frame-options", {"deny", "sameorigin"}),
        ("x-content-type-options", {"nosniff"}),
    ):
        if key in headers:
            states[key] = (
                "recognised value observed"
                if len(headers[key]) == 1 and headers[key][0].lower() in accepted
                else "value or multiplicity needs review"
            )
    locations = headers.get("location", [])
    redirect = (
        "not observed"
        if not locations
        else "multiple destinations; needs review"
        if len(locations) != 1
        else "absolute HTTP destination"
        if locations[0].lower().startswith("http://")
        else "absolute HTTPS destination"
        if locations[0].lower().startswith("https://")
        else "network-relative destination"
        if locations[0].startswith("//")
        else "relative destination"
        if locations[0].startswith(("/", "?", "#", "./", "../"))
        else "destination requires review"
    )
    metadata = {
        "format": FORMAT,
        "method": "HEAD",
        "path": "/",
        "status": int(status[1]),
        "declared_media": family,
        "headers": states,
        "cookies": cookies,
        "redirect": redirect,
        "authentication_challenge_observed": "www-authenticate" in headers,
    }
    observations = [
        PREFIX,
        f"HTTP status {status[1]}; declared media {family}. Literal-IP HEAD / only; virtual-host behaviour and other pages were not assessed.",
        "Privacy: page bodies, cookie names/values, redirect URLs, credentials and arbitrary header values are not retained.",
        "Scope: this response only. No redirects followed, HTTPS configuration tested, vulnerability confirmed, or score changed.",
    ]
    for name, title in HEADER_NAMES.items():
        interpretation = (
            "Presence is not proof of effective policy."
            if states[name] != "not observed"
            else "Review applicability on the intended HTTPS page; absence on this HEAD response is not a site-wide finding."
        )
        observations.append(f"{title}: {states[name]}. {interpretation}")
    observations.extend(
        [
            f"Response cookies: {cookies['issued']}; without Secure: {cookies['without_secure']}; without HttpOnly: {cookies['without_httponly']}.",
            f"Cookies without recognised SameSite: {cookies['without_recognised_samesite']}; attributes unverified: {cookies['attributes_unverified']}. Cookie purpose is unknown.",
            "Cookie precaution: review protections for sensitive cookies. A missing attribute does not establish session theft or a confirmed vulnerability.",
            f"Redirect: {redirect}; destination omitted and never followed. Redirect enforcement and HTTPS downgrade were not established.",
            "Authentication challenge: "
            + ("observed" if metadata["authentication_challenge_observed"] else "not observed")
            + ". This does not establish whether the application requires authentication.",
        ]
    )
    return {
        "raw_hex": json.dumps(metadata, sort_keys=True, ensure_ascii=True).encode().hex(),
        "observation": "\n".join(observations),
    }


def observation_parts(observation: str) -> list[str]:
    """Keep each metadata assertion separately citable within the model text cap."""
    if not observation.startswith(PREFIX + "\n"):
        return [observation]
    parts = observation.splitlines()
    if len(parts) > 20 or any(not part or len(part) > 200 for part in parts):
        raise NeedsReview("Needs review: website metadata exceeds its citation budget")
    return parts
