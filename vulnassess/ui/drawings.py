"""Local line drawings; role mappings are presentation, never scoring inputs."""

from html import escape
from pathlib import Path

from vulnassess.errors import ConfigError

DRAWINGS = Path(__file__).resolve().parent / "static" / "buildings"
ROLE_BUILDINGS = {
    "database": "vault",
    "web_frontend": "office",
    "app_server": "office",
    "domain_controller": "vault",
    "mail": "office",
    "file_share": "vault",
    "iot_embedded": "cabinet",
    "workstation": "office",
    "network_device": "cabinet",
    "unknown": "shed",
}
BAND_CLASSES = {band: f"band-{band.lower()}" for band in ("Critical", "High", "Medium", "Low")}


def drawing(name: str) -> str:
    if name not in {*ROLE_BUILDINGS.values(), "door"}:
        raise ConfigError(f"unknown UI drawing {name!r}")
    path = DRAWINGS / f"{name}.svg"
    if not path.is_file():
        raise ConfigError(f"MISSING: UI drawing {path}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ConfigError(f"cannot read UI drawing {path}") from error


def building(role: str) -> str:
    if role not in ROLE_BUILDINGS:
        raise ConfigError(f"no UI building mapped for stored role {role!r}")
    return drawing(ROLE_BUILDINGS[role])


def door(band: str | None, finding_id: str | None = None) -> str:
    if band is not None and band not in BAND_CLASSES:
        raise ConfigError(f"no UI badge mapped for stored band {band!r}")
    label = band if band is not None else "Not scored"
    band_class = BAND_CLASSES.get(band or "", "band-unscored")
    identity = "" if finding_id is None else f' data-finding-id="{escape(finding_id)}"'
    return (
        f'<span class="finding-door {band_class}"{identity}>'
        + drawing("door")
        + f'<span class="band-label">{escape(label)}</span></span>'
    )


def legend() -> str:
    descriptions = {
        "shed": "Unknown role",
        "office": "Web, application, mail and workstation roles",
        "vault": "Database, directory and file storage roles",
        "cabinet": "Embedded and network device roles",
    }
    figures = "".join(
        '<figure class="drawing-sample">'
        + drawing(name)
        + f"<figcaption><strong>{name.capitalize()}</strong><span>{description}</span></figcaption>"
        + "</figure>"
        for name, description in descriptions.items()
    )
    badges = "".join(door(band) for band in BAND_CLASSES)
    return (
        '<section class="drawing-legend" aria-labelledby="legend-heading">'
        '<div class="section-heading"><h2 id="legend-heading">Buildings &amp; doors</h2></div>'
        '<p class="legend-copy">A building represents a host; its shape follows the recorded role. '
        "Each door is a finding; its badge names the stored severity band.</p>"
        f'<div class="drawing-samples">{figures}</div>'
        f'<div class="badge-legend" aria-label="Severity badge legend">{badges}</div>'
        "</section>"
    )
