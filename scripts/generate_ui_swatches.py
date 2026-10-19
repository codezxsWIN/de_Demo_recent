"""Generate local SVG colour checks from Doors tokens; no dependencies or network.

Full-severity protanopia/deuteranopia matrices follow Machado, Oliveira and
Fernandes (2009). They operate on linear sRGB and approximate colour vision;
these swatches are not proof of individual perception or a clinical diagnosis.
CIELAB D65 distances are a reproducible design guard, not a WCAG criterion.
"""

import re
from itertools import combinations
from math import sqrt
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
TOKENS = ROOT / "vulnassess" / "ui" / "static" / "tokens.css"
OUTPUT = ROOT / "docs" / "ui" / "colour-check"
BANDS = ("critical", "high", "medium", "low")
MIN_DISTANCE = 15.0
MATRICES = {
    "reference": ((1.0, 0.0, 0.0), (0.0, 1.0, 0.0), (0.0, 0.0, 1.0)),
    "protanopia": (
        (0.152286, 1.052583, -0.204868),
        (0.114503, 0.786281, 0.099216),
        (-0.003882, -0.048116, 1.051998),
    ),
    "deuteranopia": (
        (0.367322, 0.860646, -0.227968),
        (0.280085, 0.672501, 0.047413),
        (-0.011820, 0.042940, 0.968881),
    ),
}


def read_tokens() -> dict[str, str]:
    if not TOKENS.is_file():
        raise FileNotFoundError(f"MISSING: {TOKENS}")
    text = TOKENS.read_text(encoding="utf-8")
    return dict(re.findall(r"--([a-z-]+):\s*(#[0-9a-fA-F]{6})\s*;", text))


def linear_rgb(colour: str) -> tuple[float, ...]:
    channels = [int(colour[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    return tuple(
        channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    )


def simulate(colour: str, mode: str) -> str:
    original = linear_rgb(colour)
    transformed = [
        min(1.0, max(0.0, sum(weight * channel for weight, channel in zip(row, original))))
        for row in MATRICES[mode]
    ]
    encoded = [
        12.92 * channel if channel <= 0.0031308 else 1.055 * channel ** (1 / 2.4) - 0.055
        for channel in transformed
    ]
    return "#" + "".join(f"{round(channel * 255):02x}" for channel in encoded)


def luminance(colour: str) -> float:
    return sum(
        weight * channel for weight, channel in zip((0.2126, 0.7152, 0.0722), linear_rgb(colour))
    )


def contrast(first: str, second: str) -> float:
    lighter, darker = sorted((luminance(first), luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def lab(colour: str) -> tuple[float, float, float]:
    linear = linear_rgb(colour)
    transform = (
        (0.4124564, 0.3575761, 0.1804375),
        (0.2126729, 0.7151522, 0.0721750),
        (0.0193339, 0.1191920, 0.9503041),
    )
    normalized = [
        sum(weight * channel for weight, channel in zip(row, linear)) / white
        for row, white in zip(transform, (0.95047, 1.0, 1.08883))
    ]
    converted = [
        value ** (1 / 3) if value > (6 / 29) ** 3 else value / (3 * (6 / 29) ** 2) + 4 / 29
        for value in normalized
    ]
    return (
        116 * converted[1] - 16,
        500 * (converted[0] - converted[1]),
        200 * (converted[1] - converted[2]),
    )


def distance(first: str, second: str) -> float:
    return sqrt(sum((left - right) ** 2 for left, right in zip(lab(first), lab(second))))


def validate_palette(tokens: dict[str, str]) -> list[str]:
    results = []
    for foreground in ("ink", "muted", *BANDS):
        for background in ("paper", "surface", "wash"):
            ratio = contrast(tokens[foreground], tokens[background])
            if ratio < 4.5:
                raise ValueError(f"{foreground}/{background}: contrast {ratio:.2f} is below 4.5")
    results.append("TEXT CONTRAST: all declared text/surface pairs >= 4.5:1")
    for mode in MATRICES:
        colours = {band: simulate(tokens[band], mode) for band in BANDS}
        nearest = min(
            distance(colours[first], colours[second]) for first, second in combinations(BANDS, 2)
        )
        if nearest < MIN_DISTANCE:
            raise ValueError(
                f"{mode}: minimum CIELAB distance {nearest:.2f} is below {MIN_DISTANCE}"
            )
        results.append(
            f"{mode}: minimum pairwise CIELAB distance {nearest:.2f} >= {MIN_DISTANCE:.0f}"
        )
    return results


def svg_document(tokens: dict[str, str], mode: str) -> str:
    document = ElementTree.Element(
        "svg",
        {
            "xmlns": "http://www.w3.org/2000/svg",
            "viewBox": "0 0 960 340",
            "width": "960",
            "height": "340",
            "role": "img",
            "aria-labelledby": "title desc",
        },
    )
    ElementTree.SubElement(
        document, "title", {"id": "title"}
    ).text = f"Doors severity colours: {mode}"
    ElementTree.SubElement(document, "desc", {"id": "desc"}).text = (
        "Locally generated token swatches. Severity is always named as well as coloured. "
        "Full-severity linear-sRGB simulation is approximate."
    )
    ElementTree.SubElement(
        document, "rect", {"width": "960", "height": "340", "fill": tokens["paper"]}
    )
    text_style = {"font-family": "Segoe UI, sans-serif", "fill": tokens["ink"]}
    ElementTree.SubElement(
        document, "text", {**text_style, "x": "32", "y": "42", "font-size": "24"}
    ).text = f"Doors / {mode}"
    for index, band in enumerate(BANDS):
        colour = simulate(tokens[band], mode)
        left = str(32 + index * 232)
        ElementTree.SubElement(
            document,
            "rect",
            {
                "x": left,
                "y": "72",
                "width": "200",
                "height": "104",
                "rx": "3",
                "fill": colour,
            },
        )
        ElementTree.SubElement(
            document, "text", {**text_style, "x": left, "y": "212", "font-size": "20"}
        ).text = band.capitalize()
        ElementTree.SubElement(
            document,
            "text",
            {
                "font-family": "Consolas, monospace",
                "fill": tokens["muted"],
                "x": left,
                "y": "242",
                "font-size": "16",
            },
        ).text = f"--{band}: {colour}"
    ElementTree.SubElement(
        document, "text", {**text_style, "x": "32", "y": "304", "font-size": "15"}
    ).text = "Simulation, not human-perception evidence. Labels remain authoritative."
    ElementTree.indent(document, space="  ")
    return ElementTree.tostring(document, encoding="unicode") + "\n"


def main() -> int:
    tokens = read_tokens()
    results = validate_palette(tokens)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for mode in MATRICES:
        path = OUTPUT / f"{mode}.svg"
        path.write_text(svg_document(tokens, mode), encoding="utf-8", newline="\n")
        print(f"GENERATED: {path.relative_to(ROOT).as_posix()}")
    for result in results:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
