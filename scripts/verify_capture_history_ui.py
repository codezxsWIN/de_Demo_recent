"""Optional isolated-browser smoke check against a synthetic localhost workbench.

Requires an already installed Playwright Chromium runtime. Never scans a target.
Usage: python scripts/verify_capture_history_ui.py http://127.0.0.1:PORT OUTPUT_DIR
"""

import argparse
import json
from importlib import import_module
from pathlib import Path
from types import ModuleType
from urllib.parse import urlsplit


def load_browser_api(parser: argparse.ArgumentParser) -> ModuleType:
    """Resolve optional, already installed tooling without provisioning it."""
    try:
        return import_module("playwright.sync_api")
    except ModuleNotFoundError as error:
        if error.name not in {"playwright", "playwright.sync_api"}:
            raise
        parser.error(
            "MISSING optional browser prerequisite: playwright.sync_api; "
            "a human must provide approved Playwright and its Chromium runtime. "
            "Nothing was installed or downloaded."
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin")
    parser.add_argument("output", type=Path)
    parser.add_argument("--channel", choices=("chromium", "chrome", "msedge"), default="chromium")
    args = parser.parse_args()
    parsed = urlsplit(args.origin)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username
    ):
        parser.error("Use a plain http://127.0.0.1:PORT origin for the synthetic workbench")
    browser_api = load_browser_api(parser)

    args.output.mkdir(parents=True, exist_ok=True)
    with browser_api.sync_playwright() as runtime:
        browser = runtime.chromium.launch(headless=True, channel=args.channel)
        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        context.route(
            "**/*",
            lambda route: (
                route.continue_()
                if route.request.url.startswith(args.origin + "/")
                else route.abort()
            ),
        )
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on(
            "console",
            lambda message: (
                errors.append(message.text) if message.type in ("error", "warning") else None
            ),
        )
        response = page.goto(args.origin + "/captures")
        assert response and response.status == 200
        assert page.get_by_role("heading", name="Saved assessments", exact=True).count() == 1
        page.locator(".history a").first.click()
        assert page.get_by_role("heading", name="Evidence-only assessment").count() == 1
        assert page.get_by_text("Collection completed", exact=True).count() == 1
        page.keyboard.press("Tab")
        assert page.evaluate("document.activeElement !== document.body")
        page.locator("summary").filter(has_text="Context and supporting evidence").click()
        for width in (320, 768, 1024, 1440):
            page.set_viewport_size({"width": width, "height": 1000})
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), width
        page.screenshot(path=str(args.output / "synthetic-capture-review.png"), full_page=True)
        assert errors == [], errors
        print(
            json.dumps(
                {
                    "status": "passed",
                    "widths": [320, 768, 1024, 1440],
                    "console_errors": errors,
                    "url": page.url,
                }
            )
        )
        browser.close()


if __name__ == "__main__":
    main()
