"""Optional isolated-browser smoke check against a synthetic localhost workbench.

Requires an already installed Playwright Chromium runtime. Never scans a target.
Usage: python scripts/verify_capture_history_ui.py http://127.0.0.1:PORT OUTPUT_DIR
"""

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit


def main():
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
    from playwright.sync_api import sync_playwright

    args.output.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as runtime:
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
