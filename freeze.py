"""Freeze the dashboard to static HTML for GitHub Pages.

The Overview and Insights pages are pure server-rendered SVG/CSS driven by
``models/metrics.json``, so they work perfectly as static files. The Predict
page is rendered in "static demo" mode (live inference disabled, with a notice).

Output goes to ``docs/`` (GitHub Pages source). Run after training:

    python freeze.py

Requires ``models/metrics.json`` to exist (run ``train.py`` first) so the real
metrics are baked into the static pages.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from src.config import Paths
from src.dashboard import app as appmod

DOCS = Paths.root / "docs"
PAGES = {"/": "index.html", "/predict": "predict.html", "/insights": "insights.html"}

# url_for(...) emits absolute paths; rewrite them for relative static hosting.
REWRITES = [
    ('href="/predict"', 'href="predict.html"'),
    ('href="/insights"', 'href="insights.html"'),
    ('href="/"', 'href="index.html"'),
    ('href="/static/', 'href="static/'),
    ('src="/static/', 'src="static/'),
]


def main() -> None:
    if not Paths.metrics.exists():
        raise SystemExit("models/metrics.json not found — run train.py first.")

    # Reload artifacts so the frozen pages reflect the latest training run, and
    # switch the app into static-demo mode (disables the live Predict form).
    appmod.ARTIFACTS = appmod.load_artifacts()
    appmod.app.config["STATIC_DEMO"] = True

    DOCS.mkdir(exist_ok=True)
    (DOCS / "static").mkdir(exist_ok=True)
    shutil.copy(Paths.root / "src" / "dashboard" / "static" / "style.css",
                DOCS / "static" / "style.css")
    # Tell GitHub Pages not to run the output through Jekyll.
    (DOCS / ".nojekyll").write_text("")

    client = appmod.app.test_client()
    for route, filename in PAGES.items():
        resp = client.get(route)
        if resp.status_code != 200:
            raise SystemExit(f"{route} returned {resp.status_code}")
        html = resp.get_data(as_text=True)
        for old, new in REWRITES:
            html = html.replace(old, new)
        (DOCS / filename).write_text(html, encoding="utf-8")
        print(f"[freeze] wrote docs/{filename} ({len(html):,} bytes)")

    print(f"[freeze] Static demo written to {DOCS}")


if __name__ == "__main__":
    main()
