"""
ingotus/core/screenshooter.py

Visual Screenshot Capturer.
Captures screenshots of active web hosts using Playwright or headless Chrome/Edge CLI as fallback.
Stores images in output/screenshots/<target_slug>/<host>.png.
"""

import os
import shutil
import subprocess
from typing import Optional

def capture_screenshot(url: str, output_path: str) -> bool:
    """
    Attempts to take a screenshot using Playwright or system browser CLI.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # 1. Try Playwright Python API if installed
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_viewport_size({"width": 1280, "height": 800})
            page.goto(url, timeout=10000, wait_until="domcontentloaded")
            page.screenshot(path=output_path)
            browser.close()
            return True
    except Exception:
        pass

    # 2. Try Chrome / Edge / Chromium CLI Fallback
    browsers = ["chrome", "msedge", "chromium", "google-chrome"]
    for b in browsers:
        b_path = shutil.which(b)
        if b_path:
            try:
                cmd = [
                    b_path,
                    "--headless",
                    "--disable-gpu",
                    "--hide-scrollbars",
                    f"--screenshot={output_path}",
                    "--window-size=1280,800",
                    url
                ]
                subprocess.run(cmd, timeout=12, capture_output=True)
                if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                    return True
            except Exception:
                continue

    return False
