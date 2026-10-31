"""Exercise history deletion on write-blocking fixtures, never real assessments.

Run the frontend dev server on port 5173 and use Mozilla marionette_driver,
as documented in tasks/ui_acceptance_report.md.
"""

import json
from pathlib import Path

from marionette_driver.by import By
from marionette_driver.keys import Keys
from marionette_driver.marionette import Marionette
from marionette_driver.wait import Wait


def main():
    output = Path("/tmp/mars-delete-ui")
    output.mkdir(exist_ok=True)
    browser = Marionette(
        port=2840, bin="/usr/lib/firefox/firefox",
        app_args=["--headless", "--remote-allow-system-access"],
        gecko_log=str(output / "firefox.log"),
    )
    results = []

    def read(script):
        return browser.execute_script(script)

    def element(selector):
        return browser.find_element(By.CSS_SELECTOR, selector)

    def wait(script):
        return Wait(browser, timeout=15).until(lambda _: read(script))

    def load(surface="history-delete", theme="light"):
        browser.navigate(f"http://127.0.0.1:5173/dashboard/qa.html?surface={surface}&theme={theme}")
        wait("return document.querySelectorAll('.red-history tbody tr').length===3;")

    def confirm():
        element(".history-delete-dialog .red-workspace-actions>button:last-child").click()
        wait("return !document.querySelector('[role=dialog]');")

    try:
        browser.start_session()
        with browser.using_context("chrome"):
            read("document.documentElement.style.setProperty('min-width','0px','important');")
        for width in (390, 1440):
            browser.set_window_rect(width=width, height=900)
            for theme in ("light", "dark"):
                load(theme=theme)
                assert not element('[aria-label="Select Assessment 01"]').is_enabled()
                element('[aria-label="Select Assessment 02"]').click()
                element(".history-selection-toolbar button").click()
                wait("return document.querySelector('.history-delete-dialog');")
                assert read("return document.activeElement.textContent;") == "Cancel"
                audit = wait("let t=document.querySelector('#audit-result').textContent;if(!t.startsWith('{'))return null;let r=JSON.parse(t);return r.surface==='history-delete-dialog'?r:null;")
                assert not audit["violations"], audit
                (output / f"confirm-{theme}-{width}.png").write_bytes(browser.screenshot(format="binary", full=False))
                element(":focus").send_keys(Keys.ESCAPE)
                assert read("return document.activeElement.textContent;") == "Delete selected record"
                assert read("return document.querySelectorAll('.red-history tbody tr').length;") == 3
                element(".history-selection-toolbar button").click()
                confirm()
                assert read("return document.querySelectorAll('.red-history tbody tr').length;") == 2
                load(theme=theme)
                element('[aria-label="Select all deletable records on this page"]').click()
                assert read("return [...document.querySelectorAll('.red-history tbody input')].filter(x=>x.checked).length;") == 2
                element(".history-selection-toolbar button").click()
                confirm()
                assert read("return document.querySelectorAll('.red-history tbody tr').length;") == 1
                assert read("return document.documentElement.scrollWidth<=innerWidth;")
                results.append({"width": width, "theme": theme, "single": True, "bulk": True,
                                "cancel": True, "activeDenied": True, "focusReturn": True, "axe": audit})
        load("history-delete-error")
        element('[aria-label="Select all deletable records on this page"]').click()
        element(".history-selection-toolbar button").click()
        element(".history-delete-dialog .red-workspace-actions>button:last-child").click()
        wait("return document.querySelector('.history-delete-dialog [role=alert]');")
        assert read("return document.querySelectorAll('.red-history tbody tr').length;") == 3
        assert read("return [...document.querySelectorAll('.red-history tbody input')].filter(x=>x.checked).length;") == 2
    finally:
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        browser.quit()
        browser.cleanup()
    print("PASS: single/bulk/cancel/focus in both themes at 390/1440; failure retains selection")


if __name__ == "__main__":
    main()
