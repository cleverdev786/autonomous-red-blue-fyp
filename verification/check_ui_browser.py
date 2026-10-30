"""UI-24/25 checks against synthetic, write-blocking fixtures in isolated Firefox.

Requires Mozilla marionette_driver and a running frontend dev server. No login,
real assessment URL, personal browser profile, or security worker is used.
"""

import argparse
import json
from pathlib import Path

from marionette_driver.by import By
from marionette_driver.keys import Keys
from marionette_driver.marionette import Marionette
from marionette_driver.wait import Wait

SURFACES = ("login", "overview", "dashboard", "setup", "workspace", "autonomous", "empty", "error", "loading")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("/tmp/mars-ui-acceptance"))
    parser.add_argument("--baseline", action="store_true", help="Capture the pre-fix fixture server on port 5174 without asserting its known defects")
    parser.add_argument("--interactions-only", action="store_true", help="Rerun keyboard and reduced-motion checks without the visual matrix")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    m = Marionette(
        port=2833 if args.interactions_only else 2831, bin="/usr/lib/firefox/firefox", startup_timeout=30,
        app_args=["--headless", "--remote-allow-system-access"],
        gecko_log=str(args.output / "firefox.log"),
        prefs={"browser.startup.page": 0, "browser.newtabpage.enabled": False},
    )
    results = {"browser": "Firefox", "cases": [], "keyboard": []}

    def read(script):
        return m.execute_script(script)

    def element(selector):
        return m.find_element(By.CSS_SELECTOR, selector)

    def wait(script):
        return Wait(m, timeout=15).until(lambda _: read(script))

    def load(surface, theme="light"):
        # Keep the fixture mounted; native option clicks exercise React change handlers.
        for index, value in ((1, surface), (2, theme)):
            m.find_element(By.XPATH, f"(//div[@class='qa-controls']//select)[{index}]/option[text()='{value}']").click()
        wait(f"return document.querySelector('#fixture') && document.documentElement.dataset.theme === '{theme}';")
        m.execute_async_script("const done=arguments[arguments.length-1]; Promise.allSettled(document.getAnimations().filter(a=>a.effect?.getComputedTiming().iterations!==Infinity).map(a=>a.finished)).then(()=>done(true));")

    def zoom(value):
        with m.using_context("chrome"):
            actual = read(f"gBrowser.selectedBrowser.browsingContext.fullZoom={value}; return gBrowser.selectedBrowser.browsingContext.fullZoom;")
        assert actual == value

    def capture(name):
        (args.output / f"{name}.png").write_bytes(m.screenshot(format="binary", full=True))

    def audit():
        element(".qa-controls>button").click()
        value = wait("const text=document.querySelector('#audit-result').textContent; return text.startsWith('{') ? JSON.parse(text) : null;")
        assert not value["violations"], value
        return value

    def geometry():
        value = read("return {width:innerWidth,height:innerHeight,dpr:devicePixelRatio,documentWidth:document.documentElement.scrollWidth,forced:matchMedia('(forced-colors: active)').matches,reduced:matchMedia('(prefers-reduced-motion: reduce)').matches};")
        assert value["documentWidth"] <= value["width"] + 1, value
        return value

    def dialog_contrast():
        # axe cannot always resolve backgrounds of overlapping fixed layers in Firefox.
        value = read(r"""
          const dialog=document.querySelector('[role=dialog]');
          const rgb=s=>s.match(/[\d.]+/g).slice(0,3).map(Number);
          const lum=c=>c.map(n=>n/255).map(n=>n<=.04045?n/12.92:((n+.055)/1.055)**2.4).reduce((s,n,i)=>s+n*[.2126,.7152,.0722][i],0);
          const bg=getComputedStyle(dialog).backgroundColor, b=lum(rgb(bg));
          return [...dialog.querySelectorAll('h2,p,code,a,summary')].filter(e=>e.getClientRects().length).map(e=>{
            const color=getComputedStyle(e).color,f=lum(rgb(color));
            return {tag:e.tagName,color,background:bg,ratio:(Math.max(f,b)+.05)/(Math.min(f,b)+.05)};
          });
        """)
        assert value and all(item["ratio"] >= 4.5 for item in value), value
        return value

    def key(value):
        # Send actual WebDriver keyboard input to the focused element.
        element(":focus").send_keys(value)

    try:
        m.start_session()
        port = 5174 if args.baseline else 5173
        m.navigate(f"http://127.0.0.1:{port}/dashboard/qa.html")
        wait("return document.querySelector('#fixture');")
        results["version"] = m.session_capabilities["browserVersion"]
        with m.using_context("chrome"):
            read("document.documentElement.style.setProperty('min-width','0px','important');")
        if args.baseline:
            for width in (390, 1440):
                m.set_window_rect(width=width, height=900)
                for surface in ("login", "dashboard", "workspace", "loading"):
                    for theme in ("light", "dark"):
                        load(surface, theme)
                        name = f"{surface}-{theme}-{width}"
                        capture(name)
                        results["cases"].append({"name": name, **geometry()})
            print("Baseline: 16 captures", flush=True)
            return
        for width in (() if args.interactions_only else (320, 390, 768, 1024, 1440, 1920)):
            m.set_window_rect(width=width, height=900)
            for surface in SURFACES:
                for theme in ("light", "dark"):
                    load(surface, theme)
                    data = geometry()
                    assert data["width"] == width, data
                    name = f"{surface}-{theme}-{width}"
                    accessibility = audit()
                    capture(name)
                    results["cases"].append({"name": name, **data, "axe": accessibility})
            print(f"{width}px: light/dark fixtures passed", flush=True)

        m.set_window_rect(width=1440, height=900)
        for surface in (() if args.interactions_only else SURFACES):
            for theme in ("light", "dark"):
                load(surface, theme)
                normal = geometry()
                zoom(2)
                data = geometry()
                assert abs(data["width"] * 2 - normal["width"]) <= 2, data
                name = f"{surface}-{theme}-zoom200"
                capture(name)
                results["cases"].append({"name": name, **data, "axe": audit()})
                zoom(1)

        m.set_pref("browser.display.document_color_use", 2)
        m.set_pref("ui.prefersReducedMotion", 1)
        for surface in (() if args.interactions_only else SURFACES):
            load(surface)
            data = geometry()
            assert data["forced"] and data["reduced"], data
            name = f"{surface}-forced-colors"
            capture(name)
            results["cases"].append({"name": name, **data, "axe": audit()})

        m.set_pref("browser.display.document_color_use", 1)
        m.set_pref("ui.prefersReducedMotion", 0)
        for width in (() if args.interactions_only else (390, 1440)):
            m.set_window_rect(width=width, height=900)
            for theme in ("light", "dark"):
                for surface, selector, expected in (
                    ("dashboard", '.filter-field:nth-child(2) [data-slot="select-trigger"]', "dropdown"),
                    ("workspace", '[aria-label="Inspect finding fixture-finding"]', "evidence-dialog"),
                ):
                    load(surface, theme)
                    element(selector).send_keys(Keys.SPACE if expected == "dropdown" else Keys.ENTER)
                    value = wait(f"const text=document.querySelector('#audit-result').textContent; if(!text.startsWith('{{')) return null; const result=JSON.parse(text); return result.surface==='{expected}' ? result : null;")
                    assert not value["violations"], value
                    name = f"{expected}-{theme}-{width}"
                    capture(name)
                    results["cases"].append({"name": name, **geometry(), "axe": value,
                        **({"computedContrast": dialog_contrast()} if expected == "evidence-dialog" else {})})
                    key(Keys.ESCAPE)

        m.set_pref("browser.display.document_color_use", 2)
        m.set_pref("ui.prefersReducedMotion", 1)

        m.set_window_rect(width=320, height=900)
        load("workspace")
        element('.red-findings .table-wrap').send_keys(Keys.ARROW_RIGHT)
        m.actions.sequence("key", "table-keyboard").key_down(Keys.ARROW_RIGHT).pause(300).key_up(Keys.ARROW_RIGHT).perform()
        wait("return document.querySelector('.red-findings .table-wrap').scrollLeft>0;")
        results["keyboard"].append({"journey": "labelled findings scroll region → ArrowRight reveals overflow columns", "passed": True})
        m.set_window_rect(width=1440, height=900)

        load("login")
        previous_theme = read("return document.documentElement.dataset.theme;")
        element(".login-utilities button").send_keys(Keys.ENTER)
        assert read("return document.documentElement.dataset.theme;") != previous_theme
        element(".login-utilities button").send_keys(Keys.TAB)
        assert read("return document.activeElement.id") == "login-username"
        key(Keys.TAB)
        assert read("return document.activeElement.id") == "login-password"
        key("fixture-password")
        key(Keys.TAB)
        key(Keys.ENTER)
        assert element("#login-password").get_attribute("type") == "text"
        key(Keys.ENTER)
        assert element("#login-password").get_attribute("type") == "password"
        focus = read("let e=document.activeElement,s=getComputedStyle(e); return {name:e.getAttribute('aria-label'),outline:s.outlineWidth,style:s.outlineStyle};")
        assert float(focus["outline"].replace("px", "")) >= 2 and focus["style"] != "none", focus
        results["keyboard"].append({"journey": "login theme → username → password → show/hide; focus retained", **focus})

        load("setup")
        element('[data-slot="select-trigger"]').send_keys(Keys.SPACE)
        key(Keys.ARROW_DOWN)
        key(Keys.ENTER)
        element('[role="radio"][value="manual"]').send_keys(Keys.SPACE)
        m.actions.sequence("key", "mode-keyboard").key_down(Keys.ARROW_RIGHT).pause(100).key_up(Keys.ARROW_RIGHT).perform()
        wait("return document.querySelector('[role=radio][value=autonomous]').getAttribute('aria-checked')==='true';")
        m.find_element(By.XPATH, "//button[text()='Review Standard scope']").send_keys(Keys.ENTER)
        wait("return document.querySelector('.red-scope-review');")
        results["keyboard"].append({"journey": "target Select Space/Down/Enter → mode ArrowRight → scope review Enter", "passed": True})

        load("workspace")
        trigger = element('[aria-label="Inspect finding fixture-finding"]')
        trigger.send_keys(Keys.ENTER)
        wait("return document.querySelector('[role=dialog] .evidence-content');")
        for _ in range(8):
            key(Keys.TAB)
            assert read("return !!document.activeElement.closest('[role=dialog]');")
        capture("evidence-forced-colors")
        key(Keys.ESCAPE)
        wait("return !document.querySelector('[role=dialog]');")
        assert read("return document.activeElement.getAttribute('aria-label')") == "Inspect finding fixture-finding"
        results["keyboard"].append({"journey": "finding Enter → evidence focus trap (8 Tabs) → Escape → exact trigger", "passed": True})

        element('.qa-controls>button:last-child').click()
        toast = wait("return document.querySelector('.notification') && getComputedStyle(document.querySelector('.notification')).animationName;")
        assert toast == "none", toast
        results["keyboard"].append({"journey": "reduced-motion notification has no animation", "passed": True})
    finally:
        (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        m.quit()
        m.cleanup()
    print(f"PASS: {len(results['cases'])} captures/audits and {len(results['keyboard'])} keyboard journeys")


if __name__ == "__main__":
    main()
