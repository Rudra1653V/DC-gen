#!/usr/bin/env python3
"""
Discord Token Generator - macOS / Apple Silicon (M1/M2/M3) build.

Fixes over upstream:
  * native arm64 chromedriver, matched to your installed Chrome
  * signature stripped before patching, then ad-hoc re-signed
    (arm64 SIGKILLs unsigned binaries; patching invalidates the old signature)
  * --disable-features=DisableLoadExtensionCommandLineSwitch  (Chrome 137+ killed --load-extension)
  * NopeCHA loaded from disk, no Chrome Web Store round-trip, no pyautogui
  * token pulled from localStorage after redirect (no captcha-required login failure)
  * no Windows-isms, no infinite loop, returns structured data
"""

from __future__ import annotations

import argparse
import json
import platform
import plistlib
import random
import shutil
import ssl
import string
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path

ssl._create_default_https_context = ssl._create_unverified_context

import requests
import tls_client
from colorama import Fore, Style, init

init(autoreset=True)

# ---------------------------------------------------------------- constants
ROOT         = Path(__file__).resolve().parent
EXT_DIR      = ROOT / "DKNLFMJAANFBLGFDFEBHIJALFMHMJJJO_0_6_1_0"
CHROME_APP   = Path("/Applications/Google Chrome.app")
DRIVER_CACHE = Path.home() / ".cache" / "uchromedriver"
UC_SUPPORT   = Path.home() / "Library" / "Application Support" / "undetected_chromedriver"
UC_DRIVER    = UC_SUPPORT / "undetected_chromedriver"
PROFILE_DIR  = Path.home() / ".discord-tokengen-profile"
TOKENS_FILE  = ROOT / "tokens.txt"
EVS_FILE     = ROOT / "evs.txt"

IS_MAC = sys.platform == "darwin"
IS_ARM = platform.machine() == "arm64"
PLATFORM_TAG = "mac-arm64" if IS_ARM else "mac-x64"

CFT_KNOWN     = "https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json"
CFT_MILESTONE = "https://googlechromelabs.github.io/chrome-for-testing/latest-versions-per-milestone-with-downloads.json"

CDC = b"cdc_"

BANNER = r"""
██████╗ ██╗██╗   ██╗███████╗██████╗
██╔══██╗██║██║   ██║██╔════╝██╔══██╗
██████╔╝██║██║   ██║█████╗  ██████╔╝
██╔══██╗██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
██║  ██║██║ ╚████╔╝ ███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
"""


# ---------------------------------------------------------------- logging
def _ts() -> str:
    return f"{Fore.LIGHTBLACK_EX}[{datetime.now():%H:%M:%S}]{Style.RESET_ALL}"


def log(msg: str, level: str = "info") -> None:
    color = {"info": Fore.BLUE, "ok": Fore.GREEN,
             "warn": Fore.YELLOW, "err": Fore.RED}[level]
    print(f"{_ts()} {color}{msg}{Style.RESET_ALL}", flush=True)


def rand(n: int = 12) -> str:
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


# ---------------------------------------------------------------- environment
def chrome_version() -> str | None:
    plist = CHROME_APP / "Contents" / "Info.plist"
    if not plist.exists():
        return None
    try:
        with open(plist, "rb") as fh:
            return plistlib.load(fh).get("CFBundleShortVersionString")
    except Exception:
        return None


def binary_arch(path: Path) -> str:
    try:
        out = subprocess.run(["file", "-b", str(path)],
                             capture_output=True, text=True).stdout
    except Exception:
        return "unknown"
    if "arm64" in out:
        return "arm64"
    if "x86_64" in out:
        return "x86_64"
    return "unknown"


def rosetta_present() -> bool:
    if not IS_ARM:
        return True
    return subprocess.run(["arch", "-x86_64", "/usr/bin/true"],
                          capture_output=True).returncode == 0


def preflight() -> list[str]:
    problems = []
    if not IS_MAC:
        log("not macOS - continuing anyway", "warn")
    if not CHROME_APP.exists():
        problems.append("Google Chrome is not installed in /Applications")
    if not EXT_DIR.exists():
        problems.append(f"missing extension folder next to the script: {EXT_DIR.name}")
    if shutil.which("codesign") is None:
        problems.append("codesign missing - run: xcode-select --install")
    if sys.version_info >= (3, 13):
        problems.append(f"Python {sys.version_info.major}.{sys.version_info.minor} - 3.11 recommended")
    return problems


# ---------------------------------------------------------------- driver download
def _pick(node: dict, tag: str) -> str | None:
    for d in node.get("downloads", {}).get("chromedriver", []):
        if d["platform"] == tag:
            return d["url"]
    return None


def fetch_chromedriver() -> Path:
    """Download the arm64 chromedriver matching the installed Chrome major."""
    ver = chrome_version()
    if not ver:
        raise SystemExit("could not determine Chrome version")
    major = ver.split(".")[0]

    target = DRIVER_CACHE / f"chromedriver-{ver}-{PLATFORM_TAG}"
    if target.exists():
        return target

    log(f"Chrome {ver} detected - resolving {PLATFORM_TAG} chromedriver")

    url = None
    try:
        meta = requests.get(CFT_KNOWN, timeout=30).json()
        hits = [v for v in meta["versions"]
                if v["version"].split(".")[0] == major and "downloads" in v]
        if hits:
            url = _pick(hits[-1], PLATFORM_TAG)
    except Exception as e:
        log(f"known-good lookup failed ({e})", "warn")

    if not url:
        meta = requests.get(CFT_MILESTONE, timeout=30).json()
        entry = meta.get("milestones", {}).get(major)
        if entry:
            url = _pick(entry, PLATFORM_TAG)

    if not url:
        raise SystemExit(f"no chromedriver published for Chrome {major} / {PLATFORM_TAG}")

    DRIVER_CACHE.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        zp = Path(td) / "cd.zip"
        zp.write_bytes(requests.get(url, timeout=180).content)
        with zipfile.ZipFile(zp) as z:
            z.extractall(td)
        src = next((p for p in Path(td).rglob("chromedriver") if p.is_file()), None)
        if not src:
            raise SystemExit("chromedriver not found inside the downloaded archive")
        shutil.copy2(src, target)

    target.chmod(0o755)
    subprocess.run(["xattr", "-cr", str(target)], capture_output=True)
    log(f"chromedriver downloaded ({binary_arch(target)})", "ok")
    return target


# ---------------------------------------------------------------- driver prep
def _self_test(path: Path) -> bool:
    """Run the driver directly so a SIGKILL surfaces before Selenium sees it."""
    try:
        r = subprocess.run([str(path), "--version"],
                           capture_output=True, text=True, timeout=30)
    except Exception as e:
        log(f"driver self-test errored: {e}", "err")
        return False
    if r.returncode != 0:
        log(f"driver self-test failed (rc={r.returncode})", "err")
        return False
    log(f"driver self-test ok: {r.stdout.strip()}")
    return True


def _strip_signature(path: Path) -> None:
    """
    Remove the embedded signature while the binary is still untouched.

    Doing this before patching matters: once bytes change, the signature's code
    limit no longer matches the file and codesign bails with
    'main executable failed strict validation'.
    """
    subprocess.run(["codesign", "--remove-signature", str(path)],
                   capture_output=True, text=True)


def _ad_hoc_sign(path: Path) -> bool:
    r = subprocess.run(["codesign", "--force", "--sign", "-",
                        "--timestamp=none", str(path)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        log(f"codesign failed: {r.stderr.strip()}", "err")
        return False
    v = subprocess.run(["codesign", "--verify", str(path)],
                       capture_output=True, text=True)
    if v.returncode != 0:
        log(f"signature verification failed: {v.stderr.strip()}", "err")
        return False
    return True


def _fallback_pristine(pristine: Path) -> Path:
    log("falling back to the pristine, unpatched driver", "warn")
    shutil.copy2(pristine, UC_DRIVER)
    UC_DRIVER.chmod(0o755)
    subprocess.run(["xattr", "-cr", str(UC_DRIVER)], capture_output=True)
    if _self_test(UC_DRIVER):
        return UC_DRIVER
    raise SystemExit("pristine chromedriver will not execute either")


def prepare_driver(patch: bool = True) -> Path:
    """
    Produce a runnable, correctly-signed chromedriver.

    Always starts from the cached pristine download, so the result is
    deterministic no matter what a previous run left on disk.
    """
    pristine = fetch_chromedriver()
    want = "arm64" if IS_ARM else "x86_64"
    UC_SUPPORT.mkdir(parents=True, exist_ok=True)

    shutil.copy2(pristine, UC_DRIVER)
    UC_DRIVER.chmod(0o755)
    subprocess.run(["xattr", "-cr", str(UC_DRIVER)], capture_output=True)

    if not patch:
        if _self_test(UC_DRIVER):
            log("pristine driver works (unpatched)")
            return UC_DRIVER
        raise SystemExit("pristine chromedriver will not execute")

    # strip while the binary is still valid, before any bytes move
    _strip_signature(UC_DRIVER)

    data = UC_DRIVER.read_bytes()
    if CDC not in data:
        log("no cdc_ identifiers found in the binary", "warn")
    else:
        # same-length swap keeps every offset and the code limit intact
        replacement = "".join(random.choice(string.ascii_letters)
                              for _ in range(len(CDC)))
        UC_DRIVER.write_bytes(data.replace(CDC, replacement.encode()))
        log("patched cdc_ identifiers")

    if not _ad_hoc_sign(UC_DRIVER):
        return _fallback_pristine(pristine)

    if not _self_test(UC_DRIVER):
        return _fallback_pristine(pristine)

    log(f"driver ready and signed ({want})")
    return UC_DRIVER


def launch(headless: bool = False, profile: Path | None = None,
           proxy: str | None = None, patch: bool = True):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    driver_path = prepare_driver(patch=patch)

    opts = Options()
    opts.add_argument("--no-first-run")
    opts.add_argument("--no-default-browser-check")
    opts.add_argument("--hide-crash-restore-bubble")
    opts.add_argument("--disable-popup-blocking")
    opts.add_argument("--disable-infobars")
    opts.add_argument("--lang=en-US")
    opts.add_argument("--window-size=1400,950")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    # Chrome 137 removed --load-extension; this switch restores it.
    opts.add_argument("--disable-features=DisableLoadExtensionCommandLineSwitch")
    opts.add_argument(f"--load-extension={EXT_DIR}")
    if profile:
        opts.add_argument(f"--user-data-dir={profile}")
    if headless:
        opts.add_argument("--headless=new")
    if proxy:
        opts.add_argument(f"--proxy-server={proxy}")
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)
    opts.add_experimental_option("prefs", {"intl.accept_languages": "en-US,en"})

    driver = webdriver.Chrome(service=Service(executable_path=str(driver_path)),
                              options=opts)
    # runs before any page script, so it must be registered immediately
    driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
        "source": "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
    })
    return driver


# ---------------------------------------------------------------- page helpers
def type_into(driver, name: str, value: str, timeout: int = 20):
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    el = WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located((By.NAME, name)))
    el.clear()
    el.send_keys(value)
    return el


def set_dob(driver, year: int = 2000, month: int = 9, day: int = 20) -> str:
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.action_chains import ActionChains
    from selenium.webdriver.support.ui import WebDriverWait, Select
    from selenium.webdriver.support import expected_conditions as EC

    names = ["January", "February", "March", "April", "May", "June",
             "July", "August", "September", "October", "November", "December"]

    # A) Discord ships named text inputs on some builds
    try:
        if driver.find_elements(By.NAME, "date_of_birth_month"):
            type_into(driver, "date_of_birth_month", f"{month:02d}", timeout=5)
            type_into(driver, "date_of_birth_day", f"{day:02d}", timeout=5)
            type_into(driver, "date_of_birth_year", str(year), timeout=5)
            return "named inputs"
    except Exception:
        pass

    # B) native <select>
    try:
        sels = WebDriverWait(driver, 5).until(
            EC.presence_of_all_elements_located((By.TAG_NAME, "select")))
        if len(sels) >= 3:
            Select(sels[0]).select_by_visible_text(names[month - 1])
            Select(sels[1]).select_by_visible_text(str(day))
            Select(sels[2]).select_by_visible_text(str(year))
            return "native selects"
    except Exception:
        pass

    # C) React comboboxes
    boxes = driver.find_elements(By.XPATH, '//*[@role="combobox"]')
    if len(boxes) >= 3:
        for idx, text in enumerate([names[month - 1], str(day), str(year)]):
            ActionChains(driver).move_to_element(boxes[idx]).click().perform()
            time.sleep(0.4)
            ActionChains(driver).send_keys(text).perform()
            time.sleep(0.4)
            opt = WebDriverWait(driver, 5).until(EC.element_to_be_clickable(
                (By.XPATH, f'//*[@role="option"][normalize-space(.)="{text}"]')))
            driver.execute_script("arguments[0].scrollIntoView(true);", opt)
            driver.execute_script("arguments[0].click();", opt)
            time.sleep(0.3)
        return "react comboboxes"

    raise RuntimeError("could not locate the date-of-birth widgets")


def accept_checkboxes(driver) -> int:
    from selenium.webdriver.common.by import By
    clicked = 0
    for cb in driver.find_elements(By.XPATH, "//input[@type='checkbox']"):
        try:
            if cb.is_selected():
                continue
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", cb)
            time.sleep(0.15)
            driver.execute_script("arguments[0].click();", cb)
            clicked += 1
        except Exception:
            pass
    return clicked


def token_from_browser(driver) -> str | None:
    try:
        raw = driver.execute_script("return window.localStorage.getItem('token');")
    except Exception:
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return raw.strip('"')


def token_via_http(email: str, password: str) -> str | None:
    headers = {
        "content-type": "application/json",
        "user-agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/120.0.0.0 Safari/537.36"),
    }
    try:
        r = requests.post("https://discord.com/api/v9/auth/login",
                          json={"login": email, "password": password,
                                "undelete": "false"},
                          headers=headers, timeout=30)
    except Exception as e:
        log(f"login request failed: {e}", "err")
        return None
    if r.status_code == 200:
        return r.json().get("token")
    if "captcha-required" in r.text:
        log("login endpoint demanded a captcha", "warn")
    else:
        log(f"login returned {r.status_code}: {r.text[:160]}", "warn")
    return None


def preflight_ratelimit() -> float:
    """The upstream pre-submit probe. Returns seconds to wait."""
    try:
        client = tls_client.Session(client_identifier="chrome_120")
        client.headers = {
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Origin": "https://discord.com",
            "Referer": "https://discord.com/register",
            "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/120.0.0.0 Safari/537.36"),
            "X-Discord-Locale": "en-US",
            "X-Super-Properties": (
                "eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIs"
                "InN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1v"
                "emlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwXzE1XzcpIEFw"
                "cGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xMjAu"
                "MC4wLjAgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEyMC4wLjAu"
                "MCIsIm9zX3ZlcnNpb24iOiIxMC4xNS43IiwicmVsZWFzZV9jaGFubmVsIjoic3Rh"
                "YmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MjQwMDAwLCJjbGllbnRfZXZlbnRf"
                "c291cmNlIjpudWxsfQ=="),
        }
        body = {
            "email": f"{rand(9)}{random.randint(100000, 999999)}@gmail.com",
            "password": "Ultimate12$$",
            "date_of_birth": "2000-09-20",
            "username": rand(10),
            "consent": True,
            "captcha_service": "hcaptcha",
            "global_name": "ultimate",
            "captcha_key": None,
            "invite": None,
            "promotional_email_opt_in": False,
            "gift_code_sku_id": None,
        }
        r = client.post("https://discord.com/api/v9/auth/register", json=body)
        if "rate limited" in r.text:
            return float(r.json().get("retry_after", 1))
    except Exception as e:
        log(f"ratelimit probe failed: {e}", "warn")
    return 1.0


# ---------------------------------------------------------------- one account
def create_account(headless: bool = False, proxy: str | None = None,
                   patch: bool = True, keep_open: bool = False,
                   fresh_profile: bool = False) -> dict | None:
    from selenium.common.exceptions import TimeoutException
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

    email = f"{rand(10)}@gmail.com"
    password = rand(16)
    username = rand(12)

    profile = Path(tempfile.mkdtemp(prefix="ucprof-")) if fresh_profile else PROFILE_DIR
    driver = None
    try:
        driver = launch(headless, profile, proxy, patch)
        log(f"browser up - registering {email}")

        driver.get("https://discord.com/register")
        WebDriverWait(driver, 40).until(EC.presence_of_element_located((By.NAME, "email")))

        type_into(driver, "email", email)
        for field, value in (("global_name", "Lunarxterm"), ("username", username)):
            try:
                type_into(driver, field, value, timeout=8)
            except Exception:
                log(f"{field} field not present, skipping", "warn")
        type_into(driver, "password", password)

        log(f"date of birth via {set_dob(driver)}")
        log(f"ticked {accept_checkboxes(driver)} checkbox(es)")

        wait = preflight_ratelimit()
        if wait > 1:
            log(f"rate limited, sleeping {wait:.0f}s", "warn")
            time.sleep(wait)

        driver.find_element(By.XPATH, '//button[@type="submit"]').click()
        log("submitted - waiting for NopeCHA to clear hCaptcha (up to 5 min)")

        WebDriverWait(driver, 300).until(EC.url_contains("discord.com/channels/@me"))
        log("through the captcha and logged in", "ok")
        time.sleep(2)

        token = token_from_browser(driver)
        if token:
            log("token read straight from localStorage", "ok")
        else:
            log("localStorage empty, falling back to the login endpoint", "warn")
            token = token_via_http(email, password)

        if not token:
            return None

        with open(TOKENS_FILE, "a") as fh:
            fh.write(token + "\n")
        with open(EVS_FILE, "a") as fh:
            fh.write(f"{email}:{password}:{token}\n")

        return {"email": email, "password": password, "token": token,
                "at": datetime.now().isoformat(timespec="seconds")}

    except TimeoutException:
        log("timed out waiting for the redirect", "err")
        return None
    except Exception as e:
        log(f"failed on {email}: {type(e).__name__}: {e}", "err")
        return None
    finally:
        if driver:
            if keep_open and not headless:
                try:
                    input(f"{_ts()} press Enter to close the browser... ")
                except EOFError:
                    pass
            try:
                driver.quit()
            except Exception:
                pass


# ---------------------------------------------------------------- modes
def do_check(proxy, patch):
    log("running environment check")
    problems = preflight()
    if problems:
        for p in problems:
            log(p, "err")
        raise SystemExit(1)

    ver = chrome_version()
    log(f"macOS {platform.mac_ver()[0]} / {platform.machine()}")
    log(f"Chrome {ver}")
    if IS_ARM and not rosetta_present():
        log("Rosetta 2 not installed (not required with the arm64 driver, "
            "but run: softwareupdate --install-rosetta)", "warn")

    driver = launch(False, PROFILE_DIR, proxy, patch)
    try:
        driver.get("https://nopecha.com/demo/hcaptcha")
        log("a browser window is open on the NopeCHA hCaptcha demo")
        log("check the puzzle icon in Chrome's toolbar - NopeCHA should be there")
        log("it should tick the checkbox by itself within ~30s")
        input(f"{_ts()} press Enter when done... ")
    finally:
        driver.quit()


def do_setup(patch):
    """Open a browser with the persistent profile so NopeCHA can be configured."""
    driver = launch(False, PROFILE_DIR, None, patch)
    try:
        driver.get("https://nopecha.com/setup")
        log("browser opened on the NopeCHA setup page")
        log("if you have a NopeCHA API key, paste it into the extension popup now -")
        log("it is stored in this profile and reused on every future run.")
        input(f"{_ts()} press Enter to close... ")
    finally:
        driver.quit()


def main():
    ap = argparse.ArgumentParser(description="Discord token generator (macOS build)")
    ap.add_argument("-n", "--count", type=int, default=1,
                    help="how many accounts to make (default 1)")
    ap.add_argument("--infinite", action="store_true", help="loop forever")
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--proxy", default=None, help="http://user:pass@ip:port")
    ap.add_argument("--no-patch", action="store_true",
                    help="use a pristine unpatched driver (diagnostic)")
    ap.add_argument("--keep-open", action="store_true",
                    help="leave the browser open on failure so you can look")
    ap.add_argument("--fresh-profile", action="store_true",
                    help="throwaway Chrome profile per run")
    ap.add_argument("--check", action="store_true", help="environment + extension check")
    ap.add_argument("--setup", action="store_true", help="configure the NopeCHA extension")
    args = ap.parse_args()

    print(Fore.MAGENTA + BANNER + Style.RESET_ALL)
    print(f"{Fore.LIGHTBLACK_EX}  macOS/arm64 build - upstream by Anomus.LY, modified by Uzif{Style.RESET_ALL}\n")

    if args.check:
        return do_check(args.proxy, not args.no_patch)
    if args.setup:
        return do_setup(not args.no_patch)

    problems = preflight()
    for p in problems:
        log(p, "err")
    if problems:
        raise SystemExit(1)

    made, failed = 0, 0
    i = 0
    while args.infinite or i < args.count:
        i += 1
        log(f"[{i}] starting account")
        acct = create_account(headless=args.headless, proxy=args.proxy,
                              patch=not args.no_patch, keep_open=args.keep_open,
                              fresh_profile=args.fresh_profile)
        if acct:
            made += 1
            log(f"[{i}] OK  {acct['email']}", "ok")
            print(f"        {Fore.LIGHTBLACK_EX}{acct['token']}{Style.RESET_ALL}\n")
        else:
            failed += 1

    log(f"done - {made} created, {failed} failed. see {TOKENS_FILE.name}", "ok")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("interrupted", "warn")