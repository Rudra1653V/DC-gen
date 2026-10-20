#!/usr/bin/env python3
"""
Discord Token Generator - macOS / Apple Silicon (M1/M2/M3) build.
hCaptcha via NoneCap or hektCaptcha. Phone-wall aware, with API-first verification.

Phone wall notes:
  * a locked account STILL has a valid token - it just cannot chat. Never discard it.
  * whether the wall appears is mostly IP reputation. Residential/mobile beats DC/proxy.
  * verification runs through Discord's REST endpoints via in-page fetch, so the
    logged-in session and the solver extension handle auth/captcha. UI is the fallback.
  * Discord allows one account per number AT A TIME - --release-phone frees it for reuse.

    python gen.py --list
    python gen.py --solver nonecap --install-ext
    python gen.py --solver nonecap --check
    python gen.py --solver nonecap -n 5
    python gen.py --solver nonecap --sms-provider smspool --sms-key KEY \
                  --release-phone -n 5
    python gen.py --verify-locked --sms-provider smspool --sms-key KEY --release-phone
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import plistlib
import random
import re
import shutil
import ssl
import string
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ssl._create_default_https_context = ssl._create_unverified_context

import requests
import tls_client
from colorama import Fore, Style, init

init(autoreset=True)

# ---------------------------------------------------------------- constants
ROOT         = Path(__file__).resolve().parent
CHROME_APP   = Path("/Applications/Google Chrome.app")
DRIVER_CACHE = Path.home() / ".cache" / "uchromedriver"
UC_SUPPORT   = Path.home() / "Library" / "Application Support" / "undetected_chromedriver"
UC_DRIVER    = UC_SUPPORT / "undetected_chromedriver"
PROFILE_DIR  = Path.home() / ".discord-tokengen-profile"
TOKENS_FILE  = ROOT / "tokens.txt"
EVS_FILE     = ROOT / "evs.txt"
LOCKED_FILE  = ROOT / "locked.txt"
FAILSHOT     = ROOT / "phone_fail.png"

IS_MAC = sys.platform == "darwin"
IS_ARM = platform.machine() == "arm64"
PLATFORM_TAG = "mac-arm64" if IS_ARM else "mac-x64"

CFT_KNOWN     = "https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json"
CFT_MILESTONE = "https://googlechromelabs.github.io/chrome-for-testing/latest-versions-per-milestone-with-downloads.json"

CDC = b"cdc_"
CAPTCHA_WAIT = 300
SMS_WAIT = 180

BANNER = r"""
██████╗ ██╗██╗   ██╗███████╗██████╗
██╔══██╗██║██║   ██║██╔════╝██╔══██╗
██████╔╝██║██║   ██║█████╗  ██████╔╝
██╔══██╗██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
██║  ██║██║ ╚████╔╝ ███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
"""


# ---------------------------------------------------------------- solvers
@dataclass(frozen=True)
class Solver:
    key: str
    label: str
    folder: str
    ext_id: str
    blurb: str
    caveat: str

    @property
    def dir(self) -> Path:
        return ROOT / self.folder

    def download_url(self) -> str:
        return ("https://clients2.google.com/service/update2/crx?response=redirect"
                "&prodversion=120.0.0.0&acceptformat=crx2,crx3"
                f"&x=id%3D{self.ext_id}%26uc")

    def install_cmd(self) -> str:
        return (f'curl -L -o {self.key}.crx "{self.download_url()}" && '
                f"mkdir -p {self.folder} && python3 -c \"import zipfile;"
                f"zipfile.ZipFile('{self.key}.crx').extractall('{self.folder}')\"")


SOLVERS: dict[str, Solver] = {
    "nonecap": Solver(
        key="nonecap", label="NoneCap", folder="nonecap-ext",
        ext_id="kahepbmokpbbkfognbmimpmnlfibcolf",
        blurb="100 free solves/day, no account. Add an API key for unlimited runs.",
        caveat="API-backed, needs network. debugger permission -> Chrome banner.",
    ),
    "hektcaptcha": Solver(
        key="hektcaptcha", label="hektCaptcha", folder="hektcaptcha-ext",
        ext_id="bpfdbfnkjelhloljelooneehdalcmljb",
        blurb="Fully local ONNX model, unlimited, free, no key.",
        caveat="Archived Dec 2023 - stale model. Usually loses to NoneCap.",
    ),
}

DEFAULT_SOLVER = os.environ.get("DTG_SOLVER", "nonecap")
_active: Solver = SOLVERS.get(DEFAULT_SOLVER, SOLVERS["nonecap"])


def solver() -> Solver:
    return _active


def set_solver(key: str) -> None:
    global _active
    _active = SOLVERS[key]


# ---------------------------------------------------------------- sms providers
DIAL_TO_COUNTRY = {
    "1": "United States", "7": "Russia", "20": "Egypt", "27": "South Africa",
    "33": "France", "34": "Spain", "39": "Italy", "44": "United Kingdom",
    "48": "Poland", "49": "Germany", "55": "Brazil", "60": "Malaysia",
    "62": "Indonesia", "63": "Philippines", "66": "Thailand", "81": "Japan",
    "84": "Vietnam", "86": "China", "90": "Turkey", "91": "India",
    "92": "Pakistan", "98": "Iran", "212": "Morocco", "234": "Nigeria",
    "254": "Kenya", "351": "Portugal", "355": "Albania", "370": "Lithuania",
    "380": "Ukraine", "381": "Serbia", "385": "Croatia", "420": "Czechia",
    "880": "Bangladesh", "994": "Azerbaijan",
}


@dataclass(frozen=True)
class SmsProvider:
    key: str
    label: str
    default_country: str
    blurb: str


SMS_PROVIDERS: dict[str, SmsProvider] = {
    "smspool": SmsProvider("smspool", "SMSPool", "1",
                           "country = numeric ID (1 = USA). Discord service 'discord'."),
    "5sim": SmsProvider("5sim", "5sim", "usa",
                        "country = slug ('usa','england'). Product 'discord'."),
    "smsactivate": SmsProvider("smsactivate", "SMS-Activate", "187",
                               "country = numeric ID (187 = USA). Service 'ds'."),
}

SMS_BASE = "https://api.sms-activate.org/stubs/handler_api.php"


def sms_send(provider: str, api_key: str, country: str,
             max_price: float | None = None) -> tuple[str, str]:
    """Returns (e164_phone, order_id)."""
    if provider == "smspool":
        data = {"key": api_key, "country": country, "service": "discord", "quantity": 1}
        if max_price:
            data["max_price"] = max_price
        j = requests.post("https://api.smspool.net/purchase/sms",
                          data=data, timeout=60).json()
        if str(j.get("success")) != "1":
            raise RuntimeError(j.get("message") or j)
        return "+" + str(j["phonenumber"]).lstrip("+"), str(j["orderid"])

    if provider == "5sim":
        params = {} if not max_price else {"maxPrice": max_price}
        j = requests.get(
            f"https://5sim.net/v1/user/buy/activation/{country}/any/discord",
            headers={"Authorization": f"Bearer {api_key}"},
            params=params, timeout=60).json()
        if "phone" not in j:
            raise RuntimeError(j)
        return "+" + str(j["phone"]).lstrip("+"), str(j["id"])

    params = {"api_key": api_key, "action": "getNumber",
              "service": "ds", "country": country}
    if max_price:
        params["maxPrice"] = max_price
    parts = requests.get(SMS_BASE, params=params, timeout=60).text.strip().split(":")
    if parts[0] != "ACCESS_NUMBER":
        raise RuntimeError(":".join(parts))
    return "+" + parts[2].lstrip("+"), parts[1]


def sms_poll(provider: str, api_key: str, order_id: str,
             timeout: int = SMS_WAIT) -> str | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        blob = ""
        try:
            if provider == "smspool":
                j = requests.post("https://api.smspool.net/sms/check", timeout=30,
                                  data={"key": api_key, "orderid": order_id}).json()
                blob = " ".join(str(j.get(k, "")) for k in ("sms", "full_sms", "code"))
            elif provider == "5sim":
                j = requests.get(f"https://5sim.net/v1/user/check/{order_id}", timeout=30,
                                 headers={"Authorization": f"Bearer {api_key}"}).json()
                blob = " ".join((s.get("code") or s.get("text") or "")
                                for s in (j.get("sms") or []))
            else:
                r = requests.get(SMS_BASE, timeout=30, params={
                    "api_key": api_key, "action": "getStatus", "id": order_id})
                if r.text.startswith("STATUS_OK"):
                    return r.text.split(":")[1].strip()
        except Exception:
            pass
        m = re.search(r"\b(\d{4,8})\b", blob)
        if m:
            return m.group(1)
        time.sleep(5)
    return None


def sms_finish(provider: str, api_key: str, order_id: str) -> None:
    try:
        if provider == "smspool":
            requests.post("https://api.smspool.net/sms/orderstatus", timeout=30,
                          data={"key": api_key, "orderid": order_id, "status": 6})
        elif provider == "5sim":
            requests.get(f"https://5sim.net/v1/user/finish/{order_id}", timeout=30,
                         headers={"Authorization": f"Bearer {api_key}"})
        else:
            requests.get(SMS_BASE, timeout=30, params={
                "api_key": api_key, "action": "setStatus", "id": order_id, "status": 6})
    except Exception:
        pass


def sms_cancel(provider: str, api_key: str, order_id: str) -> None:
    """Give the number back when no SMS ever arrived."""
    try:
        if provider == "smspool":
            requests.post("https://api.smspool.net/sms/cancel", timeout=30,
                          data={"key": api_key, "orderid": order_id})
        elif provider == "5sim":
            requests.get(f"https://5sim.net/v1/user/cancel/{order_id}", timeout=30,
                         headers={"Authorization": f"Bearer {api_key}"})
        else:
            requests.get(SMS_BASE, timeout=30, params={
                "api_key": api_key, "action": "setStatus", "id": order_id, "status": 8})
    except Exception:
        pass


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
    return "arm64" if "arm64" in out else ("x86_64" if "x86_64" in out else "unknown")


def preflight() -> list[str]:
    s = solver()
    problems = []
    if not IS_MAC:
        log("not macOS - continuing anyway", "warn")
    if not CHROME_APP.exists():
        problems.append("Google Chrome is not installed in /Applications")
    if not s.dir.exists():
        problems.append(f"missing '{s.folder}' -> python {Path(__file__).name} "
                        f"--solver {s.key} --install-ext")
    elif not (s.dir / "manifest.json").exists():
        problems.append(f"{s.folder}/manifest.json missing - nested subfolder; "
                        f"--install-ext flattens it")
    if shutil.which("codesign") is None:
        problems.append("codesign missing - run: xcode-select --install")
    if sys.version_info >= (3, 13):
        problems.append(f"Python {sys.version_info.major}.{sys.version_info.minor} - need 3.11/3.12")
    return problems


# ---------------------------------------------------------------- extension install
def _strip_crx_header(data: bytes) -> bytes:
    if data[:4] != b"Cr24":
        return data
    return data[12 + int.from_bytes(data[8:12], "little"):]


def do_install(s: Solver) -> None:
    if s.dir.exists() and (s.dir / "manifest.json").exists():
        log(f"{s.label} already installed at {s.folder}", "ok")
        return
    log(f"downloading {s.label}")
    try:
        with urllib.request.urlopen(s.download_url(), timeout=180) as resp:
            blob = _strip_crx_header(resp.read())
    except Exception as e:
        log(f"download failed ({e})", "err")
        log(f"fallback: {s.install_cmd()}", "warn")
        raise SystemExit(1)

    archive = ROOT / f".{s.key}.download"
    archive.write_bytes(blob)
    s.dir.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(archive) as z:
            z.extractall(s.dir)
    except zipfile.BadZipFile:
        raise SystemExit("archive was not a valid zip")
    finally:
        archive.unlink(missing_ok=True)

    if not (s.dir / "manifest.json").exists():
        subs = [p for p in s.dir.iterdir() if p.is_dir()]
        if len(subs) == 1 and (subs[0] / "manifest.json").exists():
            for item in list(subs[0].iterdir()):
                shutil.move(str(item), str(s.dir / item.name))
            subs[0].rmdir()
            log("flattened a nested folder level", "warn")
    if not (s.dir / "manifest.json").exists():
        raise SystemExit(f"{s.label}: manifest.json still missing")
    log(f"{s.label} installed into {s.folder}", "ok")


# ---------------------------------------------------------------- driver download
def _pick(node: dict, tag: str) -> str | None:
    for d in node.get("downloads", {}).get("chromedriver", []):
        if d["platform"] == tag:
            return d["url"]
    return None


def fetch_chromedriver() -> Path:
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
        raise SystemExit(f"no chromedriver for Chrome {major} / {PLATFORM_TAG}")

    DRIVER_CACHE.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        zp = Path(td) / "cd.zip"
        zp.write_bytes(requests.get(url, timeout=180).content)
        with zipfile.ZipFile(zp) as z:
            z.extractall(td)
        src = next((p for p in Path(td).rglob("chromedriver") if p.is_file()), None)
        if not src:
            raise SystemExit("chromedriver not found in archive")
        shutil.copy2(src, target)

    target.chmod(0o755)
    subprocess.run(["xattr", "-cr", str(target)], capture_output=True)
    log(f"chromedriver downloaded ({binary_arch(target)})", "ok")
    return target


# ---------------------------------------------------------------- driver prep
def _self_test(path: Path) -> bool:
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
    pristine = fetch_chromedriver()
    UC_SUPPORT.mkdir(parents=True, exist_ok=True)
    shutil.copy2(pristine, UC_DRIVER)
    UC_DRIVER.chmod(0o755)
    subprocess.run(["xattr", "-cr", str(UC_DRIVER)], capture_output=True)

    if not patch:
        if _self_test(UC_DRIVER):
            log("pristine driver works (unpatched)")
            return UC_DRIVER
        raise SystemExit("pristine chromedriver will not execute")

    _strip_signature(UC_DRIVER)
    data = UC_DRIVER.read_bytes()
    if CDC not in data:
        log("no cdc_ identifiers found", "warn")
    else:
        UC_DRIVER.write_bytes(data.replace(
            CDC, "".join(random.choice(string.ascii_letters)
                         for _ in range(len(CDC))).encode()))
        log("patched cdc_ identifiers")

    if not _ad_hoc_sign(UC_DRIVER) or not _self_test(UC_DRIVER):
        return _fallback_pristine(pristine)

    log(f"driver ready and signed ({'arm64' if IS_ARM else 'x86_64'})")
    return UC_DRIVER


def launch(headless: bool = False, profile: Path | None = None,
           proxy: str | None = None, patch: bool = True):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    driver_path = prepare_driver(patch=patch)
    s = solver()

    opts = Options()
    opts.add_argument("--no-first-run")
    opts.add_argument("--no-default-browser-check")
    opts.add_argument("--hide-crash-restore-bubble")
    opts.add_argument("--disable-popup-blocking")
    opts.add_argument("--disable-infobars")
    opts.add_argument("--lang=en-US")
    opts.add_argument("--window-size=1400,950")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_argument("--disable-features=DisableLoadExtensionCommandLineSwitch")
    opts.add_argument(f"--load-extension={s.dir}")
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
    driver.set_script_timeout(90)
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

    try:
        if driver.find_elements(By.NAME, "date_of_birth_month"):
            type_into(driver, "date_of_birth_month", f"{month:02d}", timeout=5)
            type_into(driver, "date_of_birth_day", f"{day:02d}", timeout=5)
            type_into(driver, "date_of_birth_year", str(year), timeout=5)
            return "named inputs"
    except Exception:
        pass

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
    try:
        r = requests.post(
            "https://discord.com/api/v9/auth/login",
            json={"login": email, "password": password, "undelete": "false"},
            headers={"content-type": "application/json",
                     "user-agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                                    "Chrome/120.0.0.0 Safari/537.36")},
            timeout=30)
    except Exception as e:
        log(f"login request failed: {e}", "err")
        return None
    if r.status_code == 200:
        return r.json().get("token")
    log(f"login returned {r.status_code}: {r.text[:160]}", "warn")
    return None


def preflight_ratelimit() -> float:
    try:
        client = tls_client.Session(client_identifier="chrome_120")
        client.headers = {
            "Accept": "*/*", "Content-Type": "application/json",
            "Origin": "https://discord.com", "Referer": "https://discord.com/register",
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
            "password": "Ultimate12$$", "date_of_birth": "2000-09-20",
            "username": rand(10), "consent": True, "captcha_service": "hcaptcha",
            "global_name": "ultimate", "captcha_key": None, "invite": None,
            "promotional_email_opt_in": False, "gift_code_sku_id": None,
        }
        r = client.post("https://discord.com/api/v9/auth/register", json=body)
        if "rate limited" in r.text:
            return float(r.json().get("retry_after", 1))
    except Exception as e:
        log(f"ratelimit probe failed: {e}", "warn")
    return 1.0


# ---------------------------------------------------------------- phone wall
def phone_wall_present(driver) -> bool:
    from selenium.webdriver.common.by import By
    try:
        if "/verify" in driver.current_url:
            return True
        return bool(driver.find_elements(
            By.XPATH, "//button[contains(normalize-space(.), 'Verify by Phone')]"))
    except Exception:
        return False


def wait_for_outcome(driver, timeout: int = CAPTCHA_WAIT) -> str:
    from selenium.webdriver.support.ui import WebDriverWait

    def state(d):
        try:
            if "discord.com/channels/@me" in d.current_url:
                return "ok"
        except Exception:
            return False
        return "locked" if phone_wall_present(d) else False

    return WebDriverWait(driver, timeout, poll_frequency=1.0).until(state)


def api_call(driver, token: str, method: str, path: str, payload=None) -> dict:
    """Runs an authenticated fetch inside the logged-in page - no selectors involved."""
    js = """
    const cb = arguments[arguments.length - 1];
    const method = arguments[0], path = arguments[1];
    const payload = arguments[2], token = arguments[3];
    fetch(path, {
        method: method,
        headers: {'Content-Type': 'application/json', 'Authorization': token},
        body: payload === null ? undefined : JSON.stringify(payload)
    }).then(async r => {
        const txt = await r.text();
        let js = null; try { js = JSON.parse(txt); } catch (e) {}
        cb({status: r.status, json: js, text: txt.slice(0, 400)});
    }).catch(e => cb({status: 0, json: null, text: String(e)}));
    """
    try:
        return driver.execute_async_script(js, method, path, payload, token)
    except Exception as e:
        return {"status": 0, "json": None, "text": f"script error: {e}"}


def release_phone(token: str, password: str) -> bool:
    """Detach the number so the next account can reuse it."""
    for payload in ({"password": password}, None):
        try:
            r = requests.delete("https://discord.com/api/v9/users/@me/phone",
                                headers={"Authorization": token},
                                json=payload, timeout=30)
            if r.status_code in (200, 204):
                return True
        except Exception:
            pass
    return False


# ---- UI fallback -----------------------------------------------------------
def _modal(driver):
    from selenium.webdriver.common.by import By
    ds = driver.find_elements(By.XPATH, "//*[@role='dialog']")
    return ds[-1] if ds else None


def _shot(driver, name: str) -> None:
    try:
        driver.save_screenshot(str(ROOT / name))
    except Exception:
        pass


def ui_open_modal(driver) -> bool:
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    try:
        btn = WebDriverWait(driver, 20).until(EC.element_to_be_clickable(
            (By.XPATH, "//button[contains(normalize-space(.), 'Verify by Phone')]")))
        driver.execute_script("arguments[0].click();", btn)
        WebDriverWait(driver, 20).until(lambda d: _modal(d) is not None)
        time.sleep(1.0)
        return True
    except Exception as e:
        log(f"could not open the phone modal: {e}", "warn")
        return False


def ui_fill_number(driver, e164: str) -> bool:
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.action_chains import ActionChains
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

    dial = e164.lstrip("+")
    label, national = None, dial
    for n in (1, 2, 3):
        if dial[:n] in DIAL_TO_COUNTRY:
            label, national = DIAL_TO_COUNTRY[dial[:n]], dial[n:]
            break

    modal = _modal(driver)
    if modal is None:
        return False

    if label:
        try:
            combo = modal.find_element(By.XPATH, ".//*[@role='combobox']")
            ActionChains(driver).move_to_element(combo).click().perform()
            time.sleep(0.5)
            ActionChains(driver).send_keys(label).perform()
            time.sleep(0.7)
            opt = WebDriverWait(driver, 8).until(EC.element_to_be_clickable(
                (By.XPATH, f"//*[@role='option'][contains(normalize-space(.), '{label}')]")))
            driver.execute_script("arguments[0].click();", opt)
            time.sleep(0.4)
        except Exception as e:
            log(f"country picker failed ({e}) - using the default", "warn")

    try:
        inp = modal.find_element(
            By.XPATH, ".//input[contains(@placeholder,'+') or @type='tel']")
        inp.click()
        try:
            inp.clear()
        except Exception:
            pass
        inp.send_keys(national)
    except Exception as e:
        log(f"phone input failed: {e}", "warn")
        _shot(driver, "phone_fail.png")
        return False

    try:
        send = modal.find_element(By.XPATH, ".//button[normalize-space(.)='Send']")
        for _ in range(24):
            if send.is_enabled():
                break
            time.sleep(0.5)
        driver.execute_script("arguments[0].click();", send)
        return True
    except Exception as e:
        log(f"Send button failed: {e}", "warn")
        _shot(driver, "phone_fail.png")
        return False


def ui_submit_code(driver, code: str) -> bool:
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.action_chains import ActionChains
    from selenium.webdriver.support.ui import WebDriverWait

    try:
        WebDriverWait(driver, 45).until(lambda d: len(d.find_elements(
            By.XPATH, "//input[@maxlength='1']")) >= 4 or len(d.find_elements(
            By.XPATH, "//*[@role='dialog']//input")) >= 1)
    except Exception:
        log("code input never appeared", "warn")
        _shot(driver, "phone_fail.png")
        return False

    boxes = driver.find_elements(By.XPATH, "//input[@maxlength='1']")
    if len(boxes) >= len(code):
        for el, ch in zip(boxes, code):
            el.send_keys(ch)
    else:
        inputs = [i for i in driver.find_elements(
            By.XPATH, "//*[@role='dialog']//input") if i.is_displayed()]
        if not inputs:
            _shot(driver, "phone_fail.png")
            return False
        ActionChains(driver).move_to_element(inputs[-1]).click().perform()
        ActionChains(driver).send_keys(code).perform()

    try:
        WebDriverWait(driver, 60).until(
            lambda d: "discord.com/channels/@me" in d.current_url)
        return True
    except Exception:
        _shot(driver, "phone_fail.png")
        return False


# ---- orchestrator ----------------------------------------------------------
def verify_phone(driver, token: str, password: str, e164: str, poll) -> bool:
    """API first, UI as fallback. `poll` returns the SMS code (or None)."""
    r = api_call(driver, token, "POST", "/api/v9/phone-verifications/send",
                 {"phone": e164})
    if r["status"] in (200, 201) and (r["json"] or {}).get("phone_token"):
        log("api: code requested")
        pt = r["json"]["phone_token"]
        code = poll()
        if not code:
            return False
        r2 = api_call(driver, token, "POST", "/api/v9/phone-verifications/verify",
                      {"phone_token": pt, "code": code})
        if r2["status"] != 200 or not (r2["json"] or {}).get("phone_token"):
            log(f"api verify rejected: {r2['status']} {r2['text']}", "warn")
            return False
        pt2 = r2["json"]["phone_token"]

        # the client shape varies; try with password then without
        for payload in ({"phone_token": pt2, "password": password},
                        {"phone_token": pt2}):
            r3 = api_call(driver, token, "POST", "/api/v9/users/@me/phone", payload)
            if r3["status"] in (200, 204):
                log("api: phone attached", "ok")
                driver.get("https://discord.com/channels/@me")
                time.sleep(3)
                return not phone_wall_present(driver)
            log(f"api attach {list(payload)} -> {r3['status']} {r3['text'][:120]}", "warn")
        return False

    log(f"api send refused ({r['status']}: {r['text'][:120]}) - using the UI", "warn")

    if not ui_open_modal(driver) or not ui_fill_number(driver, e164):
        return False
    log("ui: code requested")
    code = poll()
    if not code:
        return False
    return ui_submit_code(driver, code)


def rent_and_verify(driver, token: str, password: str, args) -> bool:
    if not (args.sms_provider and args.sms_key):
        log("no --sms-provider/--sms-key, leaving locked", "warn")
        return False

    p = SMS_PROVIDERS[args.sms_provider]
    country = args.sms_country or p.default_country

    for attempt in range(1, args.sms_retries + 1):
        order = None
        try:
            e164, order = sms_send(args.sms_provider, args.sms_key, country,
                                   args.sms_max_price)
            log(f"[{attempt}/{args.sms_retries}] rented {e164} ({p.label} order {order})")

            def poll():
                return sms_poll(args.sms_provider, args.sms_key, order)

            if verify_phone(driver, token, password, e164, poll):
                sms_finish(args.sms_provider, args.sms_key, order)
                if args.release_phone:
                    if release_phone(token, password):
                        log("number released - free for the next account", "ok")
                    else:
                        log("release failed; number stays attached", "warn")
                return True

            log("verification did not complete", "warn")
            sms_cancel(args.sms_provider, args.sms_key, order)
        except Exception as e:
            log(f"attempt {attempt} errored: {type(e).__name__}: {e}", "err")
            if order:
                sms_cancel(args.sms_provider, args.sms_key, order)
    return False


# ---------------------------------------------------------------- one account
def create_account(headless: bool = False, proxy: str | None = None,
                   patch: bool = True, keep_open: bool = False,
                   fresh_profile: bool = False, args=None) -> dict | None:
    from selenium.common.exceptions import TimeoutException
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

    s = solver()
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
        time.sleep(2)

        type_into(driver, "email", email)
        for field, value in (("global_name", "Lunarxterm"), ("username", username)):
            try:
                type_into(driver, field, value, timeout=8)
            except Exception:
                log(f"{field} not present, skipping", "warn")
        type_into(driver, "password", password)

        log(f"date of birth via {set_dob(driver)}")
        log(f"ticked {accept_checkboxes(driver)} checkbox(es)")

        wait = preflight_ratelimit()
        if wait > 1:
            log(f"rate limited, sleeping {wait:.0f}s", "warn")
            time.sleep(wait)

        driver.find_element(By.XPATH, '//button[@type="submit"]').click()
        log(f"submitted - waiting on {s.label} for hCaptcha")

        locked = wait_for_outcome(driver) == "locked"

        # token first, before any branching - locked accounts still have one
        token = token_from_browser(driver) or token_via_http(email, password)
        if not token:
            log("no token obtainable", "err")
            return None

        if locked:
            log("PHONE WALL - token captured, account not discarded", "warn")
            if args:
                if rent_and_verify(driver, token, password, args):
                    locked = False
                    token = token_from_browser(driver) or token
        else:
            log("clean registration, no wall", "ok")

        with open(TOKENS_FILE, "a") as fh:
            fh.write(token + "\n")
        with open(EVS_FILE, "a") as fh:
            fh.write(f"{email}:{password}:{token}\n")
        if locked:
            with open(LOCKED_FILE, "a") as fh:
                fh.write(f"{email}:{password}:{token}\n")

        return {"email": email, "password": password, "token": token,
                "locked": locked, "at": datetime.now().isoformat(timespec="seconds")}

    except TimeoutException:
        log("timed out waiting for /channels/@me or the wall", "err")
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
def do_verify_locked(args) -> None:
    """Re-verify accounts parked in locked.txt without re-registering."""
    if not LOCKED_FILE.exists():
        log("no locked.txt", "warn")
        return
    lines = [l.strip() for l in LOCKED_FILE.read_text().splitlines() if l.strip()]
    if not lines:
        log("locked.txt is empty", "ok")
        return

    log(f"{len(lines)} locked account(s) to try")
    remaining, done = [], 0

    for i, line in enumerate(lines, 1):
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        email, password, token = parts
        log(f"[{i}/{len(lines)}] {email}")

        driver = None
        try:
            driver = launch(args.headless, PROFILE_DIR, args.proxy, not args.no_patch)
            driver.get("https://discord.com/login")
            time.sleep(2)
            driver.execute_script(
                "window.localStorage.setItem('token', JSON.stringify(arguments[0]));",
                token)
            driver.get("https://discord.com/channels/@me")
            time.sleep(4)

            if not phone_wall_present(driver):
                log("already unlocked", "ok")
                done += 1
                continue

            if rent_and_verify(driver, token, password, args):
                done += 1
                log(f"[{i}] unlocked", "ok")
            else:
                remaining.append(line)
        except Exception as e:
            log(f"[{i}] errored: {type(e).__name__}: {e}", "err")
            remaining.append(line)
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

    LOCKED_FILE.write_text("".join(l + "\n" for l in remaining))
    log(f"unlocked {done}, {len(remaining)} still locked in {LOCKED_FILE.name}",
        "ok" if done else "warn")


def do_list() -> None:
    print(f"{Fore.CYAN}solvers:{Style.RESET_ALL}")
    for key, s in SOLVERS.items():
        state = "installed" if (s.dir / "manifest.json").exists() else "not installed"
        print(f"  {'*' if key == _active.key else ' '} {key:<13} "
              f"{Fore.LIGHTBLACK_EX}({state}){Style.RESET_ALL}")
        print(f"      {s.blurb}")
        print(f"      {Fore.YELLOW}caveat:{Style.RESET_ALL} {s.caveat}\n")
    print(f"{Fore.CYAN}sms providers:{Style.RESET_ALL}")
    for key, p in SMS_PROVIDERS.items():
        print(f"    {key:<13} {Fore.LIGHTBLACK_EX}default country "
              f"{p.default_country}{Style.RESET_ALL}")
        print(f"      {p.blurb}")


def do_check(proxy, patch):
    s = solver()
    log(f"environment check ({s.label})")
    problems = preflight()
    if problems:
        for p in problems:
            log(p, "err")
        raise SystemExit(1)

    log(f"macOS {platform.mac_ver()[0]} / {platform.machine()}")
    log(f"Chrome {chrome_version()}")
    log(f"extension: {s.dir}")

    driver = launch(False, PROFILE_DIR, proxy, patch)
    try:
        driver.get("https://accounts.hcaptcha.com/demo")
        log("browser open on the hCaptcha demo - confirm it solves unaided")
        input(f"{_ts()} press Enter when done... ")
    finally:
        driver.quit()


def do_setup(patch):
    s = solver()
    driver = launch(False, PROFILE_DIR, None, patch)
    try:
        driver.get("chrome://extensions")
        log(f"{s.label} should be listed and enabled")
        if s.key == "nonecap":
            log("optional: Details -> Extension options -> paste an API key")
        input(f"{_ts()} press Enter to close... ")
    finally:
        driver.quit()


def main():
    ap = argparse.ArgumentParser(description="Discord token generator - macOS/arm64")
    ap.add_argument("--solver", choices=list(SOLVERS), default=None)
    ap.add_argument("--list", dest="list_solvers", action="store_true")
    ap.add_argument("--install-ext", action="store_true")
    ap.add_argument("-n", "--count", type=int, default=1)
    ap.add_argument("--infinite", action="store_true")
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--proxy", default=None, help="http://user:pass@ip:port")
    ap.add_argument("--no-patch", action="store_true")
    ap.add_argument("--keep-open", action="store_true")
    ap.add_argument("--fresh-profile", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--setup", action="store_true")
    ap.add_argument("--verify-locked", action="store_true",
                    help="walk locked.txt and try to verify each one")
    ap.add_argument("--sms-provider", choices=list(SMS_PROVIDERS), default=None)
    ap.add_argument("--sms-key", default=None)
    ap.add_argument("--sms-country", default=None)
    ap.add_argument("--sms-max-price", type=float, default=None)
    ap.add_argument("--sms-retries", type=int, default=2)
    ap.add_argument("--release-phone", action="store_true",
                    help="detach the number after verifying so it can be reused")
    args = ap.parse_args()

    if args.solver:
        set_solver(args.solver)
    s = solver()

    if args.list_solvers:
        return do_list()

    print(Fore.MAGENTA + BANNER + Style.RESET_ALL)
    print(f"{Fore.LIGHTBLACK_EX}  macOS/arm64 - hCaptcha via {s.label}{Style.RESET_ALL}\n")

    if args.install_ext:
        do_install(s)
        if not args.check:
            return
    if args.check:
        return do_check(args.proxy, not args.no_patch)
    if args.setup:
        return do_setup(not args.no_patch)
    if args.verify_locked:
        return do_verify_locked(args)

    problems = preflight()
    for p in problems:
        log(p, "err")
    if problems:
        raise SystemExit(1)

    made, locked_n, failed = 0, 0, 0
    i = 0
    while args.infinite or i < args.count:
        i += 1
        log(f"[{i}] starting account")
        acct = create_account(headless=args.headless, proxy=args.proxy,
                              patch=not args.no_patch, keep_open=args.keep_open,
                              fresh_profile=args.fresh_profile, args=args)
        if acct:
            made += 1
            if acct["locked"]:
                locked_n += 1
                log(f"[{i}] OK (still locked)  {acct['email']}", "warn")
            else:
                log(f"[{i}] OK  {acct['email']}", "ok")
            print(f"        {Fore.LIGHTBLACK_EX}{acct['token']}{Style.RESET_ALL}\n")
        else:
            failed += 1

    log(f"done - {made} created ({locked_n} locked), {failed} failed", "ok")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("interrupted", "warn")
