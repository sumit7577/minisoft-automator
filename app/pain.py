#!/usr/bin/env python3
"""
main.py

Endpoints:
  POST /login/username        -> { "username": "..." }  starts browser, enters username
  POST /login/password        -> { "username": "...", "password": "..." }  enters password,
                                  starts a BACKGROUND job (returns immediately)
  GET  /login/status/<user>   -> current job state + any available MFA options,
                                  scraped live from the DOM. Poll this from the frontend.
  POST /login/mfa-select      -> { "username": "...", "option": "<label seen in status>" }
                                  clicks a specific MFA method (e.g. "Text +X...")
  POST /login/mfa-code        -> { "username": "...", "code": "123456" }
                                  submits a verification code once the code-entry screen shows

Why a background job instead of one blocking call: the frontend needs to see
and react to the live MFA screen (push vs. picker vs. code entry) instead of
someone having to watch a separate Firefox window. So password entry runs in
a thread; the frontend polls /login/status to render whatever screen the
driver is actually on right now.

IMPORTANT CAVEAT: the specific element ids/xpaths used to detect and interact
with Microsoft's MFA screens ("i0116", "i0118", "idSIButton9", "KmsiDescription")
are verified against roadtx's own selenium.py. The MFA method-picker and OTP
code-entry selectors below are best-effort based on commonly documented
Microsoft login markup and are NOT verified against live source the way the
rest of this file is — test carefully and inspect actual DOM via DevTools if
a step doesn't advance, then tell me the real element and I'll correct it.

Local-only tool: binds to 127.0.0.1, one login in flight at a time per username.
"""

import json
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs

from flask import Flask, request, jsonify, render_template, redirect, url_for

from roadtools.roadtx.selenium import SeleniumAuthentication
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import (
    TimeoutException,
    ElementClickInterceptedException,
    ElementNotInteractableException,
    NoSuchElementException,
)

from roadtools.roadlib.auth import Authentication, AuthenticationException, WELLKNOWN_CLIENTS, WELLKNOWN_RESOURCES
from roadtools.roadlib.deviceauth import DeviceAuthentication

from admin import admin_bp, admin_required, init_admin_db
from dashboard import dashboard_bp
from roadrecon_actions import actions_bp

# ---------------------------------------------------------------------------
# Edit these directly
# ---------------------------------------------------------------------------

CLIENT_ID = WELLKNOWN_CLIENTS["azcli"]
RESOURCE = WELLKNOWN_RESOURCES["msgraph"]
REDIRURL = "https://login.microsoftonline.com/common/oauth2/nativeclient"
DRIVERPATH = "/opt/homebrew/bin/geckodriver"
HEADLESS = False
STEP_TIMEOUT = 300
POLL_TIMEOUT_OVERALL = 600  # background job gives up after this long total

# Live browser session cookies captured from the interactive flow are written
# here, mirroring roadtx's own .roadtools_auth convention (same directory).
SESSION_COOKIES_FILE = Path(__file__).parent / ".roadtools_sessioncookies.json"


# ---------------------------------------------------------------------------
# Job / session state
# ---------------------------------------------------------------------------

class Stage(str, Enum):
    ENTERING_PASSWORD = "entering_password"
    AWAITING_MFA_CHOICE = "awaiting_mfa_choice"   # push screen, with a "use another way" link
    AWAITING_MFA_CODE = "awaiting_mfa_code"        # a code-entry input is on screen
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass
class LoginSession:
    selauth: SeleniumAuthentication
    auth: Authentication
    created_at: float
    stage: Stage = Stage.ENTERING_PASSWORD
    mfa_options: list[str] = field(default_factory=list)
    error: Optional[str] = None
    tokens: Optional[dict] = None
    lock: threading.Lock = field(default_factory=threading.Lock)


_sessions: dict[str, LoginSession] = {}
_sessions_lock = threading.Lock()


def _build_login_url(auth: Authentication) -> str:
    authority = auth.get_authority_url()
    return (
        f"{authority}/oauth2/authorize"
        f"?client_id={CLIENT_ID}"
        f"&resource={RESOURCE}"
        f"&redirect_uri={REDIRURL}"
        f"&response_type=code"
        f"&prompt=login"
    )


def _new_selauth() -> SeleniumAuthentication:
    auth = Authentication(client_id=CLIENT_ID)
    deviceauth = DeviceAuthentication(auth)
    selauth = SeleniumAuthentication(auth, deviceauth, REDIRURL, headless=HEADLESS)

    service = selauth.get_service(DRIVERPATH)
    if not service:
        raise RuntimeError("geckodriver not found — check DRIVERPATH")

    selauth.driver = selauth.get_webdriver(service)
    selauth.driver.response_interceptor = selauth.redir_interceptor
    return selauth


def _extract_code_from_url(driver) -> Optional[str]:
    if "?code=" not in driver.current_url:
        return None
    parsed = urlparse(driver.current_url)
    return parse_qs(parsed.query)["code"][0]


def _click_robust(driver, element):
    try:
        element.click()
    except ElementClickInterceptedException:
        driver.execute_script("arguments[0].click();", element)


# ---------------------------------------------------------------------------
# DOM scraping — classify current screen + list clickable MFA options
# ---------------------------------------------------------------------------

# Known, text-based markers for each MFA option row. Best-effort — verify
# against real DOM if a match fails.
_MFA_OPTION_PATTERNS = [
    "Approve a request on my Microsoft Authenticator app",
    "Use a verification code",
    "Text +",
    "Call +",
]

_SWITCH_METHOD_LINK_TEXT = "can't use my Microsoft Authenticator app"


def _xpath_literal(s: str) -> str:
    """Safely quote a string for XPath even if it contains a single quote."""
    if "'" not in s:
        return f"'{s}'"
    parts = s.split("'")
    return "concat(" + ", \"'\", ".join(f"'{p}'" for p in parts) + ")"


def _find_by_text(driver, text_fragment):
    try:
        return driver.find_element(
            By.XPATH,
            f"(//*[contains(normalize-space(.), {_xpath_literal(text_fragment)})])[last()]",
        )
    except NoSuchElementException:
        return None


def _scrape_mfa_options(driver) -> list[str]:
    # Screen 1: push-approval screen ("Approve sign in request"). The only
    # actionable thing here is the "I can't use my Authenticator app" link —
    # expose it as a selectable option in its own right rather than assuming
    # it gets auto-clicked, since the frontend needs something to show/click.
    switch_link = _find_by_text(driver, _SWITCH_METHOD_LINK_TEXT)
    if switch_link is not None and _find_by_text(driver, "Approve sign in request") is not None:
        return [switch_link.text.strip() or "I can't use my Microsoft Authenticator app right now"]

    # Screen 2: method picker ("Verify your identity" with a list of rows)
    found = []
    for pattern in _MFA_OPTION_PATTERNS:
        el = _find_by_text(driver, pattern)
        if el is not None:
            found.append(el.text.strip() or pattern)
    return found


def _classify_screen(driver) -> Stage:
    if "?code=" in driver.current_url:
        return Stage.SUCCEEDED
    for candidate_id in ("idTxtBx_SAOTCC_OTC",):
        try:
            driver.find_element(By.ID, candidate_id)
            return Stage.AWAITING_MFA_CODE
        except NoSuchElementException:
            pass
    if _find_by_text(driver, "Verify your identity") is not None or \
       _find_by_text(driver, "Approve sign in request") is not None or \
       _find_by_text(driver, _SWITCH_METHOD_LINK_TEXT) is not None:
        return Stage.AWAITING_MFA_CHOICE
    return Stage.ENTERING_PASSWORD


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

def _persist_session_cookies(cookies) -> None:
    """
    Write the live browser session cookies (from driver.get_cookies()) to
    SESSION_COOKIES_FILE. Best-effort: capturing these must never break the
    auth flow, so any write error is swallowed. Must be called while the
    driver is still open (i.e. before session_safe's finally closes it).
    """
    try:
        SESSION_COOKIES_FILE.write_text(json.dumps(cookies, indent=2))
    except (OSError, TypeError):
        pass


def session_safe(stage_on_error: Optional[Stage] = None):
    """
    Same idea as roadtx's own @selenium_wrap: wrap a background job step so
    every failure is caught, recorded on the session, and logged in one
    place — instead of each job function writing its own try/except that
    duplicates the same "mark failed + store error" logic.
    Usage:
        @session_safe(stage_on_error=Stage.FAILED)
        def _run_password_job(username, password):
            ...
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(username, *args, **kwargs):
            with _sessions_lock:
                session = _sessions.get(username)
            if not session:
                return
            try:
                return fn(username, *args, **kwargs)
            except Exception as exc:
                with session.lock:
                    session.error = str(exc)
                    if stage_on_error:
                        session.stage = stage_on_error
            finally:
                try:
                    session.selauth.driver.close()
                except Exception:
                    pass
        return wrapper
    return decorator


@session_safe(stage_on_error=Stage.FAILED)
def _run_password_job(username: str, password: str):
    with _sessions_lock:
        session = _sessions.get(username)

    driver = session.selauth.driver
    started = time.time()

    els = WebDriverWait(driver, STEP_TIMEOUT).until(lambda d: d.find_element(By.ID, "i0118"))
    els.send_keys(password)

    submit = WebDriverWait(driver, STEP_TIMEOUT).until(lambda d: d.find_element(By.ID, "idSIButton9"))
    _click_robust(driver, submit)

    try:
        WebDriverWait(driver, 5).until(
            lambda d: "?code=" in d.current_url or d.find_element(By.ID, "KmsiDescription")
        )
        if "?code=" not in driver.current_url:
            try:
                _click_robust(driver, driver.find_element(By.ID, "idSIButton9"))
            except (NoSuchElementException, ElementNotInteractableException):
                pass
    except TimeoutException:
        pass

    while time.time() - started < POLL_TIMEOUT_OVERALL:
        if "?code=" in driver.current_url:
            break
        stage = _classify_screen(driver)
        with session.lock:
            session.stage = stage
            session.mfa_options = _scrape_mfa_options(driver) if stage == Stage.AWAITING_MFA_CHOICE else []
        time.sleep(1.5)

    code = _extract_code_from_url(driver)
    if not code:
        raise AuthenticationException("No authorization code found in redirect URL")

    # Grab the live session cookies while the driver is still open — this has to
    # happen here (not in the decorator) because session_safe's finally closes
    # the driver. Best-effort: never let cookie capture derail the token exchange.
    try:
        _persist_session_cookies(driver.get_cookies())
    except Exception:
        pass

    if session.auth.scope:
        tokens = session.auth.authenticate_with_code_native_v2(code, REDIRURL)
    else:
        tokens = session.auth.authenticate_with_code_native(code, REDIRURL)

    with session.lock:
        session.tokens = tokens
        session.stage = Stage.SUCCEEDED


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = Flask(__name__)

app.secret_key = "paste-your-random-string-here"
app.register_blueprint(admin_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(actions_bp)
init_admin_db()


@app.route("/")
def index():
    return redirect(url_for("dashboard.dashboard_page"))


@app.route("/minisoft")
@admin_required
def minisoft_page():
    # Temporary test scaffold: serves the legacy standalone interactive-login
    # page (superseded by the dashboard's "Interactive (live)" tab). It drives
    # the same @admin_required /login/* endpoints, so it must be served here
    # (same origin, session cookie) rather than opened as a file:// page.
    return render_template("minisoft.html")


@app.route("/login/username", methods=["POST"])
@admin_required
def login_username():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"ok": False, "output": "username is required."}), 400

    with _sessions_lock:
        if username in _sessions:
            return jsonify({"ok": False, "output": "A login is already in progress for this username."}), 409

    try:
        selauth = _new_selauth()
        auth = selauth.auth
        driver = selauth.driver

        driver.get(_build_login_url(auth))

        el = WebDriverWait(driver, STEP_TIMEOUT).until(lambda d: d.find_element(By.ID, "i0116"))
        el.send_keys(username + Keys.ENTER)

        WebDriverWait(driver, STEP_TIMEOUT).until(
            lambda d: d.find_element(By.ID, "i0118") or "?code=" in d.current_url
        )

    except TimeoutException:
        return jsonify({"ok": False, "output": "Timed out waiting for the username/password screen."}), 504
    except Exception as exc:
        return jsonify({"ok": False, "output": str(exc)}), 500

    with _sessions_lock:
        _sessions[username] = LoginSession(selauth=selauth, auth=auth, created_at=time.time())

    return jsonify({"ok": True, "username": username, "status": "awaiting_password"})


@app.route("/login/password", methods=["POST"])
@admin_required
def login_password():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"ok": False, "output": "username and password are both required."}), 400

    with _sessions_lock:
        session = _sessions.get(username)
    if not session:
        return jsonify({"ok": False, "output": "No in-progress login for this username. Call /login/username first."}), 404

    threading.Thread(target=_run_password_job, args=(username, password), daemon=True).start()
    return jsonify({"ok": True, "username": username, "status": "started"})


@app.route("/login/status/<username>", methods=["GET"])
@admin_required
def login_status(username):
    with _sessions_lock:
        session = _sessions.get(username)
    if not session:
        return jsonify({"ok": False, "output": "No session for this username."}), 404

    with session.lock:
        payload = {
            "ok": session.stage != Stage.FAILED,
            "stage": session.stage,
            "mfa_options": session.mfa_options,
            "error": session.error,
            "tokens": session.tokens,
        }

    if session.stage in (Stage.SUCCEEDED, Stage.FAILED):
        with _sessions_lock:
            _sessions.pop(username, None)

    return jsonify(payload)


@app.route("/login/mfa-select", methods=["POST"])
@admin_required
def login_mfa_select():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    option = data.get("option", "").strip()

    with _sessions_lock:
        session = _sessions.get(username)
    if not session:
        return jsonify({"ok": False, "output": "No session for this username."}), 404
    if not option:
        return jsonify({"ok": False, "output": "option is required."}), 400

    driver = session.selauth.driver

    # If the option IS the "can't use Authenticator" switch link itself,
    # just click that one element and stop — don't also search for a
    # second element with the same text, which either re-clicks nothing
    # useful or fails outright.
    if "can't use my Microsoft Authenticator" in option:
        el = _find_by_text(driver, _SWITCH_METHOD_LINK_TEXT)
        if el is None:
            return jsonify({"ok": False, "output": "Switch-method link not found on current screen."}), 404
        _click_robust(driver, el)
        return jsonify({"ok": True})

    # Otherwise this is a method-picker row (Use a verification code / Text +.../ Call +...).
    # If we're somehow still on the push screen, click the switch link first.
    switch_link = _find_by_text(driver, _SWITCH_METHOD_LINK_TEXT)
    if switch_link is not None and _find_by_text(driver, "Approve sign in request") is not None:
        _click_robust(driver, switch_link)
        time.sleep(1)

    el = _find_by_text(driver, option)
    if el is None:
        return jsonify({"ok": False, "output": f"Option '{option}' not found on current screen."}), 404

    _click_robust(driver, el)
    return jsonify({"ok": True})


@app.route("/login/mfa-code", methods=["POST"])
@admin_required
def login_mfa_code():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    code = data.get("code", "").strip()

    with _sessions_lock:
        session = _sessions.get(username)
    if not session:
        return jsonify({"ok": False, "output": "No session for this username."}), 404
    if not code:
        return jsonify({"ok": False, "output": "code is required."}), 400

    driver = session.selauth.driver

    try:
        # NOTE: these ids are commonly documented for Microsoft's OTP entry
        # screen but not verified against your installed flow — inspect and
        # correct if the field/button isn't found.
        field = driver.find_element(By.ID, "idTxtBx_SAOTCC_OTC")
        field.send_keys(code)
        submit = driver.find_element(By.ID, "idSubmit_SAOTCC_Continue")
        _click_robust(driver, submit)
        return jsonify({"ok": True})
    except NoSuchElementException:
        return jsonify({"ok": False, "output": "Code entry field not found on current screen."}), 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=True)