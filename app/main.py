#!/usr/bin/env python3
"""
main.py

Endpoints:
  POST /login/username        -> { "username": "..." }  starts browser, enters username.
                                  Response includes "flow": "microsoft" | "federated" so
                                  the frontend knows which screen to show next.
  POST /login/password        -> { "username": "...", "password": "..." }  enters password
                                  on Microsoft's own page, starts a BACKGROUND job
  POST /login/org-signin      -> { "username": "...", "email": "...", "password": "..." }
                                  best-effort autofill for a federated third-party IdP page,
                                  then starts the same background finishing job
  GET  /login/status/<user>   -> current job state + any available MFA options + which
                                  federated domain (if any), scraped live from the DOM.
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
code-entry selectors are best-effort based on commonly documented Microsoft
login markup and are NOT verified against live source the way the rest of
this file is.

FEDERATED/ORG ACCOUNT CAVEAT: /login/org-signin uses generic type-based
selectors (first email/text input, first password input, then a submit
button or Enter key) since there's no single verified markup across
third-party IdPs (GoDaddy-hosted M365, ADFS, Okta, PingFederate, etc.).
This works on many simple forms but isn't guaranteed for every provider —
if it fails on a specific IdP, inspect that page's real DOM and this can be
special-cased the same way the Microsoft flow was.

Every route below requires an authenticated admin session (see admin.py) —
none of this is reachable without first logging in at /admin/login.

Local-only tool: binds to 127.0.0.1, one login in flight at a time per username.
"""

import json
import os
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

from admin import admin_bp, init_admin_db
from dashboard import dashboard_bp
from roadrecon_actions import actions_bp

# ---------------------------------------------------------------------------
# Edit these directly
# ---------------------------------------------------------------------------

CLIENT_ID = WELLKNOWN_CLIENTS["azcli"]
RESOURCE = WELLKNOWN_RESOURCES["msgraph"]
REDIRURL = "https://login.microsoftonline.com/common/oauth2/nativeclient"
DRIVERPATH = os.environ.get("GECKODRIVER_PATH")
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
    AWAITING_ORG_LOGIN = "awaiting_org_login"      # redirected to a third-party/federated IdP
    AWAITING_MFA_CHOICE = "awaiting_mfa_choice"    # push screen, with a "use another way" link
    AWAITING_MFA_CODE = "awaiting_mfa_code"         # a code-entry input is on screen
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass
class LoginSession:
    selauth: SeleniumAuthentication
    auth: Authentication
    created_at: float
    stage: Stage = Stage.ENTERING_PASSWORD
    mfa_options: list[str] = field(default_factory=list)
    federated_domain: Optional[str] = None
    error: Optional[str] = None
    tokens: Optional[dict] = None
    background_image: Optional[str] = None
    logo: Optional[str] = None
    footer_text: Optional[str] = None
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


def _quit_driver_safely(driver) -> None:
    try:
        driver.quit()
    except Exception:
        pass


def _capture_branding(driver) -> dict:
    """
    Best-effort scrape of the tenant's custom branding from Microsoft's own
    login page: the background image, the company logo, and any footer/
    boilerplate text (e.g. "contact support at ..."). Every field is None
    if not found — the frontend only renders what's actually present.
    """
    try:
        result = driver.execute_script("""
            const out = { background_image: null, logo: null, footer_text: null };

            // Background image: same detection as before.
            const bannerLogo = document.getElementById('bannerLogo');
            if (bannerLogo && bannerLogo.src) {
                out.logo = bannerLogo.src;
            }

            const images = document.querySelectorAll('img');
            if (!out.logo) {
                for (let img of images) {
                    const id = img.id || '';
                    const className = img.className || '';
                    if ((id.includes('banner') || className.includes('banner')) && img.src) {
                        out.logo = img.src;
                        break;
                    }
                }
            }

            const allElements = document.querySelectorAll('*');
            for (let el of allElements) {
                const bg = window.getComputedStyle(el).backgroundImage;
                if (bg && bg !== 'none' && bg.includes('url(')) {
                    const match = bg.match(/url\\(['\"]?(.+?)['\"]?\\)/);
                    if (match && match[1]) {
                        out.background_image = match[1];
                        break;
                    }
                }
            }

            // Footer / boilerplate text (tenant-configured support contact,
            // terms links, etc). Microsoft renders this as custom sign-in
            // page text, most reliably found at #footerTextContent (a leaf
            // div holding just that string) or #idBoilerPlateText. Capped at
            // 200 chars and required to be a leaf-ish node (no nested form
            // controls) so a broad fallback selector can't accidentally
            // sweep up the whole page's text.
            const footerCandidateIds = ['footerTextContent', 'idBoilerPlateText', 'idDiv_SAOTCC_Title'];
            for (const id of footerCandidateIds) {
                const el = document.getElementById(id);
                const text = el && el.innerText && el.innerText.trim();
                if (text && text.length <= 200 && !el.querySelector('input, button, form')) {
                    out.footer_text = text;
                    break;
                }
            }

            return out;
        """)
        return result or {}
    except Exception:
        return {}


def _username_error_text(driver) -> Optional[str]:
    """
    Microsoft shows inline validation errors (e.g. "Enter a valid email
    address, phone number, or Skype name.") in #usernameError without
    navigating away or removing #i0118 from the DOM, so callers must check
    this explicitly rather than assuming #i0118 means the password step.
    """
    try:
        el = driver.find_element(By.ID, "usernameError")
    except NoSuchElementException:
        return None
    text = el.text.strip()
    return text if text and el.is_displayed() else None


def _is_federated_redirect(driver) -> Optional[str]:
    """
    Returns the redirected-to domain if the browser has navigated away from
    login.microsoftonline.com (i.e. the tenant is federated to a third-party
    IdP), or None if we're still on Microsoft's own login pages.
    """
    domain = urlparse(driver.current_url).netloc
    if domain and "login.microsoftonline.com" not in domain and "login.microsoft.com" not in domain:
        return domain
    return None


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
    switch_link = _find_by_text(driver, _SWITCH_METHOD_LINK_TEXT)
    if switch_link is not None and _find_by_text(driver, "Approve sign in request") is not None:
        return [switch_link.text.strip() or "I can't use my Microsoft Authenticator app right now"]

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


def _finish_credentials_flow(username: str, session: LoginSession, driver) -> None:
    """
    Shared tail end of both auth flows: handle KMSI, poll for MFA/redirect,
    capture cookies, exchange the code, save tokens. Runs after credentials
    have already been entered — either by _run_password_job's Microsoft-
    specific i0118 typing, or by login_org_signin's generic federated fill.
    Not decorated itself; callers wrap this in @session_safe so exceptions
    raised here are still caught and the driver still gets closed.
    """
    started = time.time()

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


@session_safe(stage_on_error=Stage.FAILED)
def _run_password_job(username: str, password: str):
    with _sessions_lock:
        session = _sessions.get(username)

    driver = session.selauth.driver

    # Wait for password field to appear
    els = WebDriverWait(driver, STEP_TIMEOUT).until(lambda d: d.find_element(By.ID, "i0118"))

    els.send_keys(password)

    submit = WebDriverWait(driver, STEP_TIMEOUT).until(lambda d: d.find_element(By.ID, "idSIButton9"))
    _click_robust(driver, submit)

    _finish_credentials_flow(username, session, driver)


@session_safe(stage_on_error=Stage.FAILED)
def _run_org_login_job(username: str):
    """
    Federated-flow counterpart to _run_password_job. Credentials were
    already typed into the third-party IdP's page by login_org_signin()
    before this job starts — this just runs the shared MFA/code/token tail.
    """
    with _sessions_lock:
        session = _sessions.get(username)

    driver = session.selauth.driver
    _finish_credentials_flow(username, session, driver)


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
def minisoft_page():
    # Temporary test scaffold: serves the legacy standalone interactive-login
    # page (superseded by the dashboard's "Interactive (live)" tab). It drives
    # the same /login/* endpoints, so it must be served here
    # (same origin, session cookie) rather than opened as a file:// page.
    return render_template("minisoft.html")


@app.route("/login/username", methods=["POST"])
def login_username():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"ok": False, "output": "username is required."}), 400

    with _sessions_lock:
        existing = _sessions.get(username)
        if existing is not None:
            if time.time() - existing.created_at < POLL_TIMEOUT_OVERALL:
                return jsonify({"ok": False, "output": "A login is already in progress for this username."}), 409
            # Stale session past the overall timeout — abandoned by a crashed
            # job or a frontend that stopped polling. Clean it up and let this
            # attempt through instead of blocking forever.
            _sessions.pop(username, None)
            threading.Thread(target=_quit_driver_safely, args=(existing.selauth.driver,), daemon=True).start()

    try:
        selauth = _new_selauth()
        auth = selauth.auth
        driver = selauth.driver

        driver.get(_build_login_url(auth))

        el = WebDriverWait(driver, STEP_TIMEOUT).until(lambda d: d.find_element(By.ID, "i0116"))
        el.send_keys(username + Keys.ENTER)

        # Wait for EITHER Microsoft's own password field actually becoming
        # the active step, a completed auth code, a navigation away from
        # login.microsoftonline.com entirely (federated tenant redirecting
        # to its own IdP — GoDaddy-hosted M365, ADFS, Okta, etc.), OR an
        # inline validation error on the username field itself. #i0118 can
        # be present-but-hidden in the DOM before it's the active step, so
        # presence alone isn't enough — it must actually be displayed.
        WebDriverWait(driver, STEP_TIMEOUT).until(
            lambda d: (d.find_element(By.ID, "i0118").is_displayed())
            or "?code=" in d.current_url
            or _is_federated_redirect(d)
            or _username_error_text(d)
        )

        username_error = _username_error_text(driver)
        if username_error:
            # Don't let a slow/hung driver teardown block this response —
            # quit it in the background and return the error immediately.
            threading.Thread(target=_quit_driver_safely, args=(driver,), daemon=True).start()
            return jsonify({"ok": False, "output": username_error}), 400

        # The check above can fire on a TRANSIENT state — some tenants show
        # Microsoft's own page (with i0118 briefly present) for an instant
        # before a client-side JS redirect sends the browser on to a
        # third-party IdP. Give any pending redirect a moment to actually
        # complete, then make the real flow decision off the settled state
        # rather than the first instant something looked true.
        time.sleep(1.5)
        if "?code=" not in driver.current_url:
            try:
                WebDriverWait(driver, 5).until(
                    lambda d: d.find_element(By.ID, "i0118") or _is_federated_redirect(d)
                )
            except TimeoutException:
                pass  # settled on neither — fall through to whatever _is_federated_redirect reports below

    except TimeoutException:
        return jsonify({"ok": False, "output": "Timed out waiting for the username/password screen."}), 504
    except Exception as exc:
        return jsonify({"ok": False, "output": str(exc)}), 500

    federated_domain = _is_federated_redirect(driver)

    branding = {} if federated_domain else _capture_branding(driver)

    with _sessions_lock:
        _sessions[username] = LoginSession(
            selauth=selauth,
            auth=auth,
            created_at=time.time(),
            stage=Stage.AWAITING_ORG_LOGIN if federated_domain else Stage.ENTERING_PASSWORD,
            federated_domain=federated_domain,
            background_image=branding.get("background_image"),
            logo=branding.get("logo"),
            footer_text=branding.get("footer_text"),
        )

    return jsonify({
        "ok": True,
        "username": username,
        "status": "awaiting_password",
        "flow": "federated" if federated_domain else "microsoft",
        "federated_domain": federated_domain,
        "background_image": branding.get("background_image"),
        "logo": branding.get("logo"),
        "footer_text": branding.get("footer_text"),
    })


@app.route("/login/password", methods=["POST"])
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


@app.route("/login/org-signin", methods=["POST"])
def login_org_signin():
    """
    Best-effort autofill for a federated third-party IdP page. See the
    module-level "FEDERATED/ORG ACCOUNT CAVEAT" docstring above.
    """
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    with _sessions_lock:
        session = _sessions.get(username)
    if not session:
        return jsonify({"ok": False, "output": "No session for this username."}), 404

    driver = session.selauth.driver

    try:
        email_field = driver.find_element(By.CSS_SELECTOR, 'input[type="email"], input[type="text"]')
        if email:
            email_field.clear()
            email_field.send_keys(email)

        password_field = driver.find_element(By.CSS_SELECTOR, 'input[type="password"]')
        password_field.send_keys(password)

        try:
            submit_btn = driver.find_element(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
            _click_robust(driver, submit_btn)
        except NoSuchElementException:
            password_field.send_keys(Keys.ENTER)

    except NoSuchElementException:
        return jsonify({"ok": False, "output": "Could not find email/password fields on this IdP's page — its markup isn't recognized yet."}), 404

    with session.lock:
        session.stage = Stage.ENTERING_PASSWORD  # hand off to the shared post-credentials flow

    threading.Thread(target=_run_org_login_job, args=(username,), daemon=True).start()
    return jsonify({"ok": True, "username": username, "status": "started"})


@app.route("/login/status/<username>", methods=["GET"])
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
            "federated_domain": session.federated_domain,
            "error": session.error,
            "tokens": session.tokens,
            "background_image": session.background_image,
            "logo": session.logo,
            "footer_text": session.footer_text,
        }

    if session.stage in (Stage.SUCCEEDED, Stage.FAILED):
        with _sessions_lock:
            _sessions.pop(username, None)

    return jsonify(payload)


@app.route("/login/cancel", methods=["POST"])
def login_cancel():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"ok": False, "output": "username is required."}), 400

    with _sessions_lock:
        session = _sessions.pop(username, None)

    if session is not None:
        threading.Thread(target=_quit_driver_safely, args=(session.selauth.driver,), daemon=True).start()

    return jsonify({"ok": True})


@app.route("/login/mfa-select", methods=["POST"])
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

    if "can't use my Microsoft Authenticator" in option:
        el = _find_by_text(driver, _SWITCH_METHOD_LINK_TEXT)
        if el is None:
            return jsonify({"ok": False, "output": "Switch-method link not found on current screen."}), 404
        _click_robust(driver, el)
        return jsonify({"ok": True})

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
        field = driver.find_element(By.ID, "idTxtBx_SAOTCC_OTC")
        field.send_keys(code)
        submit = driver.find_element(By.ID, "idSubmit_SAOTCC_Continue")
        _click_robust(driver, submit)
        return jsonify({"ok": True})
    except NoSuchElementException:
        return jsonify({"ok": False, "output": "Code entry field not found on current screen."}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5050)), debug=False)