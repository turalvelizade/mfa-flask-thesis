import io
import base64
import time
import random
import string
import json
import os
import smtplib
from email.message import EmailMessage

import pyotp
import qrcode
from flask import Flask, render_template, request, session, redirect
from twilio.rest import Client as TwilioClient


app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")


USERS = {
    "admin": {
        "password": "admin",
        "email": "tural.velizade.az@gmail.com",
        "phone": "+37126186263",
    }
}


# ---------------------------
# Environment variables
# ---------------------------

TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_TOKEN = os.getenv("TWILIO_TOKEN")
TWILIO_FROM = os.getenv("TWILIO_FROM")
TWILIO_STATUS_CALLBACK_URL = os.getenv("TWILIO_STATUS_CALLBACK_URL", "")

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))

# Experimental configuration
MFA_ARTIFICIAL_DELAY = float(os.getenv("MFA_ARTIFICIAL_DELAY", "0"))
MFA_PAYLOAD_KB = int(os.getenv("MFA_PAYLOAD_KB", "0"))
TEST_PROFILE = os.getenv("TEST_PROFILE", "baseline")
SHOW_TOTP_QR = os.getenv("SHOW_TOTP_QR", "false").lower() == "true"

# IMPORTANT:
# Store this in Railway variables so the TOTP secret survives redeploys.
# Example Railway variable:
# TOTP_SECRET_ADMIN=SY6C34OQ5C3E2EQRXBKSW2JRXB34HSK5
TOTP_SECRET_ADMIN = os.getenv("TOTP_SECRET_ADMIN")

SECRETS_FILE = "totp_secrets.json"
sms_tracking = {}


# ---------------------------
# Logging and payload helpers
# ---------------------------

def log_event(event_type, method=None, result=None, reason=None, **kwargs):
    parts = [f"event={event_type}"]

    if method:
        parts.append(f"method={method}")
    if result:
        parts.append(f"result={result}")
    if reason:
        parts.append(f"reason={reason}")

    parts.append(f"profile={TEST_PROFILE}")
    parts.append(f"artificial_delay_s={MFA_ARTIFICIAL_DELAY}")
    parts.append(f"payload_kb={MFA_PAYLOAD_KB}")

    for k, v in kwargs.items():
        parts.append(f"{k}={v}")

    print("[MEASUREMENT] " + " | ".join(parts), flush=True)


def generate_payload():
    return "A" * (MFA_PAYLOAD_KB * 1024)


# ---------------------------
# TOTP helpers
# ---------------------------

def load_secrets():
    if os.path.exists(SECRETS_FILE):
        try:
            with open(SECRETS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_secrets(secrets):
    with open(SECRETS_FILE, "w") as f:
        json.dump(secrets, f)


def get_totp_secret(username):
    """
    TOTP secret priority:
    1. Railway environment variable for admin user
    2. totp_secrets.json fallback
    3. generate new fallback secret if no secret exists

    This fixes the issue where Railway redeploys can lose or reset local JSON data.
    """
    if username == "admin" and TOTP_SECRET_ADMIN:
        return TOTP_SECRET_ADMIN

    secrets = load_secrets()

    if username not in secrets:
        secrets[username] = pyotp.random_base32()
        save_secrets(secrets)

    return secrets[username]


def verify_totp_code(username, code):
    secret = get_totp_secret(username)
    totp = pyotp.TOTP(secret)

    return totp.verify(code, valid_window=1)


def get_totp_qr(username):
    secret = get_totp_secret(username)

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="MFA Thesis"
    )

    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")

    return base64.b64encode(buf.getvalue()).decode()


# ---------------------------
# OTP helper
# ---------------------------

def generate_otp():
    return "".join(random.choices(string.digits, k=6))


# ---------------------------
# SMS MFA
# ---------------------------

def send_sms(phone, otp):
    client = TwilioClient(TWILIO_SID, TWILIO_TOKEN)

    # Artificial delay simulates external communication delay.
    # This delay is included in total authentication time,
    # but not included in Twilio API submission time.
    if MFA_ARTIFICIAL_DELAY > 0:
        time.sleep(MFA_ARTIFICIAL_DELAY)

    # This measures only Twilio API submission time.
    start = time.time()

    message = client.messages.create(
        body=f"Your MFA code: {otp}",
        from_=TWILIO_FROM,
        to=phone,
        status_callback=TWILIO_STATUS_CALLBACK_URL if TWILIO_STATUS_CALLBACK_URL else None
    )

    ms = round((time.time() - start) * 1000, 2)

    sms_tracking[message.sid] = {
        "sent_at": time.time(),
        "status": "submitted"
    }

    log_event(
        event_type="sms_dispatch",
        method="sms",
        result="submitted",
        sid=message.sid,
        api_submission_time_ms=ms
    )

    return ms, message.sid


@app.route("/twilio-status", methods=["POST"])
def twilio_status():
    sid = request.form.get("MessageSid")
    status = request.form.get("MessageStatus")

    if sid in sms_tracking:
        sms_tracking[sid]["status"] = status
        sms_tracking[sid]["callback_at"] = time.time()

    log_event(
        event_type="sms_callback",
        method="sms",
        result=status,
        sid=sid
    )

    return "", 200


# ---------------------------
# Email MFA
# ---------------------------

def send_email(to_address, otp):
    # Artificial delay simulates external communication delay.
    # This delay is included in total authentication time,
    # but not included in SMTP submission time.
    if MFA_ARTIFICIAL_DELAY > 0:
        time.sleep(MFA_ARTIFICIAL_DELAY)

    # This measures only SMTP submission time.
    start = time.time()

    email_body = f"""Hello,

Your verification code is: {otp}

This code will expire in 5 minutes.

If you did not request this code, you can safely ignore this message.

Best regards,
MFA Testing System
"""

    msg = EmailMessage()
    msg["Subject"] = "Your verification code"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_address
    msg.set_content(email_body)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_APP_PASSWORD)
            server.send_message(msg)

        ms = round((time.time() - start) * 1000, 2)

        log_event(
            event_type="email_dispatch",
            method="email",
            result="submitted",
            smtp_submission_time_ms=ms,
            recipient=to_address
        )

        return ms

    except Exception as e:
        log_event(
            event_type="email_dispatch",
            method="email",
            result="fail",
            reason="send_error_email",
            detail=str(e)
        )
        raise


# ---------------------------
# Routes
# ---------------------------

@app.route("/", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "").strip()

        if u in USERS and USERS[u]["password"] == p:
            session["pending_user"] = u
            return redirect("/mfa")

        error = "Wrong username or password."

        log_event(
            event_type="login",
            result="fail",
            reason="wrong_username_or_password",
            username=u
        )

    return render_template("login.html", error=error)


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    if "pending_user" not in session:
        return redirect("/")

    error = None

    if request.method == "POST":
        method = request.form.get("method")
        username = session["pending_user"]
        user = USERS[username]

        session["mfa_start_ts"] = time.time()

        log_event(
            event_type="mfa_start",
            method=method,
            result="started",
            username=username
        )

        if method == "sms":
            otp = generate_otp()
            session["otp"] = otp
            session["otp_ts"] = time.time()
            session["method"] = "sms"

            try:
                send_sms(user["phone"], otp)
                return redirect("/verify")

            except Exception as e:
                error = f"SMS error: {e}"

                log_event(
                    event_type="mfa_send",
                    method="sms",
                    result="fail",
                    reason="send_error_sms",
                    detail=str(e)
                )

        elif method == "email":
            otp = generate_otp()
            session["otp"] = otp
            session["otp_ts"] = time.time()
            session["method"] = "email"

            try:
                send_email(user["email"], otp)
                return redirect("/verify")

            except Exception as e:
                error = f"Email error: {e}"

                log_event(
                    event_type="mfa_send",
                    method="email",
                    result="fail",
                    reason="send_error_email",
                    detail=str(e)
                )

        elif method == "totp":
            session["method"] = "totp"

            # Ensures the TOTP secret exists.
            # If TOTP_SECRET_ADMIN is set in Railway, it will use that stable secret.
            get_totp_secret(username)

            log_event(
                event_type="totp_ready",
                method="totp",
                result="ready",
                username=username,
                totp_secret_source="env" if (username == "admin" and TOTP_SECRET_ADMIN) else "file"
            )

            return redirect("/verify")

        else:
            error = "Please select a method."

            log_event(
                event_type="mfa_start",
                result="fail",
                reason="no_method_selected",
                username=username
            )

    return render_template("mfa_select.html", error=error)


@app.route("/verify", methods=["GET", "POST"])
def verify():
    if "method" not in session or "pending_user" not in session:
        return redirect("/")

    method = session["method"]
    username = session["pending_user"]

    # QR is only shown when SHOW_TOTP_QR=true.
    # During experiments keep SHOW_TOTP_QR=false.
    # The secret still exists through TOTP_SECRET_ADMIN or totp_secrets.json.
    qr = get_totp_qr(username) if method == "totp" and SHOW_TOTP_QR else None

    error = None

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        ok = False
        start = session.get("mfa_start_ts", time.time())

        if method == "totp":
            ok = verify_totp_code(username, code)

            if not ok:
                error = "Invalid code. Check your authenticator app."

                log_event(
                    event_type="mfa_verify",
                    method="totp",
                    result="fail",
                    reason="invalid_totp"
                )

        else:
            if time.time() - session.get("otp_ts", 0) > 300:
                error = "Code expired. Go back and request a new one."

                log_event(
                    event_type="mfa_verify",
                    method=method,
                    result="fail",
                    reason="expired_code"
                )

            elif code == session.get("otp"):
                ok = True

            else:
                error = "Wrong code."

                log_event(
                    event_type="mfa_verify",
                    method=method,
                    result="fail",
                    reason="wrong_code"
                )

        if ok:
            total = round((time.time() - start) * 1000, 2)

            log_event(
                event_type="mfa_complete",
                method=method,
                result="success",
                user_completion_time_ms=total
            )

            session.clear()
            session["mfa_ok"] = True

            return redirect("/dashboard")

    return render_template(
        "mfa_verify.html",
        method=method,
        qr_b64=qr,
        error=error,
        payload=generate_payload(),
        profile=TEST_PROFILE,
        payload_kb=MFA_PAYLOAD_KB,
        artificial_delay_s=MFA_ARTIFICIAL_DELAY
    )


@app.route("/dashboard")
def dashboard():
    if not session.get("mfa_ok"):
        return redirect("/")

    return render_template("dashboard.html", username="admin")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)