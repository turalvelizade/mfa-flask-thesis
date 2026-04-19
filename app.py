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

# created the Flask app and set the secret key from env or fallback to dev default
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

# hardcoded a single test user with email and phone for MFA testing
USERS = {
    'admin': {
        'password': 'admin',
        'email': 'tural.velizade.az@gmail.com',
        'phone': '+37126186263',
    }
}

# loaded all external service credentials from environment variables
TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_TOKEN = os.getenv("TWILIO_TOKEN")
TWILIO_FROM = os.getenv("TWILIO_FROM")
TWILIO_STATUS_CALLBACK_URL = os.getenv("TWILIO_STATUS_CALLBACK_URL", "")

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))

# used a JSON file to persist TOTP secrets across restarts, and a dict to track SMS delivery
SECRETS_FILE = 'totp_secrets.json'
sms_tracking = {}


# structured all log output with key=value pairs so it's easy to parse or grep later
def log_event(event_type, method=None, result=None, reason=None, **kwargs):
    parts = [f"event={event_type}"]
    if method:
        parts.append(f"method={method}")
    if result:
        parts.append(f"result={result}")
    if reason:
        parts.append(f"reason={reason}")
    for k, v in kwargs.items():
        parts.append(f"{k}={v}")
    print("[MEASUREMENT] " + " | ".join(parts))


# loaded TOTP secrets from disk so they survive between restarts
def load_secrets():
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, 'r') as f:
            return json.load(f)
    return {}

# saved updated secrets back to disk after any new user is registered
def save_secrets(secrets):
    with open(SECRETS_FILE, 'w') as f:
        json.dump(secrets, f)

# generated a new TOTP secret for first-time users and saved it, or returned the existing one
def get_totp_secret(username):
    secrets = load_secrets()
    if username not in secrets:
        secrets[username] = pyotp.random_base32()
        save_secrets(secrets)
    return secrets[username]

# verified the submitted TOTP code with a ±1 window to handle slight clock drift
def verify_totp_code(username, code):
    return pyotp.TOTP(get_totp_secret(username)).verify(code, valid_window=1)

# generated a QR code as a base64 PNG so the template can embed it directly in an <img> tag
def get_totp_qr(username):
    secret = get_totp_secret(username)
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name='MFA Thesis')
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode()


# generated a 6-digit numeric OTP for SMS and email methods
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


# sent the OTP via Twilio SMS and measured how long the API submission took
def send_sms(phone, otp):
    client = TwilioClient(TWILIO_SID, TWILIO_TOKEN)
    start = time.time()

    # included a status callback URL so Twilio can notify us when delivery is confirmed
    message = client.messages.create(
        body=f'Your MFA code: {otp}',
        from_=TWILIO_FROM,
        to=phone,
        status_callback=TWILIO_STATUS_CALLBACK_URL if TWILIO_STATUS_CALLBACK_URL else None
    )

    ms = round((time.time() - start) * 1000, 2)
    # stored the message SID and sent timestamp so we can match it with the callback later
    sms_tracking[message.sid] = {
        'sent_at': time.time(),
        'status': 'submitted'
    }

    log_event(
        event_type="sms_dispatch",
        method="sms",
        result="submitted",
        sid=message.sid,
        api_submission_time_ms=ms
    )
    return ms, message.sid


# received Twilio delivery status updates and updated our in-memory tracking dict
@app.route('/twilio-status', methods=['POST'])
def twilio_status():
    sid = request.form.get('MessageSid')
    status = request.form.get('MessageStatus')

    if sid in sms_tracking:
        sms_tracking[sid]['status'] = status
        sms_tracking[sid]['callback_at'] = time.time()

    log_event(
        event_type="sms_callback",
        method="sms",
        result=status,
        sid=sid
    )
    return '', 200


# sent the OTP via Gmail SMTP using app password auth and measured delivery time
def send_email(to_address, otp):
    start = time.time()

    # wrote a plain-text email body with expiry notice and a safety message for unexpected codes
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
        # used STARTTLS to upgrade the connection before logging in
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


# handled login form submission and redirected to MFA on success
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '').strip()

        # stored the username in session so the MFA step knows who is authenticating
        if u in USERS and USERS[u]['password'] == p:
            session['pending_user'] = u
            return redirect('/mfa')

        error = 'Wrong username or password.'
        log_event(
            event_type="login",
            result="fail",
            reason="wrong_username_or_password",
            username=u
        )

    return render_template('login.html', error=error)


# presented the MFA method selection and triggered OTP sending or TOTP setup
@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'pending_user' not in session:
        return redirect('/')

    error = None

    if request.method == 'POST':
        method = request.form.get('method')
        username = session['pending_user']
        user = USERS[username]
        # saved the MFA start timestamp so we can measure total completion time later
        session['mfa_start_ts'] = time.time()

        log_event(
            event_type="mfa_start",
            method=method,
            result="started",
            username=username
        )

        if method == 'sms':
            otp = generate_otp()
            session['otp'] = otp
            session['otp_ts'] = time.time()
            session['method'] = 'sms'

            try:
                send_sms(user['phone'], otp)
                return redirect('/verify')
            except Exception as e:
                error = f'SMS error: {e}'
                log_event(
                    event_type="mfa_send",
                    method="sms",
                    result="fail",
                    reason="send_error_sms",
                    detail=str(e)
                )

        elif method == 'email':
            otp = generate_otp()
            session['otp'] = otp
            session['otp_ts'] = time.time()
            session['method'] = 'email'

            try:
                send_email(user['email'], otp)
                return redirect('/verify')
            except Exception as e:
                error = f'Email error: {e}'
                log_event(
                    event_type="mfa_send",
                    method="email",
                    result="fail",
                    reason="send_error_email",
                    detail=str(e)
                )

        elif method == 'totp':
            session['method'] = 'totp'
            # called get_totp_secret here to ensure the secret is generated before the verify page loads
            get_totp_secret(username)

            log_event(
                event_type="totp_ready",
                method="totp",
                result="ready",
                username=username
            )
            return redirect('/verify')

        else:
            error = 'Please select a method.'
            log_event(
                event_type="mfa_start",
                result="fail",
                reason="no_method_selected",
                username=username
            )

    return render_template('mfa_select.html', error=error)


# handled code verification for all three MFA methods and measured completion time
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'method' not in session or 'pending_user' not in session:
        return redirect('/')

    method = session['method']
    username = session['pending_user']
    # only generated the QR code when the method is TOTP, passed None otherwise
    qr = get_totp_qr(username) if method == 'totp' else None
    error = None

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        ok = False
        start = session.get('mfa_start_ts', time.time())

        if method == 'totp':
            ok = verify_totp_code(username, code)
            if not ok:
                error = 'Invalid code. Check your authenticator app.'
                log_event(
                    event_type="mfa_verify",
                    method="totp",
                    result="fail",
                    reason="invalid_totp"
                )

        else:
            # checked expiry first before comparing the code to avoid timing issues
            if time.time() - session.get('otp_ts', 0) > 300:
                error = 'Code expired. Go back and request a new one.'
                log_event(
                    event_type="mfa_verify",
                    method=method,
                    result="fail",
                    reason="expired_code"
                )
            elif code == session.get('otp'):
                ok = True
            else:
                error = 'Wrong code.'
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
            # cleared the session and set mfa_ok so only verified users can reach the dashboard
            session.clear()
            session['mfa_ok'] = True
            return redirect('/dashboard')

    return render_template('mfa_verify.html', method=method, qr_b64=qr, error=error)


# protected the dashboard so only users who completed MFA can access it
@app.route('/dashboard')
def dashboard():
    if not session.get('mfa_ok'):
        return redirect('/')
    return render_template('dashboard.html', username='admin')


# cleared the entire session on logout and sent the user back to the login page
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)