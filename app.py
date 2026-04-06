import io
import base64
import time
import random
import string
import json
import os

import pyotp
import qrcode
from flask import Flask, render_template, request, session, redirect
from twilio.rest import Client as TwilioClient
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

USERS = {
    'admin': {
        'password': 'admin',
        'email': 'turalvelizade011@gmail.com',
        'phone': '+37126186263',
    }
}

TWILIO_SID   = os.getenv("TWILIO_SID")
TWILIO_TOKEN = os.getenv("TWILIO_TOKEN")
TWILIO_FROM  = os.getenv("TWILIO_FROM")

EMAIL_ADDRESS  = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

SECRETS_FILE = 'totp_secrets.json'

sms_tracking = {}

# Initialize Twilio client once
twilio_client = TwilioClient(TWILIO_SID, TWILIO_TOKEN)

# ─────────────────────────────────────────────
# TOTP
# ─────────────────────────────────────────────

def load_secrets():
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_secrets(secrets):
    with open(SECRETS_FILE, 'w') as f:
        json.dump(secrets, f)

def get_totp_secret(username):
    secrets = load_secrets()
    if username not in secrets:
        secrets[username] = pyotp.random_base32()
        save_secrets(secrets)
    return secrets[username]

def verify_totp_code(username, code):
    return pyotp.TOTP(get_totp_secret(username)).verify(code, valid_window=1)

def get_totp_qr(username):
    secret = get_totp_secret(username)
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name='MFA Thesis')
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode()

# ─────────────────────────────────────────────
# OTP
# ─────────────────────────────────────────────

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# ─────────────────────────────────────────────
# SMS
# ─────────────────────────────────────────────

def send_sms(phone, otp):
    try:
        start = time.time()
        message = twilio_client.messages.create(
            body=f'Your MFA code: {otp}',
            from_=TWILIO_FROM,
            to=phone,
            status_callback="https://mfa-flask-thesis.onrender.com/twilio-status"
        )
        ms = round((time.time() - start) * 1000, 2)
        sms_tracking[message.sid] = {'sent_at': time.time()}
        print(f'[MEASUREMENT] SMS | sid: {message.sid} | api_submission_time_ms: {ms}')
        return ms, message.sid
    except Exception as e:
        print(f'[ERROR] SMS failed: {e}')
        raise

@app.route('/twilio-status', methods=['POST'])
def twilio_status():
    sid    = request.form.get('MessageSid')
    status = request.form.get('MessageStatus')
    now    = time.time()

    print(f'[CALLBACK] SMS | sid: {sid} | status: {status}')

    if sid in sms_tracking and status == 'delivered':
        ms = round((now - sms_tracking[sid]['sent_at']) * 1000, 2)
        print(f'[MEASUREMENT] SMS | provider_delivery_time_ms: {ms}')

    return '', 200

# ─────────────────────────────────────────────
# EMAIL
# ─────────────────────────────────────────────

def send_email(to_address, otp):
    try:
        start = time.time()
        msg = MIMEText(f'Your MFA code: {otp}\n\nExpires in 5 minutes.')
        msg['Subject'] = 'Your MFA code'
        msg['From']    = EMAIL_ADDRESS
        msg['To']      = to_address

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            s.sendmail(EMAIL_ADDRESS, to_address, msg.as_string())

        ms = round((time.time() - start) * 1000, 2)
        print(f'[MEASUREMENT] EMAIL | api_submission_time_ms: {ms}')
        return ms
    except Exception as e:
        print(f'[ERROR] EMAIL failed: {e}')
        raise

# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '').strip()

        if u in USERS and USERS[u]['password'] == p:
            session['pending_user'] = u
            return redirect('/mfa')

        error = 'Wrong username or password.'

    return render_template('login.html', error=error)


@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'pending_user' not in session:
        return redirect('/')

    error = None

    if request.method == 'POST':
        method = request.form.get('method')
        user   = USERS[session['pending_user']]
        session['mfa_start_ts'] = time.time()

        if method == 'sms':
            otp = generate_otp()
            session['otp']    = otp
            session['otp_ts'] = time.time()
            session['method'] = 'sms'

            try:
                send_sms(user['phone'], otp)
                return redirect('/verify')
            except Exception as e:
                error = f'SMS error: {e}'

        elif method == 'email':
            otp = generate_otp()
            session['otp']    = otp
            session['otp_ts'] = time.time()
            session['method'] = 'email'

            try:
                send_email(user['email'], otp)
                return redirect('/verify')
            except Exception as e:
                error = f'Email error: {e}'

        elif method == 'totp':
            session['method'] = 'totp'
            get_totp_secret(session['pending_user'])
            return redirect('/verify')

        else:
            error = 'Please select a method.'

    return render_template('mfa_select.html', error=error)


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'method' not in session:
        return redirect('/')

    method   = session['method']
    username = session['pending_user']
    qr       = get_totp_qr(username) if method == 'totp' else None
    error    = None

    if request.method == 'POST':
        code  = request.form.get('code', '').strip()
        ok    = False
        start = session.get('mfa_start_ts', time.time())

        if method == 'totp':
            ok = verify_totp_code(username, code)
            if not ok:
                error = 'Invalid code. Check your authenticator app.'
        else:
            if time.time() - session.get('otp_ts', 0) > 300:
                error = 'Code expired. Go back and request a new one.'
            elif code == session.get('otp'):
                ok = True
            else:
                error = 'Wrong code.'

        if ok:
            total = round((time.time() - start) * 1000, 2)
            print(f'[MEASUREMENT] {method.upper()} | user_completion_time_ms: {total} | SUCCESS')

            session.clear()
            session['mfa_ok'] = True
            return redirect('/dashboard')

    return render_template('mfa_verify.html', method=method, qr_b64=qr, error=error)


@app.route('/dashboard')
def dashboard():
    if not session.get('mfa_ok'):
        return redirect('/')
    return render_template('dashboard.html', username='admin')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)