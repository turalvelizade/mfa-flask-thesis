import io
import base64
import time
import random
import string
import json
import os

import pyotp
import qrcode
from flask import Flask, render_template, request, session, redirect, url_for
from twilio.rest import Client as TwilioClient
import smtplib
from email.mime.text import MIMEText

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

# Test user (for experiment purposes)
USERS = {
    'admin': {
        'password': 'admin',
        'email':    'mfatestingthesis@gmail.com',
        'phone':    '+37126186263',
    }
}

# Twilio configuration (from environment variables)
TWILIO_SID   = os.getenv("TWILIO_SID")
TWILIO_TOKEN = os.getenv("TWILIO_TOKEN")
TWILIO_FROM  = os.getenv("TWILIO_FROM")

# Email configuration
EMAIL_ADDRESS  = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# File to store TOTP secrets
SECRETS_FILE = 'totp_secrets.json'


# Load TOTP secrets from file
def load_secrets():
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, 'r') as f:
            return json.load(f)
    return {}

# Save TOTP secrets to file
def save_secrets(secrets):
    with open(SECRETS_FILE, 'w') as f:
        json.dump(secrets, f)

# Get or create TOTP secret for user
def get_totp_secret(username):
    secrets = load_secrets()
    if username not in secrets:
        secrets[username] = pyotp.random_base32()
        save_secrets(secrets)
    return secrets[username]


# Generate random 6-digit OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


# Send SMS via Twilio + measure send time
def send_sms(phone, otp):
    t1 = time.time()

    client = TwilioClient(TWILIO_SID, TWILIO_TOKEN)

    # IMPORTANT: Add status_callback for delivery tracking
    message = client.messages.create(
        body=f'Your MFA code: {otp}',
        from_=TWILIO_FROM,
        to=phone,
        status_callback="https://mfa-flask-thesis.onrender.com/twilio-status"
    )

    ms = round((time.time() - t1) * 1000, 2)

    # Store send time for later comparison
    print(f'[MEASUREMENT] SMS | send_duration: {ms} ms | SID: {message.sid}')

    return ms


# Twilio callback endpoint (receives delivery updates)
@app.route('/twilio-status', methods=['POST'])
def twilio_status():
    message_sid = request.form.get('MessageSid')
    status = request.form.get('MessageStatus')

    now = time.time()

    print(f'[CALLBACK] SID: {message_sid} | status: {status} | time: {now}')

    return '', 200


# Send email OTP via SMTP + measure send time
def send_email(to_address, otp):
    t1 = time.time()

    msg = MIMEText(f'Your MFA code: {otp}\n\nExpires in 5 minutes.')
    msg['Subject'] = 'Your MFA code'
    msg['From']    = EMAIL_ADDRESS
    msg['To']      = to_address

    with smtplib.SMTP('smtp.gmail.com', 587) as s:
        s.starttls()
        s.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        s.sendmail(EMAIL_ADDRESS, to_address, msg.as_string())

    ms = round((time.time() - t1) * 1000, 2)

    print(f'[MEASUREMENT] EMAIL | send_duration: {ms} ms')

    return ms


# Generate QR code for TOTP setup
def get_totp_qr(username):
    secret = get_totp_secret(username)

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name='MFA Thesis'
    )

    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format='PNG')

    return base64.b64encode(buf.getvalue()).decode()


# Verify TOTP code
def verify_totp_code(username, code):
    secret = get_totp_secret(username)
    return pyotp.TOTP(secret).verify(code, valid_window=1)


# Login page
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        user = USERS.get(username)

        if user and user['password'] == password:
            session['pending_user'] = username
            return redirect(url_for('mfa_select'))

        error = 'Wrong username or password.'

    return render_template('login.html', error=error)


# MFA method selection
@app.route('/mfa', methods=['GET', 'POST'])
def mfa_select():
    if 'pending_user' not in session:
        return redirect(url_for('login'))

    error = None

    if request.method == 'POST':
        method = request.form.get('method')
        username = session['pending_user']
        user = USERS[username]

        # SMS method
        if method == 'sms':
            otp = generate_otp()

            session['otp'] = otp
            session['otp_ts'] = time.time()
            session['method'] = 'sms'

            try:
                send_sms(user['phone'], otp)
                return redirect(url_for('mfa_verify'))
            except Exception as e:
                error = f'SMS error: {e}'

        # Email method
        elif method == 'email':
            otp = generate_otp()

            session['otp'] = otp
            session['otp_ts'] = time.time()
            session['method'] = 'email'

            try:
                send_email(user['email'], otp)
                return redirect(url_for('mfa_verify'))
            except Exception as e:
                error = f'Email error: {e}'

        # TOTP method
        elif method == 'totp':
            session['method'] = 'totp'
            get_totp_secret(username)
            return redirect(url_for('mfa_verify'))

        else:
            error = 'Please select a method.'

    return render_template('mfa_select.html', error=error)


# OTP verification
@app.route('/verify', methods=['GET', 'POST'])
def mfa_verify():
    if 'pending_user' not in session or 'method' not in session:
        return redirect(url_for('login'))

    username = session['pending_user']
    method = session['method']
    error = None

    qr_b64 = get_totp_qr(username) if method == 'totp' else None

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        ok = False

        if method == 'totp':
            ok = verify_totp_code(username, code)

            print(f'[MEASUREMENT] TOTP | result: {"SUCCESS" if ok else "FAIL"}')

            if not ok:
                error = 'Invalid code. Check your authenticator app.'

        else:
            stored = session.get('otp')
            ts = session.get('otp_ts', 0)

            if time.time() - ts > 300:
                error = 'Code expired.'
            elif code != stored:
                error = 'Wrong code.'
            else:
                ok = True

            print(f'[MEASUREMENT] {method.upper()} | result: {"SUCCESS" if ok else "FAIL"}')

        if ok:
            session.clear()
            session['user'] = username
            session['mfa_ok'] = True
            return redirect(url_for('dashboard'))

    return render_template('mfa_verify.html', method=method, qr_b64=qr_b64, error=error)


# Dashboard page
@app.route('/dashboard')
def dashboard():
    if not session.get('mfa_ok'):
        return redirect(url_for('login'))

    return render_template('dashboard.html', username=session.get('user'))


# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# Run app locally
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)