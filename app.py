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

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

USERS = {
    'admin': {
        'password': 'admin',
        'email': 'mfatestingthesis@gmail.com',
        'phone': '+37126186263',
    }
}

TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_TOKEN = os.getenv("TWILIO_TOKEN")
TWILIO_FROM = os.getenv("TWILIO_FROM")

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

SECRETS_FILE = 'totp_secrets.json'

# Stores SMS send timestamps in memory using Twilio Message SID
sms_tracking = {}


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


def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


def send_sms(phone, otp):
    client = TwilioClient(TWILIO_SID, TWILIO_TOKEN)

    send_start = time.time()

    message = client.messages.create(
        body=f'Your MFA code: {otp}',
        from_=TWILIO_FROM,
        to=phone,
        status_callback="https://mfa-flask-thesis.onrender.com/twilio-status"
    )

    send_end = time.time()
    send_duration_ms = round((send_end - send_start) * 1000, 2)

    # Save the exact send time so we can later compare it with Twilio's delivered callback
    sms_tracking[message.sid] = {
        'sent_at': send_end
    }

    print(f'[MEASUREMENT] SMS | SID: {message.sid} | send_duration: {send_duration_ms} ms')

    return send_duration_ms


@app.route('/twilio-status', methods=['POST'])
def twilio_status():
    message_sid = request.form.get('MessageSid')
    status = request.form.get('MessageStatus')
    now = time.time()

    print(f'[CALLBACK] SID: {message_sid} | status: {status} | callback_time: {now}')

    # Calculate delivery time only when Twilio confirms the SMS is delivered
    if message_sid in sms_tracking and status == 'delivered':
        sent_at = sms_tracking[message_sid]['sent_at']
        delivery_time_ms = round((now - sent_at) * 1000, 2)

        print(f'[MEASUREMENT] SMS | SID: {message_sid} | delivery_time: {delivery_time_ms} ms')

    return '', 200


def send_email(to_address, otp):
    t1 = time.time()

    msg = MIMEText(f'Your MFA code: {otp}\n\nExpires in 5 minutes.')
    msg['Subject'] = 'Your MFA code'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_address

    with smtplib.SMTP('smtp.gmail.com', 587) as s:
        s.starttls()
        s.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        s.sendmail(EMAIL_ADDRESS, to_address, msg.as_string())

    ms = round((time.time() - t1) * 1000, 2)

    print(f'[MEASUREMENT] EMAIL | send_duration: {ms} ms')

    return ms


def get_totp_qr(username):
    secret = get_totp_secret(username)

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name='MFA Thesis'
    )

    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format='PNG')

    return base64.b64encode(buf.getvalue()).decode()


def verify_totp_code(username, code):
    secret = get_totp_secret(username)
    return pyotp.TOTP(secret).verify(code, valid_window=1)


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


@app.route('/mfa', methods=['GET', 'POST'])
def mfa_select():
    if 'pending_user' not in session:
        return redirect(url_for('login'))

    error = None

    if request.method == 'POST':
        method = request.form.get('method')
        username = session['pending_user']
        user = USERS[username]

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

        elif method == 'totp':
            session['method'] = 'totp'
            get_totp_secret(username)
            return redirect(url_for('mfa_verify'))

        else:
            error = 'Please select a method.'

    return render_template('mfa_select.html', error=error)


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


@app.route('/dashboard')
def dashboard():
    if not session.get('mfa_ok'):
        return redirect(url_for('login'))

    return render_template('dashboard.html', username=session.get('user'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)