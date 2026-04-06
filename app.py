import io
import base64
import time
import random
import string
import json
import os
import imaplib
import email

import pyotp
import qrcode
from flask import Flask, render_template, request, session, redirect, url_for
from twilio.rest import Client as TwilioClient
import smtplib
from email.mime.text import MIMEText

# Create Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

# Test user
USERS = {
    'admin': {
        'password': 'admin',
        'email': 'turalvelizade011@gmail.com',
        'phone': '+37126186263',
    }
}

# Twilio config
TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_TOKEN = os.getenv("TWILIO_TOKEN")
TWILIO_FROM = os.getenv("TWILIO_FROM")

# Email config
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# IMAP config
IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
IMAP_PORT = int(os.getenv("IMAP_PORT", 993))

# Files
SECRETS_FILE = 'totp_secrets.json'

# Tracking
sms_tracking = {}
email_tracking = {}

# ---------------- TOTP ----------------

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
    secret = get_totp_secret(username)
    return pyotp.TOTP(secret).verify(code, valid_window=1)

def get_totp_qr(username):
    secret = get_totp_secret(username)
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name='MFA Thesis'
    )

    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode()

# ---------------- OTP ----------------

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# ---------------- SMS ----------------

def send_sms(phone, otp):
    client = TwilioClient(TWILIO_SID, TWILIO_TOKEN)

    start = time.time()
    message = client.messages.create(
        body=f'Your MFA code: {otp}',
        from_=TWILIO_FROM,
        to=phone,
        status_callback="https://mfa-flask-thesis.onrender.com/twilio-status"
    )
    end = time.time()

    ms = round((end - start) * 1000, 2)

    sms_tracking[message.sid] = {'sent_at': end}

    print(f'[MEASUREMENT] SMS | sid: {message.sid} | api_submission_time_ms: {ms}')
    return ms, message.sid

@app.route('/twilio-status', methods=['POST'])
def twilio_status():
    sid = request.form.get('MessageSid')
    status = request.form.get('MessageStatus')
    now = time.time()

    print(f'[CALLBACK] SMS | sid: {sid} | status: {status}')

    if sid in sms_tracking and status == 'delivered':
        sent = sms_tracking[sid]['sent_at']
        ms = round((now - sent) * 1000, 2)
        print(f'[MEASUREMENT] SMS | provider_delivery_time_ms: {ms}')

    return '', 200

# ---------------- EMAIL ----------------

def send_email(to_address, otp):
    start = time.time()

    msg = MIMEText(f'Your MFA code: {otp}\n\nExpires in 5 minutes.')
    msg['Subject'] = 'Your MFA code'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_address

    with smtplib.SMTP('smtp.gmail.com', 587) as s:
        s.starttls()
        s.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        s.sendmail(EMAIL_ADDRESS, to_address, msg.as_string())

    send_time = time.time()
    ms = round((send_time - start) * 1000, 2)

    print(f'[MEASUREMENT] EMAIL | api_submission_time_ms: {ms}')

    email_tracking[otp] = {'sent_at': send_time}

    return ms

def check_email_arrival(otp, timeout=60):
    start = time.time()

    while time.time() - start < timeout:
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
            mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            mail.select('inbox')

            status, messages = mail.search(None, '(UNSEEN SUBJECT "Your MFA code")')

            if status == 'OK':
                for num in messages[0].split():
                    status, data = mail.fetch(num, '(RFC822)')
                    msg = email.message_from_bytes(data[0][1])

                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                body = part.get_payload(decode=True).decode()
                    else:
                        body = msg.get_payload(decode=True).decode()

                    if otp in body:
                        now = time.time()
                        sent = email_tracking[otp]['sent_at']
                        ms = round((now - sent) * 1000, 2)

                        print(f'[MEASUREMENT] EMAIL | email_delivery_time_ms: {ms}')

                        mail.logout()
                        return ms

            mail.logout()

        except Exception as e:
            print(f'[ERROR] IMAP: {e}')

        time.sleep(2)

    print('[MEASUREMENT] EMAIL | email_delivery_time_ms: TIMEOUT')
    return None

# ---------------- ROUTES ----------------

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')

        if u in USERS and USERS[u]['password'] == p:
            session['pending_user'] = u
            return redirect('/mfa')

    return render_template('login.html')

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'pending_user' not in session:
        return redirect('/')

    if request.method == 'POST':
        method = request.form.get('method')
        user = USERS[session['pending_user']]

        session['mfa_start_ts'] = time.time()

        if method == 'sms':
            otp = generate_otp()
            session['otp'] = otp
            session['otp_ts'] = time.time()
            session['method'] = 'sms'

            send_sms(user['phone'], otp)

        elif method == 'email':
            otp = generate_otp()
            session['otp'] = otp
            session['otp_ts'] = time.time()
            session['method'] = 'email'

            send_email(user['email'], otp)
            check_email_arrival(otp)

        elif method == 'totp':
            session['method'] = 'totp'
            get_totp_secret(session['pending_user'])

        return redirect('/verify')

    return render_template('mfa_select.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'method' not in session:
        return redirect('/')

    method = session['method']
    username = session['pending_user']

    qr = get_totp_qr(username) if method == 'totp' else None

    if request.method == 'POST':
        code = request.form.get('code')
        ok = False

        start = session['mfa_start_ts']

        if method == 'totp':
            ok = verify_totp_code(username, code)
        else:
            if time.time() - session['otp_ts'] < 300 and code == session['otp']:
                ok = True

        if ok:
            total = round((time.time() - start) * 1000, 2)
            print(f'[MEASUREMENT] {method.upper()} | user_completion_time_ms: {total} | SUCCESS')

            session.clear()
            session['mfa_ok'] = True
            return redirect('/dashboard')

    return render_template('mfa_verify.html', method=method, qr_b64=qr)

@app.route('/dashboard')
def dashboard():
    if not session.get('mfa_ok'):
        return redirect('/')
    return "Logged in!"

# ---------------- RUN ----------------

if __name__ == '__main__':
    app.run(debug=True)