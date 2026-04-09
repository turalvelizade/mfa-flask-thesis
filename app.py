import io
import base64
import time
import random
import string
import json
import os
import hmac
import pyotp
import qrcode
from flask import Flask, render_template, request, session, redirect
from twilio.rest import Client as TwilioClient
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, From

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

# Mock User Database
USERS = {
    'admin': {
        'password': 'admin',
        'email': 'tural.velizade.az@gmail.com',
        'phone': '+37126186263',
    }
}

# Environment Variables
TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_TOKEN = os.getenv("TWILIO_TOKEN")
TWILIO_FROM = os.getenv("TWILIO_FROM")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

SECRETS_FILE = 'totp_secrets.json'
sms_tracking = {}

# ----------------------------
# TOTP
# ----------------------------

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

# ----------------------------
# OTP Generation
# ----------------------------

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# ----------------------------
# SMS (Twilio)
# ----------------------------

def send_sms(phone, otp):
    if not TWILIO_SID or not TWILIO_TOKEN or not TWILIO_FROM:
        raise ValueError("Twilio environment variables are missing.")

    client = TwilioClient(TWILIO_SID, TWILIO_TOKEN)
    start = time.time()

    message = client.messages.create(
        body=f'Your MFA code: {otp}',
        from_=TWILIO_FROM,
        to=phone,
        status_callback="https://mfa-flask-thesis.onrender.com/twilio-status"
    )

    ms = round((time.time() - start) * 1000, 2)
    sms_tracking[message.sid] = {'sent_at': time.time()}

    print(f'[MEASUREMENT] SMS | sid: {message.sid} | api_submission_time_ms: {ms}')
    return ms, message.sid

@app.route('/twilio-status', methods=['POST'])
def twilio_status():
    sid = request.form.get('MessageSid')
    status = request.form.get('MessageStatus')
    print(f'[CALLBACK] SMS | sid: {sid} | status: {status}')
    return '', 200

# ----------------------------
# Email (SendGrid)
# ----------------------------

def send_email(to_address, otp):
    if not SENDGRID_API_KEY:
        raise ValueError("SENDGRID_API_KEY is missing.")
    if not EMAIL_ADDRESS:
        raise ValueError("EMAIL_ADDRESS is missing.")

    start = time.time()

    email_body = f"""Hello,

Your verification code is: {otp}

This code will expire in 5 minutes.

If you did not request this code, you can safely ignore this message.

Best regards,
MFA Testing System
"""

    message = Mail(
        from_email=From(EMAIL_ADDRESS, "MFA Testing System"),
        to_emails=to_address,
        subject='Your verification code',
        plain_text_content=email_body
    )

    sg = SendGridAPIClient(SENDGRID_API_KEY)
    response = sg.send(message)

    ms = round((time.time() - start) * 1000, 2)

    print(f'[MEASUREMENT] EMAIL | api_submission_time_ms: {ms} | status_code: {response.status_code}')
    print(f'[SENDGRID] headers: {dict(response.headers)}')
    print(f'[SENDGRID] body: {response.body}')

    return ms, response.status_code

# ----------------------------
# Flask Routes
# ----------------------------

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
        user = USERS[session['pending_user']]
        session['mfa_start_ts'] = time.time()

        if method == 'sms':
            otp = generate_otp()
            session['otp'] = otp
            session['otp_ts'] = time.time()
            session['method'] = 'sms'

            try:
                ms, sid = send_sms(user['phone'], otp)
                print(f'[INFO] SMS requested successfully | sid: {sid} | time_ms: {ms}')
                return redirect('/verify')
            except Exception as e:
                session.pop('otp', None)
                session.pop('otp_ts', None)
                session.pop('method', None)
                error = f'SMS error: {e}'

        elif method == 'email':
            otp = generate_otp()
            session['otp'] = otp
            session['otp_ts'] = time.time()
            session['method'] = 'email'

            try:
                ms, status_code = send_email(user['email'], otp)
                print(f'[INFO] EMAIL requested successfully | status_code: {status_code} | time_ms: {ms}')
                return redirect('/verify')
            except Exception as e:
                session.pop('otp', None)
                session.pop('otp_ts', None)
                session.pop('method', None)
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
    if 'method' not in session or 'pending_user' not in session:
        return redirect('/')

    method = session['method']
    username = session['pending_user']
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
        else:
            otp_ts = session.get('otp_ts', 0)
            stored_otp = session.get('otp', '')

            if time.time() - otp_ts > 300:
                error = 'Code expired. Go back and request a new one.'
            elif hmac.compare_digest(code, stored_otp):
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