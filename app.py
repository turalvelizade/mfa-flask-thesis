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

# Create Flask app and load secret key from environment variable
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

# Test user for the MFA experiment
USERS = {
    'admin': {
        'password': 'admin',
        'email': 'mfatestingthesis@gmail.com',
        'phone': '+37126186263',
    }
}

# Twilio configuration
TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_TOKEN = os.getenv("TWILIO_TOKEN")
TWILIO_FROM = os.getenv("TWILIO_FROM")

# Email configuration
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# Local file used to store TOTP secrets
SECRETS_FILE = 'totp_secrets.json'

# In-memory tracking for SMS delivery callbacks
# Key = Twilio Message SID
# Value = {'sent_at': timestamp}
sms_tracking = {}


def load_secrets():
    """Load saved TOTP secrets from file."""
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_secrets(secrets):
    """Save TOTP secrets to file."""
    with open(SECRETS_FILE, 'w') as f:
        json.dump(secrets, f)


def get_totp_secret(username):
    """Get existing TOTP secret for user or create a new one."""
    secrets = load_secrets()
    if username not in secrets:
        secrets[username] = pyotp.random_base32()
        save_secrets(secrets)
    return secrets[username]


def generate_otp():
    """Generate a random 6-digit OTP."""
    return ''.join(random.choices(string.digits, k=6))


def send_sms(phone, otp):
    """
    Send SMS via Twilio.
    Measures:
    - API submission time (app -> Twilio accepted request)
    Stores:
    - sent_at timestamp for later delivery callback comparison
    """
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

    sms_tracking[message.sid] = {
        'sent_at': send_end
    }

    print(
        f'[MEASUREMENT] SMS | sid: {message.sid} | '
        f'api_submission_time_ms: {send_duration_ms}'
    )

    return send_duration_ms, message.sid


@app.route('/twilio-status', methods=['POST'])
def twilio_status():
    """
    Receive Twilio delivery status callbacks.
    Important:
    - This measures provider-confirmed delivery time
    - It does NOT necessarily equal the exact moment the user saw the SMS
    """
    message_sid = request.form.get('MessageSid')
    status = request.form.get('MessageStatus')
    now = time.time()

    print(
        f'[CALLBACK] SMS | sid: {message_sid} | '
        f'status: {status} | callback_time: {now}'
    )

    if message_sid in sms_tracking and status == 'delivered':
        sent_at = sms_tracking[message_sid]['sent_at']
        provider_delivery_time_ms = round((now - sent_at) * 1000, 2)

        print(
            f'[MEASUREMENT] SMS | sid: {message_sid} | '
            f'provider_delivery_time_ms: {provider_delivery_time_ms}'
        )

    return '', 200


def send_email(to_address, otp):
    """
    Send OTP via email using SMTP.
    Measures:
    - API submission time (app -> Gmail SMTP accepted request)
    """
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

    print(f'[MEASUREMENT] EMAIL | api_submission_time_ms: {ms}')

    return ms


def get_totp_qr(username):
    """Generate a QR code for TOTP enrollment."""
    secret = get_totp_secret(username)

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name='MFA Thesis'
    )

    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format='PNG')

    return base64.b64encode(buf.getvalue()).decode()


def verify_totp_code(username, code):
    """Verify the TOTP code entered by the user."""
    secret = get_totp_secret(username)
    return pyotp.TOTP(secret).verify(code, valid_window=1)


@app.route('/', methods=['GET', 'POST'])
def login():
    """Login page: verifies username/password before MFA step."""
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
    """
    MFA selection page.
    Starts the timing of the MFA process when the user chooses a method.
    """
    if 'pending_user' not in session:
        return redirect(url_for('login'))

    error = None

    if request.method == 'POST':
        method = request.form.get('method')
        username = session['pending_user']
        user = USERS[username]

        # Store the moment the MFA process starts
        session['mfa_start_ts'] = time.time()

        if method == 'sms':
            otp = generate_otp()

            session['otp'] = otp
            session['otp_ts'] = time.time()
            session['method'] = 'sms'

            try:
                send_duration_ms, sid = send_sms(user['phone'], otp)
                session['sms_sid'] = sid
                session['sms_send_duration_ms'] = send_duration_ms
                return redirect(url_for('mfa_verify'))
            except Exception as e:
                error = f'SMS error: {e}'

        elif method == 'email':
            otp = generate_otp()

            session['otp'] = otp
            session['otp_ts'] = time.time()
            session['method'] = 'email'

            try:
                send_duration_ms = send_email(user['email'], otp)
                session['email_send_duration_ms'] = send_duration_ms
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
    """
    MFA verification page.
    Measures user completion time:
    - time from MFA start to successful code entry
    """
    if 'pending_user' not in session or 'method' not in session:
        return redirect(url_for('login'))

    username = session['pending_user']
    method = session['method']
    error = None

    qr_b64 = get_totp_qr(username) if method == 'totp' else None

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        ok = False

        # This is the user-perceived completion metric
        mfa_start_ts = session.get('mfa_start_ts', time.time())

        if method == 'totp':
            verify_start = time.perf_counter_ns()
            ok = verify_totp_code(username, code)
            verify_end = time.perf_counter_ns()

            verification_processing_ms = round((verify_end - verify_start) / 1_000_000, 4)

            if ok:
                completion_time_ms = round((time.time() - mfa_start_ts) * 1000, 2)
                print(
                    f'[MEASUREMENT] TOTP | verification_processing_time_ms: {verification_processing_ms} | '
                    f'user_completion_time_ms: {completion_time_ms} | result: SUCCESS'
                )
            else:
                print(
                    f'[MEASUREMENT] TOTP | verification_processing_time_ms: {verification_processing_ms} | '
                    f'result: FAIL'
                )
                error = 'Invalid code. Check your authenticator app.'

        else:
            stored = session.get('otp')
            ts = session.get('otp_ts', 0)

            verify_start = time.perf_counter_ns()

            if time.time() - ts > 300:
                error = 'Code expired.'
            elif code != stored:
                error = 'Wrong code.'
            else:
                ok = True

            verify_end = time.perf_counter_ns()
            verification_processing_ms = round((verify_end - verify_start) / 1_000_000, 4)

            if ok:
                completion_time_ms = round((time.time() - mfa_start_ts) * 1000, 2)

                if method == 'sms':
                    print(
                        f'[MEASUREMENT] SMS | verification_processing_time_ms: {verification_processing_ms} | '
                        f'user_completion_time_ms: {completion_time_ms} | result: SUCCESS'
                    )
                elif method == 'email':
                    print(
                        f'[MEASUREMENT] EMAIL | verification_processing_time_ms: {verification_processing_ms} | '
                        f'user_completion_time_ms: {completion_time_ms} | result: SUCCESS'
                    )
            else:
                if method == 'sms':
                    print(
                        f'[MEASUREMENT] SMS | verification_processing_time_ms: {verification_processing_ms} | '
                        f'result: FAIL'
                    )
                elif method == 'email':
                    print(
                        f'[MEASUREMENT] EMAIL | verification_processing_time_ms: {verification_processing_ms} | '
                        f'result: FAIL'
                    )

        if ok:
            session.clear()
            session['user'] = username
            session['mfa_ok'] = True
            return redirect(url_for('dashboard'))

    return render_template('mfa_verify.html', method=method, qr_b64=qr_b64, error=error)


@app.route('/dashboard')
def dashboard():
    """Protected page shown only after successful MFA."""
    if not session.get('mfa_ok'):
        return redirect(url_for('login'))

    return render_template('dashboard.html', username=session.get('user'))


@app.route('/logout')
def logout():
    """Log user out and clear session."""
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)