import os
from flask import Flask, redirect, url_for, session, render_template, request, jsonify
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from crypto import (otp_encrypt, otp_decrypt,
                    triple_des_encrypt, triple_des_decrypt,
                    aes_encrypt, aes_decrypt,
                    rsa_generate_keys, rsa_encrypt, rsa_decrypt)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-me')

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)


# ── Pages ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    user = session.get('user')
    if not user:
        return render_template('login.html')
    return render_template('app.html', user=user)


@app.route('/login')
def login():
    redirect_uri = url_for('auth_callback', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/auth/callback')
def auth_callback():
    token     = google.authorize_access_token()
    user_info = token.get('userinfo')
    session['user'] = {
        'name':    user_info['name'],
        'email':   user_info['email'],
        'picture': user_info['picture']
    }
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


# ── Symmetric API ──────────────────────────────────────────────────────────

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    if not session.get('user'):
        return jsonify({'error': 'Not authenticated'}), 401
    data    = request.json
    algo    = data.get('algorithm')
    message = data.get('message', '')
    key     = data.get('key', '')
    try:
        if algo == 'OTP':
            result = otp_encrypt(message, key)
        elif algo == '3DES':
            result = triple_des_encrypt(message, key)
        elif algo == 'AES':
            result = aes_encrypt(message, key)
        else:
            return jsonify({'error': 'Unknown algorithm'}), 400
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    if not session.get('user'):
        return jsonify({'error': 'Not authenticated'}), 401
    data       = request.json
    algo       = data.get('algorithm')
    ciphertext = data.get('ciphertext', '')
    key        = data.get('key', '')
    try:
        if algo == 'OTP':
            result = otp_decrypt(ciphertext, key)
        elif algo == '3DES':
            result = triple_des_decrypt(ciphertext, key)
        elif algo == 'AES':
            result = aes_decrypt(ciphertext, key)
        else:
            return jsonify({'error': 'Unknown algorithm'}), 400
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ── RSA API ────────────────────────────────────────────────────────────────

@app.route('/api/rsa/generate', methods=['POST'])
def rsa_gen():
    if not session.get('user'):
        return jsonify({'error': 'Not authenticated'}), 401
    bits = int(request.json.get('bits', 2048))
    try:
        priv, pub = rsa_generate_keys(bits)
        return jsonify({'private_key': priv, 'public_key': pub})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/rsa/encrypt', methods=['POST'])
def rsa_enc():
    if not session.get('user'):
        return jsonify({'error': 'Not authenticated'}), 401
    data = request.json
    try:
        result = rsa_encrypt(data['message'], data['public_key'])
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/rsa/decrypt', methods=['POST'])
def rsa_dec():
    if not session.get('user'):
        return jsonify({'error': 'Not authenticated'}), 401
    data = request.json
    try:
        result = rsa_decrypt(data['ciphertext'], data['private_key'])
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True)