import base64
import hashlib
from Crypto.Cipher import DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


def otp_encrypt(plaintext, key):
    pt_bytes  = plaintext.encode()
    key_bytes = key.encode()
    cipher    = bytes(pt_bytes[i] ^ key_bytes[i % len(key_bytes)]
                      for i in range(len(pt_bytes)))
    return base64.b64encode(cipher).decode()


def otp_decrypt(ciphertext, key):
    cipher    = base64.b64decode(ciphertext)
    key_bytes = key.encode()
    plain     = bytes(cipher[i] ^ key_bytes[i % len(key_bytes)]
                      for i in range(len(cipher)))
    return plain.decode()


def _prepare_3des_key(key):
    return hashlib.sha256(key.encode()).digest()[:24]


def triple_des_encrypt(plaintext, key):
    kb     = _prepare_3des_key(key)
    cipher = DES3.new(kb, DES3.MODE_CBC, kb[:8])
    return base64.b64encode(cipher.encrypt(pad(plaintext.encode(), DES3.block_size))).decode()


def triple_des_decrypt(ciphertext, key):
    kb     = _prepare_3des_key(key)
    cipher = DES3.new(kb, DES3.MODE_CBC, kb[:8])
    return unpad(cipher.decrypt(base64.b64decode(ciphertext)), DES3.block_size).decode()


def _prepare_aes_key(key):
    return hashlib.md5(key.encode()).digest()


def aes_encrypt(plaintext, key):
    kb     = _prepare_aes_key(key)
    cipher = AES.new(kb, AES.MODE_CBC, kb[:16])
    return base64.b64encode(cipher.encrypt(pad(plaintext.encode(), AES.block_size))).decode()


def aes_decrypt(ciphertext, key):
    kb     = _prepare_aes_key(key)
    cipher = AES.new(kb, AES.MODE_CBC, kb[:16])
    return unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size).decode()


def rsa_generate_keys(bits=2048):
    key = RSA.generate(bits)
    return key.export_key().decode(), key.publickey().export_key().decode()


def rsa_encrypt(plaintext, public_key_pem):
    pub    = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(pub)
    return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()


def rsa_decrypt(ciphertext, private_key_pem):
    priv   = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(priv)
    return cipher.decrypt(base64.b64decode(ciphertext)).decode()