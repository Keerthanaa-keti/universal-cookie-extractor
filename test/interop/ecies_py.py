"""ECIES interop spike (Python side): X25519 -> HKDF-SHA256 -> AES-256-GCM."""
import base64, json, os, sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HKDF_SALT = bytes(32)
HKDF_INFO = b'cookie-vault-v3/dek-wrap'

def b64(b): return base64.b64encode(b).decode()
def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def fb64(s): return base64.b64decode(s)
def fb64url(s):
    s = s + '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def derive(shared):
    return HKDF(algorithm=SHA256(), length=32, salt=HKDF_SALT, info=HKDF_INFO).derive(shared)

def seal(dek, recipient_pub_raw):
    eph = X25519PrivateKey.generate()
    eph_pub_raw = eph.public_key().public_bytes_raw()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub_raw))
    key = derive(shared)
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, dek, None)   # tag appended
    return {'epk': b64url(eph_pub_raw), 'iv': b64(iv), 'ct': b64(ct)}

def unseal(wrap, recipient_priv_raw):
    priv = X25519PrivateKey.from_private_bytes(recipient_priv_raw)
    shared = priv.exchange(X25519PublicKey.from_public_bytes(fb64url(wrap['epk'])))
    key = derive(shared)
    return AESGCM(key).decrypt(fb64(wrap['iv']), fb64(wrap['ct']), None)

if __name__ == '__main__':
    mode = sys.argv[1]
    if mode == 'genkey':
        p = X25519PrivateKey.generate()
        print(json.dumps({'pub': b64url(p.public_key().public_bytes_raw()),
                          'priv': b64url(p.private_bytes_raw())}))
    elif mode == 'seal':
        pub = fb64url(sys.argv[2]); dek = fb64(sys.argv[3])
        print(json.dumps(seal(dek, pub)))
    elif mode == 'unseal':
        priv = fb64url(sys.argv[2]); wrap = json.loads(sys.argv[3])
        print(b64(unseal(wrap, priv)))
    elif mode == 'selftest':
        p = X25519PrivateKey.generate()
        pub = p.public_key().public_bytes_raw(); priv = p.private_bytes_raw()
        dek = os.urandom(32)
        w = seal(dek, pub)
        print('py selftest match:', unseal(w, priv) == dek)
