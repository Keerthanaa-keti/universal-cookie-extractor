"""Interop harness around the REAL Python module lib/python/vault_crypto.py.
Reads one JSON command from stdin, prints one JSON result to stdout."""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib", "python"))
import vault_crypto as V  # noqa: E402


def main():
    req = json.load(sys.stdin)
    cmd = req["cmd"]
    if cmd == "genkey":
        pub, priv = V.generate_server_keypair()
        out = {"publicKey": pub, "privateKey": priv}
    elif cmd == "owner-salt":
        out = {"salt": V.generate_owner_salt()}
    elif cmd == "make-entry":
        dek = V.generate_dek()
        payload = V.encrypt_cookies(req["cookies"], dek)
        out = {
            **payload,
            "server_wrap": V.seal_dek_for_server(dek, req["serverPub"]),
            "owner_wrap": V.wrap_dek_for_owner(dek, req["passphrase"], req["ownerSalt"]),
        }
    elif cmd == "read-entry-server":
        e = req["entry"]
        dek = V.unseal_dek_for_server(e["server_wrap"], req["priv"])
        out = {"cookies": V.decrypt_cookies(e["ciphertext"], e["iv"], dek)}
    elif cmd == "read-entry-owner":
        e = req["entry"]
        dek = V.unwrap_dek_for_owner(e["owner_wrap"], req["passphrase"])
        out = {"cookies": V.decrypt_cookies(e["ciphertext"], e["iv"], dek)}
    elif cmd == "seal":
        out = V.seal_dek_for_server(base64.b64decode(req["dek"]), req["serverPub"])
    elif cmd == "unseal":
        dek = V.unseal_dek_for_server(req["wrap"], req["priv"])
        out = {"dek": base64.b64encode(dek).decode()}
    else:
        out = {"error": "unknown cmd " + cmd}
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
