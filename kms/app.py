from flask import Flask, request, jsonify
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import base64
import uuid

app = Flask(__name__)

KEK = b'\x01' * 32  # 256-bit key (AES-256-GCM)

KEYS = {}

def wrap_dek(plain_dek: bytes) -> str:
    cipher = AES.new(KEK, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_dek)
    blob = cipher.nonce + tag + ciphertext
    return base64.b64encode(blob).decode("ascii")

def unwrap_dek(wrapped_b64: str) -> bytes:
    blob = base64.b64decode(wrapped_b64)
    nonce = blob[:16]
    tag = blob[16:32]
    ciphertext = blob[32:]
    cipher = AES.new(KEK, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

@app.get("/health")
def health():
    return jsonify({"status": "alive"})

@app.post("/keys")
def create_key():
    dek = get_random_bytes(32)  # 256-bit DEK
    key_id = uuid.uuid4().hex

    wrapped = wrap_dek(dek)
    KEYS[key_id] = {"wrapped": wrapped}

    return jsonify({
        "key_id": key_id,
        "dek_hex": dek.hex(),
        "wrapped": wrapped
    }), 201

@app.get("/keys/<key_id>")
def get_key_metadata(key_id):
    meta = KEYS.get(key_id)
    if not meta:
        return jsonify({"error": "key not found"}), 404

    return jsonify({
        "key_id": key_id,
        "wrapped": meta["wrapped"]
    })

@app.get("/keys/<key_id>/dek")
def get_dek(key_id):
    meta = KEYS.get(key_id)
    if not meta:
        return jsonify({"error": "key not found"}), 404

    dek = unwrap_dek(meta["wrapped"])
    return jsonify({
        "key_id": key_id,
        "dek_hex": dek.hex()
    })

@app.delete("/keys/<key_id>")
def delete_key(key_id):
    if key_id in KEYS:
        del KEYS[key_id]
        return jsonify({"status": "deleted"})

    return jsonify({"error": "key not found"}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
