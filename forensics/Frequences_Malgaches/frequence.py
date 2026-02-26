import base64
import hashlib

def xor_data(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

cipher_b64 = "TvMkR4/JaawTmqFDbrfJJj3UWFHezyKtB5ydGi60uHA6iFJRiMo861eR80o="
cipher_bytes = base64.b64decode(cipher_b64)

key_raw = bytes.fromhex("0db06b0ebdff12df63a9c2371c849648")
result_raw = xor_data(cipher_bytes, key_raw)

print(result_raw.decode(errors='ignore'))
