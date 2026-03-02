import hashlib
import base64

challenge1_author = 'OCOI2026'
challenge2_codename = 'SPECTRE_sNODE'

payload_b64 = 'x9Gmy8/cQ7kmcfp3GV67+PbN2fLOmAyhIyakRiUA5rnooZ2xot5f5nxilXp2Xfu7tP/Y8YA='

md5_codename = hashlib.md5(challenge2_codename.encode()).hexdigest()
md5_author   = hashlib.md5(challenge1_author.encode()).hexdigest()

key_bytes = bytes(a ^ b for a, b in zip(bytes.fromhex(md5_codename), bytes.fromhex(md5_author)))

payload_bytes = base64.b64decode(payload_b64)

result = ""
for i in range(len(payload_bytes)):
    char_xor = payload_bytes[i] ^ key_bytes[i % len(key_bytes)]
    result += chr(char_xor)

print(f"Le Flag est : {result}")