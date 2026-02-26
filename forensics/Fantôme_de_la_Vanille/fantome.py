import base64

payload = 'ymHNxXIjUXxF0TlCNoBCsLxOtuIkSlk5Es07WgWFc975Tra9LkpZOxbXfFM=h-'
md5_hex = '8922828c40152a0a71bf082e5ab41d81'

# 2. Nettoyage et Décodage
# On retire d'éventuels caractères parasites à la fin (comme le 'h-') pour le base64
clean_payload = payload.split('=')[0] + '=' * (len(payload_b64) % 4)
payload_bytes = base64.b64decode(payload.split('h-')[0])

key_bytes = bytes.fromhex(md5_hex)

result = ""
for i in range(len(payload_bytes)):
    char_xor = payload_bytes[i] ^ key_bytes[i % len(key_bytes)]
    result += chr(char_xor)

print(f"Le Flag est : {result}")
