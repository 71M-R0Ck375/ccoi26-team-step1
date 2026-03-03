cipher = b""
with open("challenge.bin", "rb") as fd:
    cipher = fd.read()
    
KEY_MIN = 1
KEY_MAX = 80
PARTS = 4

vals = [b for b in cipher]
n = len(vals)

sizes = [n // PARTS] * PARTS
for i in range(n % PARTS):
    sizes[i] += 1

chunks = []
p = 0
for s in sizes:
    chunks.append(vals[p:p + s])
    p += s

flag = b""
for elt in chunks:
    for k in range(KEY_MIN, KEY_MAX + 1):
           enc = bytearray()
           for i, v in enumerate(elt):
                 x = v ^ k
                 x = (x & 255) - i
                 if x < 33 or x > 125:
                      break
                 tmp = str(chr(x))
                 
                 if not tmp.isalnum() and tmp not in "{}@_":
                         break
                 enc.append(x)
		   
           if len(enc) == len(elt):
                if len(flag) == 0 and b"ccoi" not in bytes(enc).lower():
                       continue
                flag += bytes(enc)
                break

print(flag)