BLOCK = 4

cipher = b""
with open("challenge.bin", "rb") as fd:
    cipher = fd.read()

tmp = bytearray()
for b in cipher:
    if 65 <= b <= 90:
        tmp.append(90 - (b - 65))
    elif 97 <= b <= 122:
        tmp.append(122 - (b - 97))
    else:
        tmp.append(b)

flag = bytearray()
for i in range(0, len(tmp), BLOCK):
    flag.extend(tmp[i:i + BLOCK][::-1])

print(bytes(flag))