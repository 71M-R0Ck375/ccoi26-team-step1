'''
Solution 1: Reversing
'''
print("---Reversing---")
cipher = b""

with open("challenge.bin", "rb") as fd:
	cipher = fd.read()

for key in range(1, 81):
	try:
		data = bytes((((b ^ key) & 255) - 2) for b in cipher)
		if data.lower().startswith(b"ccoi"):
			print(data)
	except:
		pass

'''
Solution 2: Brute forcing
'''
print("\n---Brute forcing---")
cipher = b""

with open("challenge.bin", "rb") as fd:
	cipher = fd.read()

for key in range(1, 81):
	data = b""
	for elt in cipher:
		for c in range(33, 126):
			if elt == ((c + 2) & 255) ^ key:
				data += str(chr(c)).encode()
				break

	if data.lower().startswith(b"ccoi"):
		print(data)