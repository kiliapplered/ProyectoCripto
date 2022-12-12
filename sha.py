from Crypto.Hash import SHA384,SHA512,SHA3_384,SHA3_512

h = SHA384.new()
h.update(b'Hello')
print(h.hexdigest())

print("_______________")

h2 = SHA512.new()
h2.update(b'Hello')
print(h2.hexdigest())

print("_______________")

h_obj = SHA3_384.new()
h_obj.update(b'Hello')
print(h_obj.hexdigest())

print("_______________")

h_obj2 = SHA3_512.new()
h_obj2.update(b'Some data')
print(h_obj2.hexdigest())