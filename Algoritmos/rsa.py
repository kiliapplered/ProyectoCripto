from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import binascii

################# RSA OAEP #################

print("RSA OAEP")

keyPair = RSA.generate(2048)

pubKey = keyPair.publickey()
print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
pubKeyPEM = pubKey.exportKey()
print(pubKeyPEM.decode('ascii'))

print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
privKeyPEM = keyPair.exportKey()
print(privKeyPEM.decode('ascii'))

msg = b'A message for encryption'
encryptor = PKCS1_OAEP.new(pubKey)
encrypted = encryptor.encrypt(msg)
print("Encrypted:", binascii.hexlify(encrypted))

decryptor = PKCS1_OAEP.new(keyPair)
decrypted = decryptor.decrypt(encrypted)
print('Decrypted:', decrypted)

################# RSA PSS #################

print("RSA PSS")

# Generar pareja de claves RSA de 2048 bits de longitud
key = RSA.generate(2048)

# Passphrase para encriptar la clave privada
secret_code = "12345"

# Exportamos la clave privada
private_key = key.export_key(passphrase=secret_code)

# Guardamos la clave privada en un fichero
with open("private.pem", "wb") as f:
    f.write(private_key)

# Obtenemos la clave pública
public_key = key.publickey().export_key()

# Guardamos la clave pública en otro fichero
with open("public.pem", "wb") as f:
    f.write(public_key)

message = b'To be signed'
key2 = RSA.import_key(open('private.pem').read(), secret_code)
h = SHA256.new(message)
signature = pss.new(key2).sign(h)

key2 = RSA.import_key(open('public.pem').read(), secret_code)
h = SHA256.new(message)
verifier = pss.new(key2)
try:
    verifier.verify(h, signature)
    print("The signature is authentic.")
except (ValueError, TypeError):
    print("The signature is not authentic.")