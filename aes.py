from Crypto.Cipher import AES
import binascii


key = b'ABCDEFGHIJIKLMOP'
msg = b'Mensaje en claro'

#CIFRADO
cipher = AES.new(key, AES.MODE_ECB)
msg_en = cipher.encrypt(msg)

print(binascii.hexlify(msg_en))

print("--------")

#DESCIFRADO
decipher = AES.new(key, AES.MODE_ECB)
msg_dec = decipher.decrypt(binascii.unhexlify(binascii.hexlify(msg_en))) # Decipher akzeptiert und Binary kein Hex

print(msg_dec)