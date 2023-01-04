from cProfile import label
from turtle import width
from Crypto.Cipher import ChaCha20
import json
from base64 import b64decode, b64encode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

from Crypto.Hash import SHA384,SHA512,SHA3_384,SHA3_512

from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

from Crypto.Random import get_random_bytes

from ecdsa import SigningKey, NIST521p

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


from matplotlib import pyplot as plt
import numpy as np
import binascii
import time

import pandas as pd

num_exec = 1 #total executions
num_exec_RSA = 1 #executions for RSA only

data = b'Capoo' #message for AES_ECB
header = b'header' #for AES-CBC

test_vectors=[b'', b'1234567890', b'0000000000000000', b'1111111111111111', b'abcdefghijklmnopqrstuvwxyz']
keyTest256=b'abcdefghijklmnopqrstuvwxyz123456' #32 bytes * 8 bits de cada caracter = clave de 256 bits :)
testPassphrase=b'1234567890'

def timeChaCha20(message): ### Proceso de cifrado con el algoritmo ChaCha20
  cipher = ChaCha20.new(key=keyTest256) # Se utiliza la llave propuesta de prueba para cifrado y descifrado

  # Proceso de cifrado
  timeChaCha20encrypt = time.perf_counter() # Se inicia a contabilizar el tiempo
  ciphertext = cipher.encrypt(message) # Se obtiene texto cifrado
  timeChaCha20encrypt = round(time.perf_counter() - timeChaCha20encrypt, 10) # Se termina de contabilizar el tiempo

  # Proceso de descifrado
  nonce = b64encode(cipher.nonce).decode('utf-8') # Generación de nonce para descifrado
  nonce = b64decode(nonce)
  decipher = ChaCha20.new(key=keyTest256,nonce=nonce) # Se utiliza la llave propuesta y el nonce
  timeChaCha20decrypt = time.perf_counter() # Se inicia a contabilizar el tiempo
  plaintext = decipher.decrypt(ciphertext) # Se obtiene texto plano
  timeChaCha20decrypt = timeChaCha20decrypt = round(time.perf_counter() - timeChaCha20decrypt, 10) # Se termina de contabilizar el tiempo

  return timeChaCha20encrypt, timeChaCha20decrypt # Se devuelven los tiempos obtenidos en cifrado y descifrado. 

def timesAES_CBC(message):
  # Proceso de cifrado
  cipher = AES.new(keyTest256, AES.MODE_CBC)
  timeAES_CBC_encrypt = time.perf_counter() # Se inicia a contabilizar el tiempo
  ciphertext = cipher.encrypt(pad(message,32)) # Se cifra la información
  iv = cipher.iv
  timeAES_CBC_encrypt = round(time.perf_counter() - timeAES_CBC_encrypt, 6) # Se termina de contabilizar el tiempo

  # Proceso de descifrado
  cipher = AES.new(keyTest256, AES.MODE_CBC, iv)
  timeAES_CBC_decrypt = time.perf_counter() # Se inicia a contabilizar el tiempo
  plaintext = cipher.decrypt(ciphertext) # Obtención de información en texto plano
  timeAES_CBC_decrypt = round(time.perf_counter() - timeAES_CBC_decrypt, 6) # Se termina de contabilizar el tiempo

  return timeAES_CBC_encrypt, timeAES_CBC_decrypt # Se devuelven los tiempos obtenidos en cifrado y descifrado. 

def timesAES_ECB(message):
  key = get_random_bytes(32)
  cipher = AES.new(keyTest256, AES.MODE_ECB)

  #Time to encrypt
  timeAES_ECB_encrypt = time.perf_counter()
  ciphertext = cipher.encrypt(pad(message,32))
  timeAES_ECB_encrypt = round(time.perf_counter() - timeAES_ECB_encrypt, 10)

  #Time to decrypt
  timeAES_ECB_decrypt = time.perf_counter()
  plaintext = cipher.decrypt(binascii.unhexlify(binascii.hexlify(ciphertext)))
  timeAES_ECB_decrypt = round(time.perf_counter() - timeAES_ECB_decrypt, 10)

  return timeAES_ECB_encrypt, timeAES_ECB_decrypt # Se devuelven los tiempos obtenidos en cifrado y descifrado. 

def timeSHAs(message): ### Proceso de hash con la familia SHA 
  ## Algoritmos SHA-2
  h = SHA384.new() 
  timeSHA2_384 = time.perf_counter() # Se inicia a contabilizar el tiempo
  h.update(message) # Proceso de hash
  timeSHA2_384 = round(time.perf_counter() - timeSHA2_384, 10) # Se termina de contabilizar el tiempo

  h2 = SHA512.new()
  timeSHA2_512 = time.perf_counter() # Se inicia a contabilizar el tiempo
  h2.update(message) # Proceso de hash
  timeSHA2_512 = round(time.perf_counter() - timeSHA2_512, 10) # Se termina de contabilizar el tiempo

  ## Algoritmos SHA-3
  h3 = SHA3_384.new()
  timeSHA3_384 = time.perf_counter() # Se inicia a contabilizar el tiempo
  h3.update(message) # Proceso de hash
  timeSHA3_384 = round(time.perf_counter() - timeSHA3_384,10) # Se termina de contabilizar el tiempo

  h4 = SHA3_512.new()
  timeSHA3_512 = time.perf_counter() # Se inicia a contabilizar el tiempo
  h4.update(message) # Proceso de hash
  timeSHA3_512 = round(time.perf_counter() - timeSHA3_512,10) # Se termina de contabilizar el tiempo

  return timeSHA2_384,timeSHA2_512,timeSHA3_384,timeSHA3_512 # Se devuelven los tiempos obtenidos con los diferentes hash. 

def timeRSA_OAEP(keyPair, message): ### Proceso de cifrado con el algoritmo RSA OAEP
  # Clave pública y privada
  pubKey = keyPair.publickey()
  pubKeyPEM = pubKey.exportKey()
  privKeyPEM = keyPair.exportKey()

  # Proceso de cifrado
  encryptor = PKCS1_OAEP.new(pubKey) # Objeto a utilizar
  timeRSA_OAEP_encrypt = time.perf_counter() # Se inicia a contabilizar el tiempo
  encrypted = encryptor.encrypt(message)
  timeRSA_OAEP_encrypt = round(time.perf_counter() - timeRSA_OAEP_encrypt, 10) # Se termina de contabilizar el tiempo

  # Proceso de descifrado
  decryptor = PKCS1_OAEP.new(keyPair)
  timeRSA_OAEP_decrypt = time.perf_counter() # Se inicia a contabilizar el tiempo
  decrypted = decryptor.decrypt(encrypted)
  timeRSA_OAEP_decrypt = round(time.perf_counter() - timeRSA_OAEP_decrypt, 10) # Se termina de contabilizar el tiempo

  return timeRSA_OAEP_encrypt, timeRSA_OAEP_decrypt # Se devuelven los tiempos obtenidos en cifrado y descifrado.

def timeRSA_PSS(key, message): # Proceso de firma y verificación con RSA
  # Exportamos las claves públicas y privadas y las guardamos en un archivo
  private_key = key.export_key(passphrase=testPassphrase)
  with open("private.pem", "wb") as f:
    f.write(private_key)

  public_key = key.publickey().export_key()
  with open("public.pem", "wb") as f:
    f.write(public_key)

  # Proceso de firma
  key2 = RSA.import_key(open('private.pem').read(), testPassphrase) # Importación de la clave privada
  h = SHA256.new(message)
  timeRSAPSS_sign = time.perf_counter() # Se inicia a contabilizar el tiempo
  signature = pss.new(key2).sign(h) # Firma con clave privada
  timeRSAPSS_sign = round(time.perf_counter() - timeRSAPSS_sign, 10) # Se termina de contabilizar el tiempo

  # Proceso de verificación
  key2 = RSA.import_key(open('public.pem').read(), testPassphrase) # Importación de la clave púlica
  h = SHA256.new(message) 
  verifier = pss.new(key2) 
  timeRSAPSSVerify = time.perf_counter() # Se inicia a contabilizar el tiempo
  try:
    verifier.verify(h, signature) # Verificación con clave pública
  except (ValueError, TypeError):
    print("The signature is not authentic.")
  timeRSAPSSVerify = round(time.perf_counter() - timeRSAPSSVerify, 10) # Se termina de contabilizar el tiempo

  return timeRSAPSS_sign, timeRSAPSSVerify  # Se devuelven los tiempos obtenidos en verificación y firma

def timeECDSA_prime(sk, message): # Proceso de firma y verificación con ECDSA Prime
  vk = sk.verifying_key

  # Proceso de firma
  timeECDSA_prime_sign = time.perf_counter() # Se inicia a contabilizar el tiempo
  signature = sk.sign(message) # Firma de los datos
  timeECDSA_prime_sign = round(time.perf_counter() - timeECDSA_prime_sign, 10) # Se termina de contabilizar el tiempo

  # Proceso de verificación 
  timeECDSA_prime_ver = time.perf_counter() # Se inicia a contabilizar el tiempo
  assert vk.verify(signature, message) # Verificación de los datos
  timeECDSA_prime_ver = round(time.perf_counter() - timeECDSA_prime_ver, 10) # Se termina de contabilizar el tiempo

  return timeECDSA_prime_sign,timeECDSA_prime_ver

def timesECDSA_bin(private_key,public_key, message):
  # Proceso de firma
  timeECDSA_bin_sign = time.perf_counter() # Se inicia a contabilizar el tiempo
  signature = private_key.sign(message,ec.ECDSA(hashes.SHA256())) # Firma de los datos
  timeECDSA_bin_sign = round(time.perf_counter() - timeECDSA_bin_sign, 10) # Se termina de contabilizar el tiempo

  # Proceso de verificación
  timeECDSA_bin_verify = time.perf_counter() # Se inicia a contabilizar el tiempo
  public_key.verify(signature,message,ec.ECDSA(hashes.SHA256())) # Verificación de los datos
  timeECDSA_bin_verify = round(time.perf_counter() - timeECDSA_bin_verify, 10) # Se termina de contabilizar el tiempo

  return timeECDSA_bin_sign,timeECDSA_bin_verify

def printTable(datos, filas): 
  columnas = ['Vector 1', 'Vector 2', 'Vector 3', 'Vector 4', 'Vector 5']
  df=pd.DataFrame(datos, columns=columnas, index=filas)
  print(df)

def main():
  # Arreglos para conteo de tiempo
  timeChaCha20encrypt = []
  timeChaCha20decrypt = []
  timeAES_CBC_encrypt = []
  timeAES_CBC_decrypt = []
  timeAES_ECB_encrypt = []
  timeAES_ECB_decrypt = []
  timeSHA2_384 = []
  timeSHA2_512 = []
  timeSHA3_384 = []
  timeSHA3_512 = []
  timeRSA_OAEP_encrypt = []
  timeRSA_OAEP_decrypt = []
  timeRSA_PSS_sign = []
  timeRSA_PSS_verify = []
  timeECDSA_prime_sign = []
  timeECDSA_prime_verify = []
  timeECDSA_bin_sign = []
  timeECDSA_bin_verify = []

  print('Ejecutando conteo de tiempos con ChaCha20...')
  for x in range(5):
    aux1,aux2 = timeChaCha20(test_vectors[x])
    timeChaCha20encrypt.append(aux1)
    timeChaCha20decrypt.append(aux2)
  print('Fin de ejecución de Chacha20.')

  print('Ejecutando conteo de tiempos con AES-CBC')
  for x in range(5):
    aux1,aux2 = timesAES_CBC(test_vectors[x])
    timeAES_CBC_encrypt.append(aux1)
    timeAES_CBC_decrypt.append(aux2)
  print('Fin de ejecución de AES-CBC.')
  
  print('Ejecutando conteo de tiempos con AES-ECB')
  for x in range(5):
    aux1,aux2 = timesAES_ECB(test_vectors[x])
    timeAES_ECB_encrypt.append(aux1)
    timeAES_ECB_decrypt.append(aux2)
  print('Fin de ejecución de AES-ECB.')

  print('Ejecutando conteo de tiempos con la familia SHA-2 Y SHA-3')
  for x in range(5):
    aux1,aux2,aux3,aux4 = timeSHAs(test_vectors[x])
    timeSHA2_384.append(aux1)
    timeSHA2_512.append(aux2)
    timeSHA3_384.append(aux3)
    timeSHA3_512.append(aux4)
  print('Fin de ejecución de SHA-2 Y SHA-3.')

  print('Ejecutando conteo de tiempos con RSA-OAEP')
  # Generamos las llaves previamente ya que es un proceso muy lento.
  keyPair = RSA.generate(1024)
  for x in range(5):
    aux1,aux2 = timeRSA_OAEP(keyPair, test_vectors[x])
    timeRSA_OAEP_encrypt.append(aux1)
    timeRSA_OAEP_decrypt.append(aux2)
  print('Fin de ejecución de RSA-OAEP.')

  print('Ejecutando conteo de tiempos con RSA-PSS')
  PSSKey = RSA.generate(1024)
  for x in range(5):
    aux1,aux2 = timeRSA_PSS(PSSKey, test_vectors[x])
    timeRSA_PSS_sign.append(aux1)
    timeRSA_PSS_verify.append(aux2)
  print('Fin de ejecución de RSA-PSS.')

  print('Ejecutando conteo de tiempos con ECDSA Prime')
  sk = SigningKey.generate(curve=NIST521p)
  for x in range(5):
    aux1,aux2 = timeECDSA_prime(sk, test_vectors[x])
    timeECDSA_prime_sign.append(aux1)
    timeECDSA_prime_verify.append(aux2)
  print('Fin de ejecución de ECDSA Prime.')

  print('Ejecutando conteo de tiempos con ECDSA Binary')
  private_key = ec.generate_private_key(ec.SECT571R1())
  public_key = private_key.public_key()
  for x in range(5):
    aux1,aux2 = timesECDSA_bin(private_key,public_key, test_vectors[x])
    timeECDSA_bin_sign.append(aux1)
    timeECDSA_bin_verify.append(aux2)
  print('Fin de ejecución de ECDSA Binary.')

  # Impresión de resultados
  print('\n\n *** IMPRESIÓN DE RESULTADOS DE TIEMPO *** \n')

  algCifrado = ['ChaCha20','AES-CBC','AES-ECB','RSA-OAEP']
  algDescifrado = ['ChaCha20','AES-CBC','AES-ECB','RSA-OAEP']
  algHash = ['SHA2-384','SHA2-512','SHA3-384','SHA3-512']
  algFirma = ['RSA-PSS','ECDSA-Prime','ECDSA-Binary']
  algVerificacion = ['RSA-PSS','ECDSA-Prime','ECDSA-Binary']

  print('\n\n * Cifrado')
  datos = [timeChaCha20encrypt, timeAES_CBC_encrypt,timeAES_ECB_encrypt, timeRSA_OAEP_encrypt]
  printTable(datos, algCifrado)

  print('\n\n * Descifrado')
  datos = [timeChaCha20decrypt, timeAES_CBC_decrypt,timeAES_ECB_decrypt, timeRSA_OAEP_decrypt]
  printTable(datos, algDescifrado )

  print('\n\n * Hashing')
  datos = [timeSHA2_384, timeSHA2_512, timeSHA3_384, timeSHA3_512]
  printTable(datos, algHash)

  print('\n\n * Firma')
  datos = [timeRSA_PSS_sign, timeECDSA_prime_sign, timeECDSA_bin_sign]
  printTable(datos, algFirma)

  print('\n\n * Verificación')
  datos = [timeRSA_PSS_verify, timeECDSA_prime_verify, timeECDSA_bin_verify]
  printTable(datos, algVerificacion)

  # Gráficas tiempos de cifrado
  x=np.arange(5)
  width=0.2

  plt.title("Cifrado")
  plt.bar(x-0.2, timeChaCha20encrypt, width, color='cyan')
  plt.bar(x, timeAES_CBC_encrypt, width, color='orange')
  plt.bar(x+0.2, timeAES_ECB_encrypt, width, color='green')
  plt.bar(x+0.4, timeRSA_OAEP_encrypt, width, color='red')

  plt.xticks(x, ['Vector 1', 'Vector 2', 'Vector 3', 'Vector 4', 'Vector 5'])
  plt.xlabel("Vectores")
  plt.ylabel("Tiempos")
  plt.legend(algCifrado)
  plt.show()

  # Gráficas tiempos de descifrado
  x=np.arange(5)
  width=0.2

  plt.title("Descifrado")
  plt.bar(x-0.2, timeChaCha20decrypt, width, color='cyan')
  plt.bar(x, timeAES_CBC_decrypt, width, color='orange')
  plt.bar(x+0.2, timeAES_ECB_decrypt, width, color='green')
  plt.bar(x+0.4, timeRSA_OAEP_decrypt, width, color='red')

  plt.xticks(x, ['Vector 1', 'Vector 2', 'Vector 3', 'Vector 4', 'Vector 5'])
  plt.xlabel("Vectores")
  plt.ylabel("Tiempos")
  plt.legend(algDescifrado)
  plt.show()

  # Gráficas tiempos de hashing
  x=np.arange(5)
  width=0.2

  plt.title("Hashing")
  plt.bar(x-0.2, timeSHA2_384, width, color='cyan')
  plt.bar(x, timeSHA2_512, width, color='orange')
  plt.bar(x+0.2, timeSHA3_384, width, color='green')
  plt.bar(x+0.4, timeSHA3_512, width, color='red')

  plt.xticks(x, ['Vector 1', 'Vector 2', 'Vector 3', 'Vector 4', 'Vector 5'])
  plt.xlabel("Vectores")
  plt.ylabel("Tiempos")
  plt.legend(algHash)
  plt.show()

  # Gráficas tiempos de firma
  x=np.arange(5)
  width=0.2

  plt.title("Firma")
  plt.bar(x-0.2, timeRSA_PSS_sign, width, color='cyan')
  plt.bar(x, timeECDSA_prime_sign, width, color='orange')
  plt.bar(x+0.2, timeECDSA_bin_sign, width, color='green')

  plt.xticks(x, ['Vector 1', 'Vector 2', 'Vector 3', 'Vector 4', 'Vector 5'])
  plt.xlabel("Vectores")
  plt.ylabel("Tiempos")
  plt.legend(algFirma)
  plt.show()

  # Gráficas tiempos de verificación
  x=np.arange(5)
  width=0.2

  plt.title("Verificación")
  plt.bar(x-0.2, timeRSA_PSS_verify, width, color='cyan')
  plt.bar(x, timeECDSA_prime_verify, width, color='orange')
  plt.bar(x+0.2, timeECDSA_bin_verify, width, color='green')

  plt.xticks(x, ['Vector 1', 'Vector 2', 'Vector 3', 'Vector 4', 'Vector 5'])
  plt.xlabel("Vectores")
  plt.ylabel("Tiempos")
  plt.legend(algVerificacion)
  plt.show()

if __name__ == '__main__':
  main()