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

num_exec = 1000 #total executions
num_exec_RSA = 1000 #executions for RSA only


keyChaCha = get_random_bytes(32) #key de 256 para ChaCha20

data = b'data' #message for AES_ECB
header = b'header' #for AES-GCM

def timesChaCha20():
  cipher = ChaCha20.new(key=keyChaCha)

  #Time to encrypt
  timeChaCha20encrypt = time.perf_counter()
  ciphertext = cipher.encrypt(data)
  timeChaCha20encrypt = round(time.perf_counter() - timeChaCha20encrypt, 6)

  nonce = b64encode(cipher.nonce).decode('utf-8')
  nonce = b64decode(nonce)
  decipher = ChaCha20.new(key=keyChaCha,nonce=nonce)
  #Time to decrypt
  timeChaCha20decrypt = time.perf_counter()
  plaintext = decipher.decrypt(ciphertext)
  timeChaCha20decrypt = timeChaCha20decrypt = round(time.perf_counter() - timeChaCha20decrypt, 6)

  #This is only for showing coded message purposes
  #nonce = b64encode(cipher.nonce).decode('utf-8')
  #ct = b64encode(ciphertext).decode('utf-8')
  #print(json.dumps({'nonce':nonce, 'ciphertext':ct}))

  return timeChaCha20encrypt, timeChaCha20decrypt

def timesAES_GCM():
  key = get_random_bytes(32)
  nonce = get_random_bytes(12)
  cipher = AES.new(key, AES.MODE_GCM, nonce= nonce)
  #cipher.update(header)

  #Encryption time
  timeAES_GCM_encrypt = time.perf_counter()
  ciphertext,tag = cipher.encrypt_and_digest(data)
  timeAES_GCM_encrypt = round(time.perf_counter() - timeAES_GCM_encrypt, 6)

  #json_k = ['nonce','header','ciphertext','tag']
  #json_v = [b64encode(x).decode('utf-8') for x in [cipher.nonce,header,ciphertext,tag]]
  #result = json.dumps(dict(zip(json_k,json_v)))
  #This is only for showing coded message purposes
  #print(result)

  #b64 = json.loads(result)
  #json_k = ['nonce','header','ciphertext','tag']
  #jv = {k:b64decode(b64[k]) for k in json_k}

  decipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
  #decipher.update(jv['header'])
  #Decryption time
  timeAES_GCM_decrypt = time.perf_counter()
  plaintext = decipher.decrypt(ciphertext)
  timeAES_GCM_decrypt = round(time.perf_counter() - timeAES_GCM_decrypt, 6)

  return timeAES_GCM_encrypt, timeAES_GCM_decrypt

def timesAES_ECB():
  key = get_random_bytes(32)
  cipher = AES.new(key, AES.MODE_ECB)

  #Time to encrypt
  timeAES_ECB_encrypt = time.perf_counter()
  ciphertext = cipher.encrypt(pad(data,32))
  timeAES_ECB_encrypt = round(time.perf_counter() - timeAES_ECB_encrypt, 6)

  #Time to decrypt
  timeAES_ECB_decrypt = time.perf_counter()
  plaintext = cipher.decrypt(binascii.unhexlify(binascii.hexlify(ciphertext)))
  timeAES_ECB_decrypt = round(time.perf_counter() - timeAES_ECB_decrypt, 6)

  #This is only for showing coded message purposes
  #print(ciphertext)

  return timeAES_ECB_encrypt, timeAES_ECB_decrypt

def timesSHA():
  h = SHA384.new()
  timeSHA2_384 = time.perf_counter()
  h.update(b'data')
  timeSHA2_384 = round(time.perf_counter() - timeSHA2_384, 6)
  #print(h.hexdigest())

  h2 = SHA512.new()
  timeSHA2_512 = time.perf_counter()
  h2.update(b'data')
  timeSHA2_512 = round(time.perf_counter() - timeSHA2_512, 6)
  #print(h2.hexdigest())

  h_obj = SHA3_384.new()
  timeSHA3_384 = time.perf_counter()
  h_obj.update(b'data')
  timeSHA3_384 = round(time.perf_counter() - timeSHA3_384,6)
  #print(h_obj.hexdigest())

  h_obj2 = SHA3_512.new()
  timeSHA3_512 = time.perf_counter()
  h_obj2.update(b'data')
  timeSHA3_512 = round(time.perf_counter() - timeSHA3_512,6)
  #print(h_obj2.hexdigest())

  return timeSHA2_384,timeSHA2_512,timeSHA3_384,timeSHA3_512

def timesRSA_OAEP(keyPair):
  pubKey = keyPair.publickey()
  #print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
  pubKeyPEM = pubKey.exportKey()
  #print(pubKeyPEM.decode('ascii'))

  #print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
  privKeyPEM = keyPair.exportKey()
  #print(privKeyPEM.decode('ascii'))

  msg = b'data'
  encryptor = PKCS1_OAEP.new(pubKey)

  #Encryption time
  timeRSA_OAEP_encrypt = time.perf_counter()
  encrypted = encryptor.encrypt(msg)
  timeRSA_OAEP_encrypt = round(time.perf_counter() - timeRSA_OAEP_encrypt, 6)
  #print("Encrypted:", binascii.hexlify(encrypted))

  decryptor = PKCS1_OAEP.new(keyPair)

  #Decryption time
  timeRSA_OAEP_decrypt = time.perf_counter()
  decrypted = decryptor.decrypt(encrypted)
  timeRSA_OAEP_decrypt = round(time.perf_counter() - timeRSA_OAEP_decrypt, 6)
  #print('Decrypted:', decrypted)

  return timeRSA_OAEP_encrypt, timeRSA_OAEP_decrypt

def timesRSA_PSS(key):
  #########################################################
  #                GENERACIÓN DE LA CLAVE                 #
  #########################################################

  # Generar pareja de claves RSA de 2048 bits de longitud
  #key = RSA.generate(2048)

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

  timeRSAPSS_sign = time.perf_counter()
  signature = pss.new(key2).sign(h)
  timeRSAPSS_sign = round(time.perf_counter() - timeRSAPSS_sign, 6)

  key2 = RSA.import_key(open('public.pem').read(), secret_code)
  h = SHA256.new(message)
  verifier = pss.new(key2)

  #Tomamos tiempo
  timeRSAPSSVerify = time.perf_counter()
  try:
    verifier.verify(h, signature)
    #print("The signature is authentic.")
  except (ValueError, TypeError):
    print("The signature is not authentic.")
  timeRSAPSSVerify = round(time.perf_counter() - timeRSAPSSVerify, 6)

  return timeRSAPSS_sign, timeRSAPSSVerify

def timesECDSA_prime(sk):
  #sk = SigningKey.generate(curve=NIST521p)
  vk = sk.verifying_key

  #time to sign
  timeECDSA_prime_sign = time.perf_counter()
  signature = sk.sign(b"data")
  timeECDSA_prime_sign = round(time.perf_counter() - timeECDSA_prime_sign, 6)

  #time to verify
  timeECDSA_prime_ver = time.perf_counter()
  assert vk.verify(signature, b"data")
  timeECDSA_prime_ver = round(time.perf_counter() - timeECDSA_prime_ver, 6)

  return timeECDSA_prime_sign,timeECDSA_prime_ver

def timesECDSA_bin(private_key,public_key):
  #private_key = ec.generate_private_key(ec.SECT571R1())
  data = b"data"

  timeECDSA_bin_sign = time.perf_counter()
  signature = private_key.sign(data,ec.ECDSA(hashes.SHA256()))
  timeECDSA_bin_sign = round(time.perf_counter() - timeECDSA_bin_sign, 6)
  #print(signature)

  timeECDSA_bin_ver = time.perf_counter()
  public_key.verify(signature,data,ec.ECDSA(hashes.SHA256()))
  timeECDSA_bin_ver = round(time.perf_counter() - timeECDSA_bin_ver, 6)

  return timeECDSA_bin_sign,timeECDSA_bin_ver

#Graph data vs time
#x and y are lists of our indexes values
#x = algorithm
#y = time
def impresion(x,y,graph_title,x_label,y_label):
  plt.style.use('fivethirtyeight')

  bar_width = 0.25
  x_indexes = np.arange(len(x))

  plt.bar(x_indexes, y, width= bar_width, label = 'a')

  plt.title(graph_title)
  plt.xlabel(x_label)
  plt.ylabel(y_label)

  #plt.legend()

  plt.xticks(ticks = x_indexes, labels = x)
  plt.xticks()

  plt.grid(True)

  plt.tight_layout()

  plt.show()


def main():
  
  #List of algorithms to display in xlabel of graph
  cypherList = ['ChaCha20','AES-GCM','AES-ECB','RSA-OAEP']#,'RSA-OAEP']
  decypherList = ['ChaCha20','AES-GCM','AES-ECB','RSA-OAEP']#,'RSA-OAEP']
  hashingList = ['SHA2-384','SHA2-512','SHA3-384','SHA3-512']#,'ECDSA-Prime','ECDSA-Binary']
  signingList = ['RSA-PSS','ECDSA-Prime','ECDSA-Binary']
  verifyingList = ['RSA-PSS','ECDSA-Prime','ECDSA-Binary']
  
  #List of times to display in ylabel of graphs
  #where our times will be stored
  cypherTimes = [] 
  decypherTimes = []
  hashingTimes = []
  signingTimes = []
  verifyingTimes = []

  #variables for time count
  #for ChaCha20:
  timeChaCha20encrypt = 0
  timeChaCha20decrypt = 0
  #for AES_GCM:
  timeAES_GCM_encrypt = 0
  timeAES_GCM_decrypt = 0
  #for AES_ECB
  timeAES_ECB_encrypt = 0
  timeAES_ECB_decrypt = 0
  #for SHAs
  timeSHA2_384 = 0
  timeSHA2_512 = 0
  timeSHA3_384 = 0
  timeSHA3_512 = 0
  #for RSA-OAEP
  timeRSA_OAEP_encrypt = 0
  timeRSA_OAEP_decrypt = 0
  #for RSA-PSS
  timeRSA_PSS_sign = 0
  timeRSA_PSS_verify = 0
  #for ecdsa_prime
  timeECDSA_prime_sign = 0
  timeECDSA_prime_verify = 0
  #for ecdsa_binary
  timeECDSA_bin_sign = 0
  timeECDSA_bin_ver = 0



  print('---------Inicio: ChaCha20---------')
  for x in range(0,num_exec):
    aux1,aux2 = timesChaCha20()
    timeChaCha20encrypt += aux1
    timeChaCha20decrypt += aux2
  cypherTimes.append(timeChaCha20encrypt)
  decypherTimes.append(timeChaCha20decrypt)
  print('---------Fin: ChaCha20---------\n')

  print('---------Inicio: AES-GCM---------')
  for x in range(0,num_exec):
    aux1,aux2 = timesAES_GCM()
    timeAES_GCM_encrypt += aux1
    timeAES_GCM_decrypt += aux2
  cypherTimes.append(timeAES_GCM_encrypt)
  decypherTimes.append(timeAES_GCM_decrypt)
  print('---------Fin: AES-GCM---------\n')
  
  print('---------Inicio: AES-ECB---------')
  for x in range(0,num_exec):
    aux1,aux2 = timesAES_ECB()
    timeAES_ECB_encrypt += aux1
    timeAES_ECB_decrypt += aux2
  cypherTimes.append(timeAES_ECB_encrypt)
  decypherTimes.append(timeAES_ECB_decrypt)
  print('---------Fin: AES-ECB---------\n')

  print('---------Inicio: SHAs---------')
  for x in range(0,num_exec):
    aux1,aux2,aux3,aux4 = timesSHA()
    timeSHA2_384 += aux1
    timeSHA2_512 += aux2
    timeSHA3_384 += aux3
    timeSHA3_512 += aux4
  hashingTimes.append(timeSHA2_384)
  hashingTimes.append(timeSHA2_512)
  hashingTimes.append(timeSHA3_384)
  hashingTimes.append(timeSHA3_512)
  print('---------Fin: SHAs---------\n')

  print('---------Inicio: RSA-OAEP---------')
  #generamos las llaves porque si no tarda muchísimo
  keyPair = RSA.generate(2048)
  for x in range(0,num_exec_RSA):
    aux1,aux2 = timesRSA_OAEP(keyPair)
    timeRSA_OAEP_encrypt += aux1
    timeRSA_OAEP_decrypt += aux2
    #print(x)
  cypherTimes.append(timeRSA_OAEP_encrypt)
  decypherTimes.append(timeRSA_OAEP_decrypt)
  print('---------Fin: RSA-OAEP---------\n')

  print('---------Inicio: RSA-PSS---------')
  PSSKey = RSA.generate(2048)
  for x in range(0,num_exec_RSA):
    aux1,aux2 = timesRSA_PSS(PSSKey)
    timeRSA_PSS_sign += aux1
    timeRSA_PSS_verify += aux2
  signingTimes.append(timeRSA_PSS_sign)
  verifyingTimes.append(timeRSA_PSS_verify)
  print('---------Fin: RSA-PSS---------\n')

  print('---------Inicio: ECDSA Prime---------')
  sk = SigningKey.generate(curve=NIST521p)
  for x in range(0,num_exec):
    aux1,aux2 = timesECDSA_prime(sk)
    timeECDSA_prime_sign += aux1
    timeECDSA_prime_verify += aux2
    print(x)
  signingTimes.append(timeECDSA_prime_sign)
  verifyingTimes.append(timeECDSA_prime_verify)
  print('---------Fin: ECDSA Prime---------')

  print('---------Inicio: ECDSA binary---------')
  private_key = ec.generate_private_key(ec.SECT571R1())
  public_key = private_key.public_key()
  for x in range(0,num_exec):
    aux1,aux2 = timesECDSA_bin(private_key,public_key)
    timeECDSA_bin_sign += aux1
    timeECDSA_bin_ver += aux2
    #print(x)
  signingTimes.append(timeECDSA_bin_sign)
  verifyingTimes.append(timeECDSA_bin_ver)
  print('---------Fin: ECDSA binary---------')

  print('***** Encryption Times:')
  print('ChaCha20: ' + str(timeChaCha20encrypt) + '\n'
    + 'AES-GCM: ' + str(timeAES_GCM_encrypt) + '\n'
    + 'AES-ECB: ' + str(timeAES_ECB_encrypt) + '\n'
    + 'RSA-OAEP: ' + str(timeRSA_OAEP_encrypt) + '\n\n')

  
  print('***** Decryption Times:')
  print('ChaCha20: ' + str(timeChaCha20decrypt) + '\n'
    + 'AES-GCM: ' + str(timeAES_GCM_decrypt) + '\n'
    + 'AES-ECB: ' + str(timeAES_ECB_decrypt) + '\n'
    + 'RSA-OAEP: ' + str(timeRSA_OAEP_decrypt) + '\n\n')

  print('***** Hashing Times:')
  print('SHA-2 384: ' + str(timeSHA2_384) + '\n'
    + 'SHA-2 512: ' + str(timeSHA2_512) + '\n'
    + 'SHA-3 384: ' + str(timeSHA3_384) + '\n'
    + 'SHA-3 512: ' + str(timeSHA3_512) + '\n\n')
  
  print('***** Signing Times:')
  print('RSA-PSS: ' + str(timeRSA_PSS_sign) + '\n'
    + 'ECDSA-Prime: ' + str(timeECDSA_prime_sign) + '\n'
    + 'ECDSA-Binary: ' + str(timeECDSA_bin_sign) + '\n\n')

  print('***** Verifying Times:')
  print('RSA-PSS: ' + str(timeRSA_PSS_verify) + '\n'
    + 'ECDSA-Prime: ' + str(timeECDSA_prime_verify) + '\n'
    + 'ECDSA-Binary: ' + str(timeECDSA_bin_ver) + '\n\n')

  #plot our encryption times
  graphtitle = "Encryption times for " + str(num_exec) + " iterations\n"
  graphtitle += "Note: RSA was executed " + str(num_exec_RSA) + " times"
  impresion(cypherList,cypherTimes,graphtitle,'Algorithm','Time in seconds')

  #plot our decryption times
  graphtitle = "Decryption times for " + str(num_exec) + " iterations\n"
  graphtitle += "Note: RSA was executed " + str(num_exec_RSA) + " times"
  impresion(decypherList,decypherTimes,graphtitle,'Algorithm','Time in seconds')

  #plot our hashing times
  graphtitle = "Hashing times for " + str(num_exec) + " iterations"
  impresion(hashingList,hashingTimes,graphtitle,'Algorithm','Time in seconds')

  #plot our sign times
  graphtitle = "Sign times for " + str(num_exec) + " iterations\n"
  graphtitle += "Note: RSA was executed " + str(num_exec_RSA) + " times"
  impresion(signingList,signingTimes,graphtitle,'Algorithm','Time in seconds')

  #plot our verification times
  graphtitle = "Verification times for " + str(num_exec) + " iterations\n"
  graphtitle += "Note: RSA was executed " + str(num_exec_RSA) + " times"
  impresion(verifyingList,verifyingTimes,graphtitle,'Algorithm','Time in seconds')

if __name__ == '__main__':
  main()