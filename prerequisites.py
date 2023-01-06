import subprocess
import sys
import runpy

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

#installing packages
install('pycryptodome')
install('matplotlib')
install('pandas')
install('ecdsa')
install('cryptography')