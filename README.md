#  Cryptography 🔐
## Final Project 
_________________
---
This project consists of a program that compares the efficiency of the algorithms listed below. The program generates a set of test vectors for each algorithm and, after execution, displays the results of each algorithm using graphs according to the goals shared and operations.
The operations are:
- Encryption 🔒
- Decryption 🔓
-  Hashing  #️⃣
-  Signing ✍️
- Verifying ✅

The algorithms to compare and analyze are the following:

| Algorithm | Size |
| ------ | ------ |
| Chacha20 | Key Size 256 bits |
| AES-EBC | Key Size 256 bits |
| AES-CBC | Key Size 256 bits |
| SHA-2 | Hash size 384 bits |
| SHA-2 | Hash size 512 bits |
| SHA-3 | Hash size 384 bits |
| SHA-3 | Hash size 512 bits |
| RSA-OAEP | 1024 bits |
| RSA-PSS | 1024 bits |
| ECDSA Prime Field | ECDSA, 521 Bits (Prime Field) |
| ECDSA Binary Field |ECDSA, 571 Bits (Binary Field, Koblitz Curve)|

### Modules 
---
To execute the program is it necessary to have python3 installed. Also, this project uses a number of modules to get the algorithms, graphics and for a properly working:
- pycryptodome -- crypto algorithms.
 - cryptography -- crypto algorithms.
- matplotlib --used to graph.
- ecdsa -- eliptic curves algorithms.
- pandas -- used for tables printing.

If you don´t have them installed, you can do it with the following command:
```sh
cd <PATH_OF_THE_PROJECT>
python3 prerequisites.py
```

### Running the program
---
Follow the next commands:

```sh
cd <PATH_OF_THE_PROJECT>
python3 main.py
```
