# RSA_algorithm
Implementation of RSA algorithm in python

## RSA.py
Program to encrypt or decrypt text using RSA

The commands of the program are:

  -maxbytes n alphabetLenght :: Returns the max bytes per RSA block for modulus n and a specific alphabet lenght
  
  -encrypt m e n :: Returns the message 'm' encryption by the public key (e,n), being m an Int
  
  -decrypt c d n :: Returns the message 'c' decryption by the private key (e,n), being c an Int
  
  -test :: Makes a visual test of RSA
  
## RSAKeyGen.py
Program to generate public and private keys for RSA

It gets as parameter the size in bits of the keys (must be > 50)
