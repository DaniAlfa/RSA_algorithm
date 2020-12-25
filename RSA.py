## Programa para encriptar o desencriptar un texto usando claves publica y privada segun el algoritmo RSA
## Se pueden generar las claves con el programa RSAKeyGen.py
## Los comandos que recibe el programa son:
##   maxbytes n alphabetLenght :: Returns the max bytes per RSA block for modulus n and a specific alphabet lenght
##   encrypt m e n :: Returns the message 'm' encryption by the public key (e,n), being m an Int
##   decrypt c d n :: Returns the message 'c' decryption by the private key (e,n), being c an Int
##   test :: Makes a visual test of RSA
##
## Copyright (c) 2020 Daniel Alfaro Miranda

from math import log, floor
import sys
from RSAKeyGen import genRSAKeys, printKeys

def asciiToNum(message):  ##Funcion para convertir un mensaje a un numero siguiendo el alfabeto ASCII
    num = 0
    for i, char in enumerate(message):
        num += ord(char) * (256**i)
    return num

def numToAscii(num):  ##Funcion para convertir un numero a un mensaje siguiendo el alfabeto ASCII
    message = ""
    while num >= 256:
        num, r = divmod(num, 256)
        message += chr(r)
    message += chr(num)
    return message

def MaxBytesPerBlock(n, alphabetLenght): ##Recibe el modulo y la longitud del alfabeto y devuelve el tamaño maximo del bloque RSA en bytes
    return floor(log(n, alphabetLenght))

def Encrypt(m, e, n): ##Recibe el mensaje y la clave publica
    return pow(m, e, n) ## m^e mod n

def Decrypt(c, d, n): ##Recibe el texto cifrado y la clave privada
    return pow(c, d, n) ## c^d mod n


def TestRSA():
    keys = genRSAKeys(1024)
    print(":: Clave utilizada de 1024 bits")
    n = keys[0] * keys[1]
    maxBytes = MaxBytesPerBlock(n, 256)
    printKeys(keys)
    print("")
    message = input(":: Introduce un mensaje con longitud máxima de {} carácteres para encriptar:".format(maxBytes))
    print("")
    m = asciiToNum(message)
    c = Encrypt(m, keys[2], n)
    cryptMessage = numToAscii(c)
    m2 = Decrypt(c, keys[3], n)
    decryptedMessage = numToAscii(m2)

    print("::  Proceso de encriptacion:")
    print("::  Mensaje codificado al número:", m)
    print("::  Número encriptado:", c)
    print("::  Número encriptado, decodificado al mensaje:", cryptMessage)
    print("")
    print("::  Proceso de desencriptacion para validacion:")
    print("::  Desencriptación del número:", m2)
    print("::  Mensaje decodificado:", decryptedMessage)
    print("")
    if message == decryptedMessage: print("::  Los mensajes después del proceso son iguales")
    else: print("::  Los mensajes después del proceso no son iguales")


def ExecuteCommands():
    if sys.argv[1] == "maxbytes" and len(sys.argv) == 4:
        print("Max Bytes per block:", MaxBytesPerBlock(int(sys.argv[2]), int(sys.argv[3])))
        return True
    elif sys.argv[1] == "encrypt" and len(sys.argv) == 5:
        print("Encrypted Number:", Encrypt(int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])))
        return True
    elif sys.argv[1] == "decrypt" and len(sys.argv) == 5:
        print("Decrypted Number:", Decrypt(int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])))
        return True
    elif sys.argv[1] == "test":
        TestRSA()
        return True
    print("Error in format of command.", file=sys.stderr)
    return False


if __name__ == '__main__':
    if len(sys.argv) < 2 or not(ExecuteCommands()):
        print("Help:", sys.argv[0], "<command> <<arguments>>.")
        print("--Existing commands are:")
        print("----maxbytes n alphabetLenght :: Returns the max bytes per RSA block for modulus n and a specific alphabet lenght")
        print("----encrypt m e n :: Returns the message 'm' encryption by the public key (e,n), being m an Int")
        print("----decrypt c d n :: Returns the message 'c' decryption by the private key (e,n), being c an Int")
        print("----test :: Makes a visual test of RSA")
        sys.exit(0)