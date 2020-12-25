## Programa para generar claves publica y privada para el algoritmo RSA
## Recibe como parametro el tamaño en bits de las claves (debe ser mayor que 50)
##
## Copyright (c) 2020 Daniel Alfaro Miranda

from secrets import randbelow, randbits
import sys

def isPrime(n, k = 8): ##Test de primalidad de Miller-Rabin (Retorna que es primo con probabilidad de error de 1/(4^k))
    if n == 2 or n == 3: return True
    if n < 2 or n % 2 == 0: return False
    d = n - 1
    r = 0
    while d % 2 == 0: ##Se escribe n - 1 como 2^r * d siendo r el mayor exponente y d impar
        d //= 2
        r += 1

    for _ in range(k):
        a = 1
        while a < 2: a = randbelow(n - 1) ## Se genera un numero aleatorio [2, n-1)
        x = pow(a, d, n) ## x = a^d mod n
        if x != 1 and x != n - 1: ## Si la primera potencia falla se comprueba hasta la r - 1
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == 1: return False ## Si x == 1 significa que el anterior numero != 1 y != -1 es una raiz de la unidad no trivial
                if x == n - 1: break
            else: return False
    return True

def mcd(a, b): ##Algoritmo extendido de euclides
    if a <= 0 or b <= 0: return 0,0,0
    if b > a: a,b = b,a
    q = 0
    alfa0 = beta1 = 1
    alfa1 = beta0 = 0
    while b != 0:
        t = divmod(a,b)
        a = b
        q,b = t
        alfa0 = alfa0 - q * alfa1
        alfa1, alfa0 = alfa0, alfa1
        beta0 = beta0 - q * beta1
        beta1, beta0 = beta0, beta1
    return a,alfa0,beta0

def genLargePrime(kBitLength): ##Funcion que genera un primo grande de k bits
    while True:
        p = randbits(kBitLength - 2)
        p = (p << 1) | 1
        p = p | (1 << kBitLength - 1)
        if isPrime(p): return p

def genRSAValidPrimes(kBitLenght): ##Funcion que genera dos primos p y q validos para RSA
    p = genLargePrime(kBitLenght // 2)
    q = genLargePrime(kBitLenght // 2)
    while q == p: q = genLargePrime(kBitLenght // 2)
    return p, q

def genPublicPrivateKeys(p, q):  ##Funcion que genera la clave publica y privada valida para RSA
    phi = (p-1)*(q-1)
    e = 65537
    return e, mcd(phi, e)[2] % phi

def genRSAKeys(kBitLenght): ##Devuelve tupla (p, q, e, d) con los primos, la clave publica y privada
    primes = genRSAValidPrimes(kBitLenght)
    e, d = genPublicPrivateKeys(primes[0], primes[1]) ##Se generan 1<e<phi(n) y su inverso mod phi(n)
    return primes[0], primes[1], e, d

def printKeys(keys):
    print(":: Modulus Value N:", keys[0] * keys[1])
    print(":: First Prime p:", keys[0])
    print(":: Second Prime q:", keys[1])
    print(":: Public Key e:", keys[2])
    print(":: Private Key d:", keys[3])


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Help:", sys.argv[0], "<bitLenght> to generate RSA Keys. bitLenght must be > 50.")
        sys.exit(0)
    try:
        bitLenght = int(sys.argv[1])
        if bitLenght < 50: raise ValueError("bitLenght under 50")
    except ValueError as ex:
        print("Error:", ex, file=sys.stderr)
        print("Help:", sys.argv[0], "<bitLenght> to generate RSA Keys. bitLenght must be > 50.")
        sys.exit(-1)

    keys = genRSAKeys(bitLenght)
    printKeys(keys)
    sys.exit(0)