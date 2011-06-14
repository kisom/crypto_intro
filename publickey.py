# -*- coding: utf-8 -*-
# file: publickey.py
# author: kyle isom <coder@kyleisom.net>
# 
# example RSA public key cryptography code

import Crypto.PublicKey.RSA
import Crypto.Random.OSRNG.posix

def load_key(filename):
    try:
        f = open(filename)
    except IOError as e:
        print e
        raise
    else:
        key = Crypto.PublicKey.RSA.importKey(f.read())
        f.close()
    return key

def generate_key(size):
    PRNG    = Crypto.Random.OSRNG.posix.new().read
    key     = Crypto.PublicKey.RSA.generate(size, PRNG)

    return key

def encrypt(key, message):
    ciphertext  = key.encrypt(message, None)
    ciphertext  = ciphertext[0]

    return ciphertext

def decrypt(key, message):
    plaintext   = key.decrypt(message)
    return plaintext
