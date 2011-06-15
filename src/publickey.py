# -*- coding: utf-8 -*-
# file: publickey.py
# author: kyle isom <coder@kyleisom.net>
# 
# example RSA public key cryptography code

import Crypto.PublicKey.RSA
import Crypto.Random.OSRNG.posix

import base64

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

def export_key(filename, key):
    if key.has_private():
        print '\t[+] exporting secret key to %s... ' % filename, 
    else:
        print '\t[+] exporting public key to %s... ' % filename,     
    try:
        f = open(filename, 'w')
    except IOError as e:
        print e
        raise
    else:
        f.write( key.exportKey() )
        f.close()
        print 'OK!'

def export_pubkey(filename, key):
    print '\t[+] exporting public key to %s... ' % filename, 
    try: 
        f = open(filename, 'w')
    except IOError as e:
        print e
        raise
    else:
        f.write( key.publickey().exportKey() )
        f.close()
        print 'OK!'

def export_keypair(basename, key):
    pubkeyfile   = basename + '.pub'
    prvkeyfile   = basename + '.prv'

    export_key(prvkeyfile, key)
    export_pubkey(pubkeyfile, key)


def generate_key(size):
    PRNG    = Crypto.Random.OSRNG.posix.new().read
    key     = Crypto.PublicKey.RSA.generate(size, PRNG)

    return key

def encrypt(key, message, armour = True):
    ciphertext  = key.encrypt( message, None )
    ciphertext  = ciphertext[0]

    if armour:
        ciphertext = '\x41' + base64.encodestring( ciphertext )
    else:
        ciphertext = '\x00' + ciphertext

    return ciphertext

def decrypt(key, message):
    if   '\x00' == message[0]:
        message = message[1:]
    elif '\x41' == message[0]:
        message = base64.decodestring( message[1:] )

    plaintext   = key.decrypt( message )
    return plaintext
