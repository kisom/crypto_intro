# -*- coding: utf-8 -*-
# file: block.py
# author: kyle isom <coder@kyleisom.net>
#
# AES-256 block cipher examples for the article "Introduction to 
# Cryptography Using Python and PyCrypto".

# PyCrypto imports
import Crypto.Cipher.AES
import Crypto.Random.OSRNG.posix
import Crypto.Hash.MD5
import Crypto.Hash.SHA256

# other imports
import time

# constants
BLOCK_SIZE  = 16
KEY_SIZE    = 32
mode        = Crypto.Cipher.AES.MODE_CBC


def pad_data(data):
    # subtract one byte that should be the 0x80
    # if 0 bytes of padding are required, it means only
    # a single \x80 is required.

    if len(data) % BLOCK_SIZE == 0: 
        return data
    padding_required = (BLOCK_SIZE - 1) - (len(data) % BLOCK_SIZE)

    data = '%s\x80' % data
    data = '%s%s' % (data, '\x00' * padding_required)

    return data

def unpad_data(data):
    if not data: 
        return data

    data = data.rstrip('\x00')
    if data[-1] == '\x80':
        return data[:-1]
    else:
        return data

def generate_nonce():
    # use a POSIX RNG
    # if you are on a windows system you will probably need OSRNG.nt
    # you will also need to change the import at the beginning of the file.
    rnd = Crypto.Random.OSRNG.posix.new().read(BLOCK_SIZE)
    rnd = '%s%s' % (rnd, str(time.time()))
    nonce = Crypto.Hash.MD5.new(data = rnd)
    
    return nonce.digest()

# generate an AES-256 key from a passphrase
def passphrase(password, readable = False):
    """
    Converts a passphrase to a format suitable for use as an AES key.

    If readable is set to True, the key is output as a hex digest. This is
    suitable for sharing with users or printing to screen when debugging
    code.

    By default readable is set to False, in which case the value it 
    returns is suitable for use directly as an AES-256 key.
    """
    key     = Crypto.Hash.SHA256.new(password)
    
    if readable:
        return key.hexdigest()
    else:
        return key.digest()

# AES-256 encryption using a passphrase
def passphrase_encrypt(password, iv, data):
    key     = passphrase(password)
    data    = pad_data(data)
    aes     = Crypto.Cipher.AES.new(key, mode, iv)

    return aes.encrypt(data)

# AES-256 decryption using a passphrase
def passphrase_decrypt(password, iv, data):
    key     = passphrase(password)
    aes     = Crypto.Cipher.AES.new(key, mode, iv)
    data    = aes.decrypt(data)

    return unpad_data(data)

# generate a random AES-256 key
def generate_aes_key():
    rnd     = Crypto.Random.OSRNG.posix.new().read(KEY_SIZE)

    return rnd
    
def encrypt(key, iv, data):
    aes     = Crypto.Cipher.AES.new(key, mode, iv)
    data    = pad_data(data)

    return aes.encrypt(data)

def decrypt(key, iv, data):
    aes     = Crypto.Cipher.AES.new(key, mode, iv)
    data    = aes.decrypt(data)

    return unpad_data(data)

