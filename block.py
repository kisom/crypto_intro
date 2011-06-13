# -*- coding: utf-8 -*-
# file: block.py
# author: kyle isom <coder@kyleisom.net>
#
# AES block cipher examples for the article "Introduction to Cryptography
# Using Python and PyCrypto".

# PyCrypto imports
import Crypto.Cipher.AES
import Crypto.Random.OSRNG.posix
import Crypto.Hash.MD5

# other imports
import time

# constants
BLOCK_SIZE = 16

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
    i = len(data) - 1
    for i in range(i, 0, -1):
        if not data[i] in [ '\x80', '\x00' ]:
            return data
        if data[i] == '\x80':
            break
    return data[:i]

def generate_nonce():
    rnd = Crypto.Random.OSRNG.posix.new().read(BLOCK_SIZE)
    rnd = '%s%s' % (rnd, str(time.time()))
    nonce = Crypto.Hash.MD5.new(data = rnd)
    
    return nonce.digest()
