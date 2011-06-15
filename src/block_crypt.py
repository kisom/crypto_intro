#!/usr/bin/env python
# -*- coding: utf-8 -*-
# file: block_crypt.py
# author: kyle isom <coder@kyleisom.net>
#
# test code to demonstrate practical use of crypto code

import base64
import block
import getopt
import sys

def dump(filename, data):
    try:
        f = open(filename, 'w')
    except IOError as e:
        print e
        raise
    else:
        f.write(data)
        f.close()

def load(filename):
    try:
        f = open(filename)
    except IOError as e:
        print e
        raise
    else:
        data = f.read()
        f.close()
        return data

def gen_key(filename):
    key = block.generate_aes_key()

    dump(filename, key)

def encrypt_file(filename, keyfile, crypted_filename = None, 
                 ascii_armour = False):
    if not crypted_filename:
        crypted_filename    = filename + '.aes256'

    plaintext               = load(filename)
    iv                      = block.generate_nonce()
    key                     = load(keyfile)
    ciphertext              = block.encrypt(key, plaintext, iv, ascii_armour)

    print '[+] encrypted %s to %s...' % (filename, crypted_filename)
    dump(crypted_filename, ciphertext)
    print '[+] file written...'

def decrypt_file( filename, keyfile, ivfile, decrypted_filename = None ):
    if not decrypted_filename:
        decrypted_filename  = filename.rstrip('.aes256')

    ciphertext              = load(filename)

    key                     = load(keyfile)
    plaintext               = block.decrypt(key, ciphertext)

    print '[+] decrypted %s to %s...' % (filename, decrypted_filename)
    dump(decrypted_filename, plaintext)
    print '[+] file written...'

def main(operation, keyfile, input_filename, output_filename, ascii_armour):
    
    if 'generate_key' == operation:
        assert( output_filename )
        gen_key( output_filename )

    elif 'encrypt_file' == operation:
        assert( input_filename )
        assert( keyfile )
        encrypt_file( input_filename, keyfile, output_filename, ascii_armour )

    elif 'decrypt_file' == operation:
        assert( input_filename )
        assert( keyfile )
        decrypt_file( input_filename, keyfile, output_filename )

    sys.exit(0)

if __name__ == '__main__':
    input_filename  = None
    output_filename = None
    keyfile         = None
    operation       = None
    ascii_armour    = False

    opts, args = getopt.getopt(sys.argv[1:], 'f:o:k:i:adeg')

    for opt, val in opts:
        opt = opt.lstrip('-')
        if   'f' == opt:
            input_filename = val
        elif 'o' == opt:
            output_filename = val
        elif 'k' == opt:
            keyfile = val
        elif 'a' == opt:
            ascii_armour = True
        elif 'd' == opt:
            operation = 'decrypt_file'
        elif 'e' == opt:
            operation = 'encrypt_file'
        elif 'g' == opt:
            operation = 'generate_key'

    main( operation, keyfile, input_filename, output_filename, ascii_armour )
