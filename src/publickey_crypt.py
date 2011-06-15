#!/usr/bin/env python
# -*- coding: utf-8 -*-
# file: publickey_crypt.py
# author: kyle isom <coder@kyleisom.net>
#
# test code to demonstrate practical use of crypto code

import base64
import getopt
import publickey
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

def gen_key(filename, size):
    key = publickey.generate_key(size)

    print '\t[+] generated a %d-bit RSA key' % (key.size() + 1)
    publickey.export_key( filename, key )
    print '\t[+] exported private key to %s' % filename

def encrypt_file(filename, keyfile, crypted_filename = None, 
                 ascii_armour = False):
    if not crypted_filename:
        crypted_filename    = filename + '.rsa'

    plaintext               = load(filename)
    key                     = publickey.load_key(keyfile)
    ciphertext              = publickey.encrypt(key, plaintext)

    if not ascii_armour:
        ciphertext          = '\x00' + ciphertext
    else:
        ciphertext          = 'A' + base64.encodestring(ciphertext)

    print '[+] encrypted %s to %s...' % (filename, crypted_filename)
    dump(crypted_filename, ciphertext)
    print '[+] file written...'

def decrypt_file( filename, keyfile, decrypted_filename = None ):
    if not decrypted_filename:
        decrypted_filename  = filename.rstrip('.rsa')

    ciphertext              = load(filename)

    if '\x00' == ciphertext[0]:
        ciphertext = ciphertext[1:]
    elif 'A' == ciphertext[0]:
        ciphertext = base64.decodestring(ciphertext[1:])

    iv                      = load(ivfile)
    key                     = load(keyfile)
    plaintext               = publickey.decrypt(key, ciphertext)

    print '[+] decrypted %s to %s...' % (filename, decrypted_filename)
    dump(decrypted_filename, plaintext)
    print '[+] file written...'

def main(operation, keyfile, input_filename, output_filename, bitsize, 
         ascii_armour):
    
    if 'generate_key' == operation:
        assert( output_filename )
        assert( bitsize )
        gen_key( output_filename, bitsize )

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
    bitsize         = 1024

    opts, args = getopt.getopt(sys.argv[1:], 'b:f:o:k:i:adeg')

    for opt, val in opts:
        opt = opt.lstrip('-')

        if   'b' == opt:
            bitsize = int(val)
        elif 'f' == opt:
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

    main( operation, keyfile, input_filename, output_filename, bitsize, 
          ascii_armour )
