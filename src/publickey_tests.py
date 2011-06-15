#!/usr/bin/env python
# -*- coding: utf-8 -*-
# file: publickey_tests.py
# author: kyle isom <coder@kyleisom.net>
#
# tests for the public key example code 


import publickey
import os
import sys         


# set up flush to force printing status messages during key generation
flush = sys.stdout.flush

def test_keygen():
    print '\t[+] generating 1024 bit RSA key... ',
    flush()
    key = publickey.generate_key(size = 1024)
    assert( key.size() == 1023 )
    print 'OK!'

    print '\t[+] generating 2048 bit RSA key... ',
    flush()
    key = publickey.generate_key(size = 2048)
    assert( key.size() == 2047 )
    print 'OK!'

    print '\t[+] generating 4096 bit RSA key... ',
    flush()
    key = publickey.generate_key(size = 4096)
    assert( key.size() == 4095 )
    print 'OK!'


def test_crypto():
    message = 'This is a test message. 0123456789ABCDEF'
    print '\t[+] generating a 2048-bit RSA key... ',
    flush()
    key     = publickey.generate_key( 2048 )
    assert( key.size() == 2047 )
    print 'OK!'

    print '\t[+] can we encrypt with this key? ',
    flush()
    assert( key.can_encrypt() )
    print 'yes'

    print '\t[+] encrypting \'%s\'...' % message
    print '\t[+] using %d-bit RSA key' % (key.size() + 1)

    ct      = publickey.encrypt( key, message )
    pt      = publickey.decrypt( key, ct )

    print '\t[+] decryped ciphertext as \'%s\'' % pt
    assert( pt == message )


def test_key_export():
    print '\t[+] generating 2048-bit RSA test key... ',
    flush()
    masterkey   = publickey.generate_key( 2048 )
    print 'OK!'
    
    print '[+] exporting keypair to disk...'
    publickey.export_keypair( 'publickey_tests', masterkey )

    print '\t[+] attempting to reload keypair from disk... ',
    pubkey      = publickey.load_key( 'publickey_tests.pub' )
    prvkey      = publickey.load_key( 'publickey_tests.prv' )

    assert( prvkey.has_private() )
    assert( not pubkey.has_private() )

    print 'OK!'

    assert( pubkey == prvkey.publickey() )
    print '\t[+] cleaning up... ',

    try:
        os.unlink('publickey_tests.pub')
        os.unlink('publickey_tests.prv')
    except OSError as e:
        print 'FAILED!'
        print '\t[!] failed cleanup: %s' % e

        # failure to cleanup isn't a failure of the crypto library
        return
    else:
        print 'OK!'
        print '\t[+] cleanup successful!'

if __name__ == '__main__':
    print '[+] beginning RSA tests'

    print '[+] beginning key generation tests'
    test_keygen()
    print '[+] successfully completed key generation test!'

    print '[+] testing encryption and decryption'
    test_crypto()
    print '[+] successfully completed RSA tests'

    print '[+] testing key exports and imports'
    test_key_export()
    print '[+] successfully completed export / import test!'

    print '[+] successfully passed all tests!'
