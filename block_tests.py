#!/usr/bin/env python
# -*- coding: utf-8 -*-
# file: block_tests.py
# author: kyle isom <coder@kyleisom.net>
# 
# tests for the block encryption example code

import block

# test to ensure data can be padded to the proper length and then unpadded
# and that the original message is not distorted in the process
def test_padding():
    # test from empty block to full block
    for i in range(17):
        print '\t[+] testing input size %d...' % i,
        data = 'A' * i
        assert(len(data) == i)
        
        padded = block.pad_data(data)
        assert( len(padded) % 16 == 0 )

        unpadded = block.unpad_data(padded)
        assert( len(unpadded) == i )
        assert( unpadded == data )

        print 'OK!'

# ensure that the nonces generated are the proper size
def test_nonce():
    nonces = [ ]
    for i in range(1024):
        nonce = block.generate_nonce()
        assert( not nonce in nonces )   # quick sanity test
        assert( len(nonce) == 16 )      # nonce needs to be block-sized
        nonces.append(nonce)            

# test verifying that a message encrypted with a passphrase can be 
# successfully decrypted without distortion to the original message
def test_passphrase():
    password    = 'Hello World! This is a secure passphrase.'
    message     = 'This is a sample message. 1234567890ABCDEF'

    print '\t[+] test password: \'%s\'' % password
    print '\t[+] test message:  \'%s\'' % message
    print '\t[+] passphrase: \n\t\t\'%s\'...\n\t\t\'%s\'' % (
        block.passphrase(password, True)[:32],
        block.passphrase(password, True)[32:])

    assert( len(block.passphrase(password)) == 32 )

    iv          = block.generate_nonce()
    ct          = block.passphrase_encrypt( password, iv, message )
    pt          = block.passphrase_decrypt( password, iv, ct )

    assert( message == pt )

# test verifying that encryption and decryption of a message with a randomly
# generated key works without the message losing data
def test_random_key():
    key         = block.generate_aes_key()
    message     = 'This is a sample message. 1234567890ABCDEF'

    print '\t[+] test message:  \'%s\'' % message
    assert( len(key) == 32 )
    
    iv          = block.generate_nonce()
    ct          = block.encrypt( key, iv, message )
    pt          = block.decrypt( key, iv, ct )

    assert( pt == message )


# the program should be run with no arguments from the command line
# it will run through all the tests.
if __name__ == '__main__':
    print '[+] beginning test suite...'

    print '[+] begin padding test'
    test_padding()
    print '[+] successfully passed padding test!'

    print '[+] begin nonce test'
    test_nonce()
    print '[+] successfully passed nonce test!'

    print '[+] begin passphrase encryption test'
    test_passphrase()
    print '[+] successfully passed passphrase encryption test!'

    print '[+] begin standard encryption test'
    test_random_key()
    print '[+] successfully passed standard encryption test!'

    print '[+] successfully passed all tests!'
