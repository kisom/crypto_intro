#!/usr/bin/env python
"""Tests for block.py."""

import block


def padding_ok(inlen, padlen):
    """Return true if the input length is the expected padding length."""
    if (padlen % block.AES.block_size) != 0:
        return False

    if (inlen % block.AES.block_size) == 0:
        return padlen == (inlen + block.AES.block_size)

    return True


def test_padding():
    """Ensure padding function works."""
    for i in range(4096):
        inp = 'A' * i
        padded = block.pad_data(inp)
        assert(padding_ok(len(inp), len(padded)))
        out = block.unpad_data(padded)
        assert(out == inp)
    print('\t[+] padding okay')


def test_crypt():
    "Test encryption and decryption."
    key1 = block.generate_key()
    key2 = block.generate_key()
    messages = ['Hello, world.', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ']
    for msg in messages:
        ct1 = block.encrypt(msg, key1)
        ct2 = block.encrypt(msg, key2)
        ptxt, success = block.decrypt(ct1, key1)
        assert(success)
        assert(ptxt == msg)

        ptxt, success = block.decrypt(ct1, key2)
        assert(not success)
        assert(ptxt == None)

        ptxt, success = block.decrypt(ct2, key2)
        assert(success)
        assert(ptxt == msg)

        ptxt, success = block.decrypt(ct2, key1)
        assert(not success)
        assert(ptxt == None)
    for msg in messages:
        ct1 = block.encrypt(msg, key1, True)
        ct2 = block.encrypt(msg, key2, True)
        ptxt, success = block.decrypt(ct1, key1)
        assert(success)
        assert(ptxt == msg)

        ptxt, success = block.decrypt(ct1, key2)
        assert(not success)
        assert(ptxt == None)

        ptxt, success = block.decrypt(ct2, key2)
        assert(success)
        assert(ptxt == msg)

        ptxt, success = block.decrypt(ct2, key1)
        assert(not success)
        assert(ptxt == None)
    print('\t[+] encrypt/decrypt ok')


def main():
    """Run the test suite."""
    print('[+] beginning test suite...')

    test_padding()
    test_crypt()

    print('[+] passed all tests.')


if __name__ == '__main__':
    main()
