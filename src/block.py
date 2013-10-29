"""
Block cipher encryption example code using Python.
"""

import streql
import struct
import Crypto.Cipher.AES as AES
import Crypto.Random.OSRNG.posix as RNG
import Crypto.Hash.HMAC as HMAC
import Crypto.Hash.SHA384 as SHA384


__AES_KEYLEN = 32
__TAG_KEYLEN = 48
__TAG_LEN = 48
KEYSIZE = __AES_KEYLEN + __TAG_KEYLEN


def pad_data(data):
    """Pad data for use with CBC mode."""
    padding_required = AES.block_size
    padding_required -= len(data) % AES.block_size
    if padding_required == 0:
        padding_required = AES.block_size
    padding = struct.pack('B', (0x80))
    padding += struct.pack('B' * (padding_required - 1),
                           *([0] * (padding_required - 1)))
    return data + padding


def unpad_data(data):
    """Strip padding from input."""
    if not data:
        return data
    data = data.strip('\x00')
    if data[-1] == '\x80':
        return data[:-1]
    raise Exception("Invalid padding.")


def generate_nonce():
    """Return a nonce suitable for use as an IV."""
    return RNG.new().read(AES.block_size)


def generate_key():
    """Generate a new random AES key."""
    return RNG.new().read(KEYSIZE)


def encrypt(data, key, armour=False):
    """
    Encrypt data using AES in CBC mode. The IV is prepended to the
    ciphertext.
    """
    data = pad_data(data)
    ivec = generate_nonce()
    aes = AES.new(key[:__AES_KEYLEN], AES.MODE_CBC, ivec)
    ctxt = aes.encrypt(data)
    tag = new_tag(ivec+ctxt, key[__AES_KEYLEN:])
    if armour:
        return '\x41' + (ivec + ctxt + tag).encode('base64')
    else:
        return '\x00' + ivec + ctxt + tag


def decrypt(ciphertext, key):
    """
    Decrypt a ciphertext encrypted with AES in CBC mode; assumes the IV
    has been prepended to the ciphertext.
    """
    if ciphertext[0] == '\x41':
        ciphertext = ciphertext[1:].decode('base64')
    else:
        ciphertext = ciphertext[1:]
    if len(ciphertext) <= AES.block_size:
        return None, False
    tag_start = len(ciphertext) - __TAG_LEN
    ivec = ciphertext[:AES.block_size]
    data = ciphertext[AES.block_size:tag_start]
    if not verify_tag(ciphertext, key[__AES_KEYLEN:]):
        return None, False
    aes = AES.new(key[:__AES_KEYLEN], AES.MODE_CBC, ivec)
    data = aes.decrypt(data)
    return unpad_data(data), True


def new_tag(ciphertext, key):
    """Compute a new message tag using HMAC-SHA-384."""
    return HMAC.new(key, msg=ciphertext, digestmod=SHA384).digest()


def verify_tag(ciphertext, key):
    """Verify the tag on a ciphertext."""
    tag_start = len(ciphertext) - __TAG_LEN
    data = ciphertext[:tag_start]
    tag = ciphertext[tag_start:]
    actual_tag = new_tag(data, key)
    return streql.equals(actual_tag, tag)
