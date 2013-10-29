ASCII-Armouring
===============

I'm going to take a quick detour and talk about ASCII armouring. If
you've played with the crypto functions above, you'll notice they
produce an annoying dump of binary data that can be a hassle to
deal with. One common technique for making the data a little bit
easier to deal with is to encode it with base64. There are a
few ways to incorporate this into python:
{Absolute Base64 Encoding}The easiest way is to just base64 encode
everything in the encrypt function. Everything that goes into the
decrypt function should be in base64 - if it's not, the `base64`
module will throw an error: you could catch this and then try to
decode it as binary data.

A Simple Header
---------------

A slightly more complex option, and the one I adopt in this
article, is to use a `\x00` as the first byte of the ciphertext for
binary data, and to use `\x41` (an ASCII "`A`") for ASCII encoded
data. This will increase the complexity of the encryption and
decryption functions slightly. We'll also pack the initialisation
vector at the beginning of the file as well. Given now that the
`iv` argument might be `None` in the decrypt function, I will have
to rearrange the arguments a bit; for consistency, I will move it
in both functions. My modified functions look like this now:

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


A More Complex Container
------------------------

There are more complex ways to do it (and you’ll see it with the public
keys in the next section) that involve putting the base64 into a
container of sorts that contains additional information about the key.



