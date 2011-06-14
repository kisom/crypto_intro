Recently at work I have been doing a lot of work with the 
[PyCrypto](https://www.dlitz.net/software/pycrypto/) libraries.
The documentation is pretty good, but there are a few areas that took me a bit
to figure out. In this post, I'll be writing up a quick overview of the 
PyCrypto library and cover some general things to know when writing 
cryptographic code in general. I'll go over symmetric, public-key, hybrid,
and message authentication codes. For a more complete introduction to
cryptography, take a look at the references at the end of this article. This
article is just an appetite-whetter - if you have a real need for information
security you should hire an expert. Real data security goes beyond this quick
introduction (you wouldn't trust the design and engineering of a bridge to
a student with a quick introduction to civil engineering, would you?)

Some quick terminology: for those unfamiliar, I introduce the following terms:    
* *plaintext*: the original message     
* *ciphertext*: the message after cryptographic transformations are applied 
to obscure the original message.
* *encrypt*: producting ciphertext by applying cryptographic transformations
to plaintext.
* *decrypt*: producing plaintext by applying cryptographic transformations to
ciphertext.
* *cipher*: a particular set of cryptographic transformations providing means
of both encryption and decryption.    
* *hash*: a set of cryptographic transformations that take a large input and
transform it to a unique (typically fixed-size) output. For hashes to be
cryptographically secure, collisions should be practically nonexistent. It
should be practically impossible to determine the input from the output.

Cryptography is an often misunderstood component of information security, so
an overview of what it is and what role it plays is in order. There are four
major roles that cryptography plays:     
0. *confidentiality*: ensuring that only the intended recipients receive the
plaintext of the message.    
0. *data integrity*: the plaintext message arrives unaltered.     
0. *entity authentication*: the identity of the sender is verified. An entity
may be a person or a machine.   
0. *message authentication*: the message is verified as having been 
unaltered.     
Note that cryptography is used to obscure the contents of a message and verify
its contents and source. It will **not** hide the fact that two entities are 
communicating.

There are two basic types of ciphers: symmetric and public-key ciphers. A 
symmetric key cipher employs the use of shared secret keys. They also tend to
be much faster than public-key ciphers. A public-key cipher is so-called because
each key consists of a private key which is used to generate a public key. Like
their names imply, the private key is kept secret while the public key is 
passed around. 

There are two further types of symmetric keys: stream and block ciphers. Stream
ciphers operate on data streams, i.e. one byte at a time. Block ciphers operate
on blocks of data, typically 16 bytes at a time. The most common block cipher
and the standard one you should use unless you have a very good reason to use
another one is the 
[AES](https://secure.wikimedia.org/wikipedia/en/wiki/Advanced_Encryption_Standard)
block cipher, also documented in 
[FIPS PUB 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf). 
AES is a specific subset of the Rijndael cipher. AES uses block size of 
128-bits (16 bytes); data should be padded out to fit the block size - the
length of the data block must be multiple of the block size. For example, 
given an input of `ABCDABCDABCDABCD ABCDABCDABCDABCD` no padding would
need to be done. However, given `ABCDABCDABCDABCD ABCDABCDABCD` an additional
4 bytes of padding would need to be added. A common padding scheme is to use
0x80 as the first byte of padding, with 0x00 bytes filling out the rest of 
the padding. With padding, the previous example would look like: 
`ABCDABCDABCDABCD ABCDABCDABCD\x80\x00\x00\x00`.

Writing a padding function is pretty easy:   

    def pad_data(data):
    	# return data if no padding is required
    	if len(data) % 16 == 0: 
            return data
	
        # subtract one byte that should be the 0x80
    	# if 0 bytes of padding are required, it means only
    	# a single \x80 is required.

	padding_required     = 15 - (len(data) % 16)

    	data = '%s\x80' % data
    	data = '%s%s' % (data, '\x00' * padding_required)

    	return data

Similarly, removing padding is also easy:

    def unpad_data(data):
        if not data: 
            return data

        data = data.rstrip('\x00')
        if data[-1] == '\x80':
            return data[:-1]
        else:
            return data

I've included these functions in the example code for this tutorial. 

Encryption with a block cipher requires selecting a 
[block mode](https://secure.wikimedia.org/wikipedia/en/wiki/Block_cipher_modes_of_operation). 
By far the most
common mode used is **cipher block chaining** or *CBC* mode. Other modes
include *counter (CTR)*, *cipher feedback (CFB)*, and the extremely insecure
*electronic codebook (ECB)*. CBC mode is the standard and is well-vetted, so
I will stick to that in this tutorial. Cipher block chaining works by XORing
the previous block of ciphertext with the current block. You might recognise
that the first block has nothing to be XOR'd with; enter the 
[*initialisation vector*](https://secure.wikimedia.org/wikipedia/en/wiki/Initialization_vector). 
This comprises a number of randomly-generated bytes of data the same
size as the cipher's block size. This initialisation vector should random 
enough that it cannot be recovered; one manner of doing this is to combine a
standard UNIX timestamp with a block-size group of random data, using a standard
hashing algorithm such as MD5 to make it unique. 

One of the most critical components to encryption is properly generating 
random data. Fortunately, most of this is handled by the PyCrypto library's
Crypto.Random.OSRNG module. You should know that the more entropy sources
available (such as network traffic and disk activity), the faster the system
can generate cryptographically-secure random data. I've written a function that 
can generate a 
[nonce](https://secure.wikimedia.org/wikipedia/en/wiki/Cryptographic_nonce) 
suitable for use as an initialisation vector. This will
work on a UNIX machine; the comments note how easy it is to adapt it to a
Windows machine. This function requires a version of PyCrypto at least 2.1.0
or higher.

    import time
    import Crypto.Random.OSRNG.posix

    def generate_nonce():
    	rnd = Crypto.Random.OSRNG.posix.new().read(BLOCK_SIZE)
    	rnd = '%s%s' % (rnd, str(time.time()))
	nonce = Crypto.Hash.MD5.new(data = rnd)
    
        return nonce.digest()

I will note here that the python `random` module is completely unsuitable for
cryptography (as it is completely deterministic). You shouldn't use it for
cryptographic code.

Symmetric ciphers are so-named because the key is shared across any entities.
There are three key sizes for AES: 128-bit, 192-bit, and 256-bit, aka 16-byte,
24-byte, and 32-byte key sizes. If you want to use a passphrase, you 
should use a digest algorithm that produces an appropriately sized digest, and
hash that passphrase. For example, for AES-256, you would want to use SHA-256.
Here is a sample function to generate an AES-256 key from a passphrase:

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


We could include this a set of AES encryption and decryption functions:

    mode = Crypto.Cipher.AES.MODE_CBC       # shortcut to clean up code

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

Notice how the data is padded before being encrypted and unpadded after 
decryption - the decryption process will not remove the padding on its own.

Unless you are you doing interactive encryption passphrase encryption won't be
terribly useful. Instead, we just need to generate 32 random bytes (and make
sure we keep track of it) and use that as the key:

    # generate a random AES-256 key
    def generate_aes_key():
        rnd     = Crypto.Random.OSRNG.posix.new().read(KEY_SIZE)
        return rnd

We can use this key directly in the AES transformations:

    def encrypt(key, iv, data):
        aes     = Crypto.Cipher.AES.new(key, mode, iv)
        data    = pad_data(data)

        return aes.encrypt(data)

    def decrypt(key, iv, data):
        aes     = Crypto.Cipher.AES.new(key, mode, iv)
        data    = aes.decrypt(data)

        return unpad_data(data)

That should cover the basics of block cipher encryption. We've gone over key
generation, padding, and encryption / decryption. AES-256 isn't the only 
block cipher provided by the PyCrypto package, but again - it is the standard
and well vetted. 

Now it is time to take a look at public-key cryptography. Public-key 
cryptography, or PKC, involves the use of two-part keys. The private key is
the sensitive key that should be kept private by the owning entity, whereas the
public key (which is generated from the private key) is meant to be distributed
to any entities which must communicate securely with the entity owning the 
private key. Confusing? Let's look at this using the venerable Alice and Bob,
patron saints of cryptography.

Alice wants to talk to Bob, but doesn't want Eve to know the contents of the
message. Both Alice and Bob generate a set of private keys. From those private
keys, they both generate public keys. Let's say they post their public keys on
their websites. Alice wants to send a private message to Bob, so she looks up
Bob's public key from his site. The public key can be used as the key to 
encrypt a message with PKC. The resulting ciphertext can only be decrypted 
using Bob's private key. Alice sends Bob the resulting ciphertext, which Eve
cannot decrypt without Bob's private key. Hopefully this is a little less 
confusing. 

One of the most common PKC systems is RSA (which is an acronym for the last 
names of the designers of the algorithm). Generally, RSA keys are 1024-bit,
2048-bit, or 4096-bits long. The keys are most often in 
[PEM](https://secure.wikimedia.org/wikipedia/en/wiki/Privacy-enhanced_Electronic_Mail) or 
[DER](https://secure.wikimedia.org/wikipedia/en/wiki/Distinguished_Encoding_Rules) 
format. Generating RSA keys with PyCrypto is extremely easy:

    def generate_key(size):
        PRNG    = Crypto.Random.OSRNG.posix.new().read
        key     = Crypto.PublicKey.RSA.generate(size, PRNG)

        return key

The `key` that is returned isn't like the keys we used with the block ciphers:
it is an RSA object and comes with several useful built-in methods. One of 
these is the size() method, which returns the size of the key in bits minus
one. For example:

    >>> import publickey
    >>> key = publickey.generate_key( 1024 )
    >>> key.size()
    1023
    >>>


