Recently at work I have been doing a lot of work with the 
[PyCrypto](https://www.dlitz.net/software/pycrypto/) libraries.
The documentation is pretty good but there are a few areas that took me a bit
to figure out. In this post, I'll be writing up a quick overview of the 
PyCrypto library and cover some general things to know when writing 
cryptographic code in general. I'll go over symmetric, public-key, hybrid,
and message authentication codes. For a more complete introduction to
cryptography, take a look at the references at the end of this article. This
article is just an appetite-whetter - if you have a real need for information
security you should hire an expert. Real data security goes beyond this quick
introduction (you wouldn't trust the design and engineering of a bridge to
a student with a quick introduction to civil engineering, would you?)

Some quick terminology: for those unfamiiar, I introduce the following terms:   
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
cryptographically secure, collisions should be practically nonexistent and it
should be practically impossible to determine the input from the output.

Cryptography is an often misunderstood component of information security, so
an overview of what it is and what role it plays is in order. There are four
major roles that cryptography plays:     
0. *confidentiality*: ensuring that only the intended recipients receive the
plaintext of the message.    
0. *data integrity*: the plaintext message arrives unaltered.     
0. *entity authentication*: the identity of the sender is verified.    
0. *message authentication*: the message is verified as having been 
unaltered.     

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
the padding. Using the previous example: 
`ABCDABCDABCDABCD ABCDABCDABCD\x80\x00\x00\x00`.

A padding function is pretty easy:     
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
    	i = len(data) - 1
    	for i in range(i, 0, -1):
            if not data[i] in [ '\x80', '\x00' ]:
                return data
            if data[i] == '\x80':
                break
    	return data[:i]

I've included these functions in the example code for this tutorial. 

Encryption with a block is done with one of several modes. By far the most
common mode used is **cipher block chaining** or *CBC* mode. Other modes
include *counter (CTR)*, *cipher feedback (CFB)*, and the extremely insecure
*electronic codebook (ECB)*. CBC mode is the standard and is well-vetted, so
I will stick to that in this tutorial. Cipher block chaining works by XORing
the previous block of ciphertext with the current block.