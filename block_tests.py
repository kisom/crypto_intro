import block

def test_padding():
    # test from empty block to full block
    for i in range(17):
        data = 'A' * i
        assert(len(data) == i)
        
        padded = block.pad_data(data)
        assert( len(padded) % 16 == 0 )
        print '\t[+] passed for input size:', i, 'bytes'

        unpadded = block.unpad_data(padded)
        assert( len(unpadded) == i )
        assert( unpadded == data )

if __name__ == '__main__':
    print '[+] begin padding test'
    test_padding()
    print '[+] successfully passed padding test!'




