
import binascii

from sphinxmixcrypto.padding import add_padding, remove_padding


def test_add_padding():
    message = b"the quick brown fox"
    padded = add_padding(message, 100)
    want = binascii.unhexlify("74686520717569636b2062726f776e20666f78000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005100")
    assert padded == want
    unpadded = remove_padding(padded)
    assert unpadded == message
