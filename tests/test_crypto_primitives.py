
import binascii

from sphinxmixcrypto.crypto_primitives import GroupCurve25519, SphinxDigest, SphinxLioness
from pylioness.lioness import Chacha20_Blake2b_Lioness


def test_eccgroup():
    g = GroupCurve25519()
    secret = binascii.unhexlify("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b4")
    x = g.makesecret(secret)
    blinds = [x]
    alpha = g.multiexpon(g.generator, blinds)
    want = binascii.unhexlify("56f7f7946e62a79f2a4440cc5ca459a9d1b080c5972014c782230fa38cfe8277")
    assert alpha == want


def test_blinding_hash():
    digest = SphinxDigest()
    alpha = binascii.unhexlify("56f7f7946e62a79f2a4440cc5ca459a9d1b080c5972014c782230fa38cfe8277")
    s = binascii.unhexlify("ae573641850deb7324ad0c821af24a7e95f32d389db29ffd8dbe625d62a2794d")
    b = digest.hash_blinding(alpha, s)
    want = binascii.unhexlify("b0967a0c4da220652d48e82e2863e2a10af37a4feafa1e3f7ecc48084ebbe070")
    assert b == want


def test_create_block_cipher_key():
    alpha = binascii.unhexlify("56f7f7946e62a79f2a4440cc5ca459a9d1b080c5972014c782230fa38cfe8277")
    block_cipher = SphinxLioness()
    key = block_cipher.create_block_cipher_key(alpha)
    assert len(key) == Chacha20_Blake2b_Lioness.KEY_LEN
    want = binascii.unhexlify("8c8efb9ab5606f3ba6c4c2ec57f4c751147088dbab36fd464a561668472830480b409b9c0b3b4e64ab1f5542959fc24ca4b87c4927fd95eba14c541b18c59770fb0503288dd033f6c82542ad83618af3efa9ac6962892774b9c139832e307f5df711f505b5992fa09553259827769ba913fd36038ab15b753056124b9631e76729d36f313a321161cf2d1e3373e7985c23477613625b49fcdec292528aff7c0033d1668aec65c2c4b39573408437399921e553004240db08fa3c2b2599e280f7")
    assert key == want


def test_create_stream_cipher_key():
    digest = SphinxDigest()
    alpha = binascii.unhexlify("56f7f7946e62a79f2a4440cc5ca459a9d1b080c5972014c782230fa38cfe8277")
    key = digest.create_stream_cipher_key(alpha)
    assert len(key) == 32
    want = binascii.unhexlify("44cbf1428c9e7f6915cb923e55e0835cfcf778822abbf323dee0fa4c76dde986")
    assert key == want


def test_derive_hmac_key():
    digest = SphinxDigest()
    secret = binascii.unhexlify("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b4")
    key = digest.create_hmac_key(secret)
    assert len(key) == 16
    want_key = binascii.unhexlify("eba2ad216a65c5230ad2018b4c536c45")
    assert key == want_key
    data = binascii.unhexlify("4171bd9a48a58cf7579e9fa662fe0ac2acb8c6eed3056cd970fd35dd4d026cae")
    want_mac = binascii.unhexlify("77724528a77692be295f07bcfc8bd5eb")
    mac = digest.hmac(key, data)
    assert mac == want_mac
