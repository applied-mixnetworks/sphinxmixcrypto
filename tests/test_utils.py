
import unittest

from sphinxmixcrypto import SphinxNode
from sphinxmixcrypto.params import SphinxParams, GroupECC, Chacha_Lioness, Chacha20_stream_cipher, Blake2_hash
from sphinxmixcrypto.node import unpad_body, pad_body


class TestNodeUtils(unittest.TestCase):
    def test_pad_unpad(self):
        message = b"hello world"
        paded = pad_body(200, message)
        self.failUnlessEqual(len(paded), 200)
        orig = unpad_body(paded)
        self.failUnlessEqual(message, orig)

    def test_prefix_free_decode(self):
        self.r = 5
        self.params = SphinxParams(
            self.r, group_class = GroupECC,
            hash_func = Blake2_hash,
            lioness_class = Chacha_Lioness,
            stream_cipher = Chacha20_stream_cipher,
        )
        node = SphinxNode(self.params)
        s = b""
        message_type, val, rest = node._prefix_free_decode(s)
        self.failUnless(message_type is None)
        self.failUnless(val is None)
        self.failUnless(rest is None)

        s = b"\x00" * 200
        message_type, val, rest = node._prefix_free_decode(s)
        self.failUnless(message_type == "Dspec")
        self.failUnless(val is None)
        self.failUnless(rest == s[1:])

        s = b"\xFF" * 200
        message_type, val, rest = node._prefix_free_decode(s)
        self.failUnless(message_type == "node")
        self.failUnless(val == s[:node.p.k])
        self.failUnless(rest == s[node.p.k:])

        s = b"\x03" + b"\xFF" * 200
        message_type, val, rest = node._prefix_free_decode(s)
        self.failUnless(message_type == "dest")
        self.failUnless(val == s[1:ord(s[0:1])+1])
        self.failUnless(rest == s[ord(s[0:1])+1:])

        s = b"\xFE" + b"\xFF" * 200
        message_type, val, rest = node._prefix_free_decode(s)
        self.failUnless(message_type is None)
        self.failUnless(val is None)
        self.failUnless(rest is None)
