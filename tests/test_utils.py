

from sphinxmixcrypto import SphinxNode
from sphinxmixcrypto.params import SphinxParams, GroupECC, Chacha_Lioness, Chacha20_stream_cipher, Blake2_hash
from sphinxmixcrypto.common import RandReader


def test_prefix_free_decode():
    r = 5
    params = SphinxParams(
        r, group_class=GroupECC,
        hash_func=Blake2_hash,
        lioness_class=Chacha_Lioness,
        stream_cipher=Chacha20_stream_cipher,
    )

    rand_reader = RandReader()
    node = SphinxNode(params, rand_reader=rand_reader)
    s = b""
    message_type, val, rest = node._prefix_free_decode(s)
    assert message_type is None
    assert val is None
    assert rest is None

    s = b"\x00" * 200
    message_type, val, rest = node._prefix_free_decode(s)
    assert message_type == "Dspec"
    assert val is None
    assert rest == s[1:]

    s = b"\xFF" * 200
    message_type, val, rest = node._prefix_free_decode(s)
    assert message_type == "node"
    assert val == s[:node.params.k]
    assert rest == s[node.params.k:]

    s = b"\x03" + b"\xFF" * 200
    message_type, val, rest = node._prefix_free_decode(s)
    assert message_type == "dest"
    assert val == s[1:ord(s[0:1]) + 1]
    assert rest == s[ord(s[0:1]) + 1:]

    s = b"\xFE" + b"\xFF" * 200
    message_type, val, rest = node._prefix_free_decode(s)
    assert message_type is None
    assert val is None
    assert rest is None
