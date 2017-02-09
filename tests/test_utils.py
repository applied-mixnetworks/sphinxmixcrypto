

from sphinxmixcrypto import prefix_free_decode, SECURITY_PARAMETER
from sphinxmixcrypto import SphinxParams, SphinxPacket


def test_sphinx_packet_encode_decode():
    params = SphinxParams(5, 1024)
    alpha = b"A" * 32
    beta = b"B" * 176
    gamma = b"G" * 16
    delta = b"D" * 1024
    packet = SphinxPacket.from_raw_bytes(params, alpha + beta + gamma + delta)
    assert len(packet.get_raw_bytes()) == 1248
    assert len(packet.header.alpha) == 32
    assert len(packet.header.beta) == 176
    assert len(packet.header.gamma) == 16
    assert len(packet.body.delta) == 1024

    params = SphinxParams(10, 1024)
    alpha = b"A" * 32
    beta = b"B" * 336
    gamma = b"G" * 16
    delta = b"D" * 1024
    packet = SphinxPacket.from_raw_bytes(params, alpha + beta + gamma + delta)
    assert len(packet.get_raw_bytes()) == 1408
    assert len(packet.header.alpha) == 32
    assert len(packet.header.beta) == 336
    assert len(packet.header.gamma) == 16
    assert len(packet.body.delta) == 1024

    params = SphinxParams(10, 2048)
    alpha = b"A" * 32
    beta = b"B" * 336
    gamma = b"G" * 16
    delta = b"D" * 2048
    packet = SphinxPacket.from_raw_bytes(params, alpha + beta + gamma + delta)
    assert len(packet.get_raw_bytes()) == 2432
    assert len(packet.header.alpha) == 32
    assert len(packet.header.beta) == 336
    assert len(packet.header.gamma) == 16
    assert len(packet.body.delta) == 2048


def test_prefix_free_decode():
    s = b""
    message_type, val, rest = prefix_free_decode(s)
    assert message_type is None
    assert val is None
    assert rest is None

    s = b"\x00" * 200
    message_type, val, rest = prefix_free_decode(s)
    assert message_type == "process"
    assert val is None
    assert rest == s[1:]

    s = b"\xFF" * 200
    message_type, val, rest = prefix_free_decode(s)
    assert message_type == "mix"
    assert val == s[:SECURITY_PARAMETER]
    assert rest == s[SECURITY_PARAMETER:]

    s = b"\x03" + b"\xFF" * 200
    message_type, val, rest = prefix_free_decode(s)
    assert message_type == "client"
    assert val == s[1:ord(s[0:1]) + 1]
    assert rest == s[ord(s[0:1]) + 1:]

    s = b"\xFE" + b"\xFF" * 200
    message_type, val, rest = prefix_free_decode(s)
    assert message_type is None
    assert val is None
    assert rest is None
