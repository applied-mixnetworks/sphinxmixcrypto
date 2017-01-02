

from sphinxmixcrypto import prefix_free_decode, SECURITY_PARAMETER


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
