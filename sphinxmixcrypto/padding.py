
import struct


def add_padding(src, block_size):
    """
    add_padding appends padding to the body of a message
    and returns the padded message
    """
    assert block_size > 0
    assert len(src) != 0
    assert len(src) < block_size - 2
    offset = block_size - len(src)
    padding = b"\x00" * (offset - 2)
    offset_bytes = struct.pack('H', offset)
    return src + padding + offset_bytes


def remove_padding(src):
    """
    remove_padding removes the message padding
    """
    src_len = len(src)
    offset = struct.unpack("H", src[src_len - 2:])[0]
    assert offset < src_len
    return src[:(src_len - offset)]
