# Copyright 2016-2017 David Stainton
#
# This file is part of Sphinx.
#
# Sphinx is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# Sphinx is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with Sphinx.  If not, see
# <http://www.gnu.org/licenses/>.
#

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
    return bytes(src) + bytes(padding) + bytes(offset_bytes)


def remove_padding(src):
    """
    remove_padding removes the message padding
    """
    src_len = len(src)
    offset = struct.unpack("H", src[src_len - 2:])[0]
    assert offset < src_len
    return src[:(src_len - offset)]
