#!/usr/bin/env python

# Copyright 2011 Ian Goldberg
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

"""
This SphinxNode module includes cryptographic algorithms for mix net nodes
"""

import os
import re
import binascii

# The special destination
DSPEC = b"\x00"


def pad_body(msgtotalsize, body):
    """
    pad_body appends padding to the body of a message.
    Given the total size and the message data a new
    padded message is returned.
    """
    body = bytes(body) + b"\x7f"
    body = body + (b"\xff" * (msgtotalsize - len(body)))
    return body


def unpad_body(body):
    """
    unpad_body performs the inverse of pad_body
    """
    return re.compile(b"\x7f\xff*$").sub(b"", body)


def destination_encode(dest):
    """
    encode destination
    """
    assert len(dest) >= 1 and len(dest) <= 127
    return b"%c" % len(dest) + dest


class MessageResult:
    def __init__(self):
        self.error_invalid_message_type = False
        self.error_invalid_dspec = False
        self.error_no_such_client = False
        self.error_not_in_alpha_group = False
        self.error_tag_seen_already = False
        self.error_mac_mismatch = False
        self.tuple_next_hop = ()
        self.tuple_exit_hop = ()
        self.tuple_client_hop = ()

    def print_error(self):
        for err in [x for x in dir(self) if x.startswith('error')]:
            if getattr(self, err):
                print(("err %s is %s" % (err, getattr(self, err))))

    def has_error(self):
        for err in [x for x in dir(self) if x.startswith('error')]:
            if getattr(self, err):
                print(("err %s is %s" % (err, getattr(self, err))))  # XXX
                return True
        return False


class SphinxNode:
    def __init__(self, params):
        self.received = []
        self.p = params
        group = self.p.group
        self.__x = group.gensecret()
        self.y = group.expon(group.generator, self.__x)
        idnum = os.urandom(4)
        self.id = self.__Nenc(idnum)
        self.name = "Node " + str(binascii.b2a_hex(idnum))
        self.seen = {}

    def get_id(self):
        return self.id

    def __Nenc(self, idnum):
        id = b"\xff" + idnum + (b"\x00" * (self.p.k - len(idnum) - 1))
        assert len(id) == self.p.k
        return id

    # Decode the prefix-free encoding.  Return the type, value, and the
    # remainder of the input string
    def _prefix_free_decode(self, s):
        if len(s) == 0:
            return None, None, None
        if isinstance(s[0], int):
            l = s[0]
        else:
            l = ord(s[0])
        if l == 0:
            return 'Dspec', None, s[1:]
        if l == 255:
            return 'node', s[:self.p.k], s[self.p.k:]
        if l < 128:
            return 'dest', s[1:l+1], s[l+1:]
        return None, None, None

    def process(self, header, payload):
        """
        process returns a MessageResult given a header and payload
        """
        result = MessageResult()
        p = self.p
        group = p.group
        alpha, beta, gamma = header

        if not group.in_group(alpha):
            result.error_not_in_alpha_group = True
            return result
        s = group.expon(alpha, self.__x)
        tag = p.htau(s)

        if tag in self.seen:
            result.error_tag_seen_already = True
            return result
        if gamma != p.mu(p.hmu(s), beta):
            result.error_mac_mismatch = True
            return result

        self.seen[tag] = 1
        B = p.xor(beta + (b"\x00" * (2 * p.k)), p.rho(p.hrho(s)))
        message_type, val, rest = self._prefix_free_decode(B)
        if message_type == "node":
            b = p.hb(alpha, s)
            alpha = group.expon(alpha, b)
            gamma = B[p.k:p.k*2]
            beta = B[p.k*2:]
            payload = p.pii(p.hpi(s), payload)
            result.tuple_next_hop = (val, (alpha, beta, gamma), payload)
            return result
        elif message_type == "Dspec":
            payload = p.pii(p.hpi(s), payload)
            if payload[:p.k] == (b"\x00" * p.k):
                inner_type, val, rest = self._prefix_free_decode(payload[p.k:])
                if inner_type == "dest":
                    # We're to deliver rest (unpadded) to val
                    body = unpad_body(rest)
                    self.received.append(body)
                    result.tuple_exit_hop = (val, body)
                    return result
            result.error_invalid_dspec = True
            return result
        elif message_type == "dest":
            id = rest[:p.k]
            payload = p.pii(p.hpi(s), payload)
            if val in p.clients:
                result.tuple_client_hop = (val, id, payload)
                return result
            else:
                result.error_no_such_client = True
                return result

        result.error_invalid_message_type = True
        return result
