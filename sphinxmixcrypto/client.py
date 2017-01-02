# Copyright 2011 Ian Goldberg
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

import os
import binascii

from sphinxmixcrypto.node import destination_encode, DSPEC, SECURITY_PARAMETER
from sphinxmixcrypto.crypto_primitives import PAYLOAD_SIZE
from sphinxmixcrypto.padding import add_padding, remove_padding
from sphinxmixcrypto.common import RandReader


def rand_subset(lst, nu):
    """
    Return a list of nu random elements of the given list (without
    replacement).
    """
    # Randomize the order of the list by sorting on a random key
    nodeids = [(os.urandom(8), x) for x in lst]
    nodeids.sort(key=lambda x: x[0])
    # Return the first nu elements of the randomized list
    return [x[1] for x in nodeids[:nu]]


def create_header(params, route, node_map, dest, message_id, rand_reader):
    route_len = len(route)
    assert len(dest) <= 2 * (params.r - route_len + 1) * SECURITY_PARAMETER
    assert route_len <= params.r
    assert len(message_id) == SECURITY_PARAMETER
    p = params
    group = p.group
    x = group.gensecret(rand_reader)
    padding = rand_reader.read(((2 * (params.r - route_len) + 2) * SECURITY_PARAMETER - len(dest)))

    # Compute the (alpha, s, b) tuples
    blinds = [x]
    asbtuples = []
    for node in route:
        alpha = group.multiexpon(group.generator, blinds)
        s = group.multiexpon(node_map[node], blinds)
        b = p.hb(alpha, s)
        blinds.append(b)
        asbtuples.append({'alpha': alpha, 's': s, 'b': b})

    # Compute the filler strings
    phi = b''
    for i in range(1, route_len):
        min = (2 * (p.r - i) + 3) * SECURITY_PARAMETER
        phi = p.xor(phi + (b"\x00" * (2 * SECURITY_PARAMETER)),
                    p.rho(p.create_stream_cipher_key(asbtuples[i - 1]['s']))[min:])

    # Compute the (beta, gamma) tuples
    beta = dest + message_id + padding
    beta = p.xor(beta,
                 p.rho(p.create_stream_cipher_key(asbtuples[route_len - 1]['s']))[:(2 * (p.r - route_len) + 3) * SECURITY_PARAMETER]) + phi
    gamma_key = p.hmu(asbtuples[route_len - 1]['s'])
    gamma = p.mu(gamma_key, beta)
    for i in range(route_len - 2, -1, -1):
        message_id = route[i + 1]
        assert len(message_id) == SECURITY_PARAMETER
        beta = p.xor(message_id + gamma + beta[:(2 * p.r - 1) * SECURITY_PARAMETER],
                     p.rho(p.create_stream_cipher_key(asbtuples[i]['s']))[:(2 * p.r + 1) * SECURITY_PARAMETER])
        gamma = p.mu(p.hmu(asbtuples[i]['s']), beta)
    return (asbtuples[0]['alpha'], beta, gamma), [y['s'] for y in asbtuples]


def create_forward_message(params, route, node_map, dest, msg, rand_reader):
    p = params
    route_len = len(route)
    assert len(dest) < 128 and len(dest) > 0
    assert SECURITY_PARAMETER + 1 + len(dest) + len(msg) < PAYLOAD_SIZE
    # Compute the header and the secrets
    header, secrets = create_header(params, route, node_map, DSPEC, b"\x00" * SECURITY_PARAMETER, rand_reader)
    encoded_dest = destination_encode(dest)
    body = (b"\x00" * SECURITY_PARAMETER) + bytes(encoded_dest) + bytes(msg)
    padded_body = add_padding(body, PAYLOAD_SIZE)

    # Compute the delta values
    key = p.create_block_cipher_key(secrets[route_len - 1])
    delta = p.pi(key, padded_body)
    for i in range(route_len - 2, -1, -1):
        delta = p.pi(p.create_block_cipher_key(secrets[i]), delta)
    alpha, beta, gamma = header
    return alpha, beta, gamma, delta


def create_surb(params, route, node_map, dest, rand_reader):
    p = params
    message_id = rand_reader.read(SECURITY_PARAMETER)

    # Compute the header and the secrets
    header, secrets = create_header(params, route, node_map, destination_encode(dest), message_id, rand_reader)

    # ktilde is 32 bytes because our create_block_cipher_key
    # requires a 32 byte input. However in the Sphinx reference
    # implementation the block cipher key creator function called "hpi"
    # allows any size input. ktilde was previously 16 bytes.
    ktilde = rand_reader.read(32)
    keytuple = [ktilde]
    keytuple.extend([p.create_block_cipher_key(x) for x in secrets])
    return message_id, keytuple, (route[0], header, ktilde)


class NymKeyNotFoundError(Exception):
    pass


class CorruptMessageError(Exception):
    pass


class ClientMessage:
    def __init__(self):
        self.payload = None


class SphinxClient:
    def __init__(self, params, id=None, rand_reader=None):
        self.params = params
        if rand_reader is None:
            self.rand_reader = RandReader()
        else:
            self.rand_reader = rand_reader
        if id is None:
            self.id = b"Client %s" % binascii.hexlify(self.rand_reader.read(4))
        else:
            self.id = id
        params.clients[self.id] = self
        self.keytable = {}

    def create_nym(self, route, node_map):
        """Create a SURB for the given nym (passing through nllength
        nodes), and send it to the nymserver."""

        message_id, keytuple, nymtuple = create_surb(self.params, route, node_map, self.id, self.rand_reader)
        self.keytable[message_id] = keytuple
        return nymtuple

    def decrypt(self, message_id, delta):
        """
        decrypt reply message
        """
        message = ClientMessage()
        p = self.params
        keytuple = self.keytable.pop(message_id, None)

        if keytuple is None:
            raise NymKeyNotFoundError
        ktilde = keytuple.pop(0)
        route_len = len(keytuple)
        for i in range(route_len - 1, -1, -1):
            delta = p.pi(keytuple[i], delta)
        delta = p.pii(p.create_block_cipher_key(ktilde), delta)

        if delta[:SECURITY_PARAMETER] == (b"\x00" * SECURITY_PARAMETER):
            msg = remove_padding(delta[SECURITY_PARAMETER:])
            message.tuple_message = (self.id, msg)
            return message

        raise CorruptMessageError
