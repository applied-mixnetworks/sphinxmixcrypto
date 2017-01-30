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

import binascii
import attr

from sphinxmixcrypto.node import destination_encode, DSPEC, SphinxParams
from sphinxmixcrypto.crypto_primitives import SECURITY_PARAMETER, xor
from sphinxmixcrypto.crypto_primitives import SphinxLioness, SphinxStreamCipher, SphinxDigest, GroupCurve25519
from sphinxmixcrypto.padding import add_padding, remove_padding
from sphinxmixcrypto.common import RandReader, IMixPKI
from sphinxmixcrypto.errors import NymKeyNotFoundError, CorruptMessageError


def create_header(params, route, pki, dest, message_id, rand_reader):
    assert IMixPKI.providedBy(pki)
    route_len = len(route)
    assert len(dest) <= 2 * (params.max_hops - route_len + 1) * SECURITY_PARAMETER
    assert route_len <= params.max_hops
    assert len(message_id) == SECURITY_PARAMETER

    group = GroupCurve25519()
    digest = SphinxDigest()
    stream_cipher = SphinxStreamCipher()
    x = group.gensecret(rand_reader)
    padding = rand_reader.read(((2 * (params.max_hops - route_len) + 2) * SECURITY_PARAMETER - len(dest)))

    # Compute the (alpha, s, b) tuples
    blinds = [x]
    asbtuples = []
    for node_id in route:
        alpha = group.multiexpon(group.generator, blinds)
        s = group.multiexpon(pki.get(node_id), blinds)
        b = digest.hash_blinding(alpha, s)
        blinds.append(b)
        asbtuples.append({'alpha': alpha, 's': s, 'b': b})

    # Compute the filler strings
    phi = b''
    stream_cipher = SphinxStreamCipher()
    for i in range(1, route_len):
        min = (2 * (params.max_hops - i) + 3) * SECURITY_PARAMETER
        phi = xor(phi + (b"\x00" * (2 * SECURITY_PARAMETER)),
                  stream_cipher.generate_stream(digest.create_stream_cipher_key(asbtuples[i - 1]['s']), params.beta_cipher_size)[min:])

    # Compute the (beta, gamma) tuples
    beta = dest + message_id + padding
    stream_key = digest.create_stream_cipher_key(asbtuples[route_len - 1]['s'])
    beta = xor(beta,
               stream_cipher.generate_stream(stream_key, (2 * (params.max_hops - route_len) + 3) * SECURITY_PARAMETER)[:(2 * (params.max_hops - route_len) + 3) * SECURITY_PARAMETER]) + phi
    gamma_key = digest.create_hmac_key(asbtuples[route_len - 1]['s'])
    gamma = digest.hmac(gamma_key, beta)
    for i in range(route_len - 2, -1, -1):
        message_id = route[i + 1]
        assert len(message_id) == SECURITY_PARAMETER
        stream_key = digest.create_stream_cipher_key(asbtuples[i]['s'])
        beta = xor(message_id + gamma + beta[:(2 * params.max_hops - 1) * SECURITY_PARAMETER],
                   stream_cipher.generate_stream(stream_key, params.beta_cipher_size)[:(2 * params.max_hops + 1) * SECURITY_PARAMETER])
        gamma = digest.hmac(digest.create_hmac_key(asbtuples[i]['s']), beta)
    return (asbtuples[0]['alpha'], beta, gamma), [y['s'] for y in asbtuples]


def create_forward_message(params, route, pki, dest, msg, rand_reader):
    assert IMixPKI.providedBy(pki)

    route_len = len(route)
    assert len(dest) < 128 and len(dest) > 0
    assert SECURITY_PARAMETER + 1 + len(dest) + len(msg) < params.payload_size
    block_cipher = SphinxLioness()

    # Compute the header and the secrets
    header, secrets = create_header(params, route, pki, DSPEC, b"\x00" * SECURITY_PARAMETER, rand_reader)
    encoded_dest = destination_encode(dest)
    body = (b"\x00" * SECURITY_PARAMETER) + bytes(encoded_dest) + bytes(msg)
    padded_body = add_padding(body, params.payload_size)

    # Compute the delta values
    block_cipher = SphinxLioness()
    key = block_cipher.create_block_cipher_key(secrets[route_len - 1])
    delta = block_cipher.encrypt(key, padded_body)
    for i in range(route_len - 2, -1, -1):
        delta = block_cipher.encrypt(block_cipher.create_block_cipher_key(secrets[i]), delta)
    alpha, beta, gamma = header
    return alpha, beta, gamma, delta


def create_surb(params, route, pki, dest, rand_reader):
    """
    returns -> 16 byte message ID, key tuple, nym tuple w/ header
    """
    assert IMixPKI.providedBy(pki)

    message_id = rand_reader.read(SECURITY_PARAMETER)
    block_cipher = SphinxLioness()
    # Compute the header and the secrets
    header, secrets = create_header(params, route, pki, destination_encode(dest), message_id, rand_reader)

    # ktilde is 32 bytes because our create_block_cipher_key
    # requires a 32 byte input. However in the Sphinx reference
    # implementation the block cipher key creator function called "hpi"
    # allows any size input. ktilde was previously 16 bytes.
    ktilde = rand_reader.read(32)
    keytuple = [ktilde]
    keytuple.extend([block_cipher.create_block_cipher_key(x) for x in secrets])
    return message_id, keytuple, (route[0], header, ktilde)


@attr.s(frozen=True)
class ClientMessage(object):
    identity = attr.ib(validator=attr.validators.instance_of(bytes))
    payload = attr.ib(validator=attr.validators.instance_of(bytes))


class SphinxClient:
    def __init__(self, params, id, rand_reader=None):
        """
        params is an instance of SphinxParams, encapsulating max hops
        and payload size and a couple of helper methods that provide
        Sphinx packet element dimensions
        """
        assert isinstance(params, SphinxParams)

        self.params = params
        if rand_reader is None:
            self.rand_reader = RandReader()
        else:
            self.rand_reader = rand_reader
        if id is None:
            self.id = b"Client %s" % binascii.hexlify(self.rand_reader.read(4))
        else:
            self.id = id
        self.keytable = {}

    def create_nym(self, route, pki):
        """
        Create a SURB for the given nym (passing through nllength
        nodes), and send it to the nymserver.
        """
        assert IMixPKI.providedBy(pki)

        message_id, keytuple, nymtuple = create_surb(self.params, route, pki, self.id, self.rand_reader)
        self.keytable[message_id] = keytuple
        return nymtuple

    def decrypt(self, message_id, delta):
        """
        decrypt reply message
        returns a ClientMessage
        """
        keytuple = self.keytable.pop(message_id, None)
        block_cipher = SphinxLioness()
        if keytuple is None:
            raise NymKeyNotFoundError
        ktilde = keytuple.pop(0)
        route_len = len(keytuple)
        for i in range(route_len - 1, -1, -1):
            delta = block_cipher.encrypt(keytuple[i], delta)
        delta = block_cipher.decrypt(
            block_cipher.create_block_cipher_key(ktilde), delta
        )

        if delta[:SECURITY_PARAMETER] == (b"\x00" * SECURITY_PARAMETER):
            msg = remove_padding(delta[SECURITY_PARAMETER:])
            return ClientMessage(identity=self.id, payload=msg)

        raise CorruptMessageError
