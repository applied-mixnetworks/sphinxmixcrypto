
import py.test
import binascii
import cbor
import os

from sphinxmixcrypto.params import SphinxParams, GroupECC, Chacha_Lioness, Chacha20_stream_cipher, Blake2_hash, Blake2_hash_mac
from sphinxmixcrypto import SphinxNode
from sphinxmixcrypto.node import ReplayError, BlockSizeMismatchError, SphinxNodeState
from sphinxmixcrypto.client import SphinxClient, rand_subset, create_forward_message


class TestSphinxCorrectness():

    def newTestRoute(self, numHops):
        self.r = numHops
        self.params = SphinxParams(
            self.r, group_class=GroupECC,
            hash_func=Blake2_hash,
            hash_mac_func=Blake2_hash_mac,
            lioness_class=Chacha_Lioness,
            stream_cipher=Chacha20_stream_cipher,
        )
        self.node_map = {}
        self.consensus = {}
        for i in range(numHops):
            node = SphinxNode(self.params)
            self.node_map[node.get_id()] = node
            self.consensus[node.get_id()] = node.public_key
        route = rand_subset(self.node_map.keys(), self.r)
        return route

    def test_sphinx_single_hop(self):
        route = self.newTestRoute(1)
        destination = b"dest"
        message = b"this is a test"
        alpha, beta, gamma, delta = create_forward_message(self.params, route, self.consensus, destination, message)
        header = alpha, beta, gamma
        payload = delta
        print("after create forward message")
        result = self.node_map[route[0]].unwrap(header, payload)
        assert len(result.tuple_exit_hop) == 2
        assert len(result.tuple_next_hop) == 0
        assert len(result.tuple_client_hop) == 0
        received_dest, received_message = result.tuple_exit_hop
        assert received_dest == destination
        assert received_message == message

    def test_sphinx_replay(self):
        route = self.newTestRoute(5)
        destination = b"dest"
        message = b"this is a test"
        alpha, beta, gamma, delta = create_forward_message(self.params, route, self.consensus, destination, message)
        header = alpha, beta, gamma
        payload = delta
        self.node_map[route[0]].unwrap(header, payload)
        py.test.raises(ReplayError, self.node_map[route[0]].unwrap, header, payload)

    def test_sphinx_assoc_data(self):
        route = self.newTestRoute(5)
        destination = b"dest"
        message = b"this is a test"
        alpha, beta, gamma, delta = create_forward_message(self.params, route, self.consensus, destination, message)
        header = alpha, beta, gamma
        payload = delta
        assert payload is not None
        py.test.raises(BlockSizeMismatchError, self.node_map[route[0]].unwrap, header, b"somethingelse!!!!!!!!!!!!!!")


class TestSphinxEnd2End():

    def setUp(self):
        hexedState = [
            {
            "id": binascii.unhexlify("ff2182654d0000000000000000000000"),
            "public_key": binascii.unhexlify("d7314c8d2ba771dbe2982fa6299844f1b92736881e78ae7644f4bccbf8817a69"),
            "private_key": binascii.unhexlify("306e5a009897d4e134727037f9b275294bd01fb33c0c7dbe5f1fdaed765d0c47"),
            },
            {
                "id": binascii.unhexlify("ff0f9a62780000000000000000000000"),
                "public_key": binascii.unhexlify("5ce56657b8af66bd47df2469b10065206a2fd777a0cd17b104160256810bc976"),
                "private_key": binascii.unhexlify("98967364dfe5d5f5d0180c727797d9111f3b1da573c25036ba16396579c25048"),
            },
            {
                "id": binascii.unhexlify("ffc74d10550000000000000000000000"),
                "public_key": binascii.unhexlify("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941"),
                "private_key": binascii.unhexlify("18c539194baae419f50ff117cbf15456a0762845af3d0a77ba85024ba488ce58"),
            },
            {
                "id": binascii.unhexlify("ffbb0407380000000000000000000000"),
                "public_key": binascii.unhexlify("4704aff4bc2aaaa3fd187d52913a203aba4e19f6e7b491bda8c8e67daa8daa67"),
                "private_key": binascii.unhexlify("781e6fc7636d70dae8ebf2337538b22d7b64281a55505c1f12921e7b61f09c59"),
            },
            {
                "id": binascii.unhexlify("ff81855a360000000000000000000000"),
                "public_key": binascii.unhexlify("73514173ee741afacdd4733e84f629b5cb9e34d28d072d749a8171fc6d64a930"),
                "private_key": binascii.unhexlify("9863a8f1b5307938cd4bc9782411e9eea0a38b9144d096bd923085dfb8534277"),
            },

        ]
        self.r = 5
        self.params = SphinxParams(
            self.r, group_class=GroupECC,
            hash_func=Blake2_hash,
            hash_mac_func=Blake2_hash_mac,
            lioness_class=Chacha_Lioness,
            stream_cipher=Chacha20_stream_cipher,
        )

        self.node_map = {}
        self.consensus = {}
        self.route = []

        # Create some nodes
        for i in range(len(hexedState)):
            state = SphinxNodeState()
            state.id = hexedState[i]['id']
            state.public_key = hexedState[i]['public_key']
            state.private_key = hexedState[i]['private_key']
            node = SphinxNode(self.params, state=state)
            self.route.append(node.id)
            self.node_map[node.get_id()] = node
            self.consensus[node.get_id()] = node.public_key

        # Create a client
        self.alice_client = SphinxClient(self.params, id=binascii.unhexlify("436c69656e74206564343564326264"))

    def test_client_surb(self):
        self.setUp()
        self.bob_client = SphinxClient(self.params)

        route = rand_subset(self.node_map.keys(), self.r)
        nym_id = b"Cypherpunk"
        nym_tuple = self.alice_client.create_nym(route, self.consensus)
        self.params.nymserver.add_surb(nym_id, nym_tuple)

        print("Bob sends a message to [%s]" % nym_id)
        reply_to_bob_surb = self.alice_client.create_nym(route, self.consensus)
        inner_message = {
            'surb': reply_to_bob_surb,
        }
        message = cbor.dumps(inner_message)
        print "size of serialized surb is %s" % len(message)
        nym_result = self.params.nymserver.process(nym_id, message)
        received_client_message = self.mixnet_test_state_machine(nym_result.message_result)

        inner_message = cbor.loads(received_client_message)
        assert 'surb' in inner_message
        surb = inner_message['surb']
        assert surb is not None

        # XXX todo: Bob's send message on his choosen route to -> mix proxy to SURB -> Alice

    def mixnet_test_state_machine(self, result):
        while True:
            if result.tuple_next_hop:
                result = self.send_to_mix(result.tuple_next_hop[0], result.tuple_next_hop[1], result.tuple_next_hop[2])
            elif result.tuple_exit_hop:
                print("Deliver [%s] to [%s]" % (result.tuple_exit_hop[1], binascii.hexlify(result.tuple_exit_hop[0])))
                break
            elif result.tuple_client_hop:
                result = self.send_to_client(*result.tuple_client_hop)
                print("message received by [%s]" % result.tuple_message[0])
                return result.tuple_message[1]

    def send_to_client(self, client_id, message_id, delta):
        print("send_to_client client_id %s message_id %s delta len %s" % (client_id, binascii.hexlify(message_id), len(delta)))
        return self.params.clients[client_id].decrypt(message_id, delta)

    def send_to_mix(self, destination, header, payload):
        return self.node_map[destination].unwrap(header, payload)

    def test_end_to_end(self):
        self.setUp()
        message = b"the quick brown fox"
        secret = binascii.unhexlify("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b4")
        route_len = 5
        dest_len = 1
        padding = binascii.unhexlify("3c78e065c89b26bc7b498dd6c0f24925c67a7ac0d4a191937bc7698f650391")

        alpha, beta, gamma, delta = create_forward_message(self.params, self.route, self.consensus,
                                                           self.route[-1], message, secret=secret, padding=padding)
        header = alpha, beta, gamma

        # Send it to the first node for processing
        result = self.node_map[self.route[0]].unwrap(header, delta)
        self.mixnet_test_state_machine(result)
        assert self.node_map[self.route[-1]].received[0] == message
