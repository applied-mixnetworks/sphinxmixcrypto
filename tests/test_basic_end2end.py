
import py.test
import binascii
import cbor

from sphinxmixcrypto.params import SphinxParams
from sphinxmixcrypto.params import GroupECC, Chacha_Lioness, Chacha20_stream_cipher, Blake2_hash, Blake2_hash_mac
from sphinxmixcrypto.params import GroupP, AES_Lioness, AES_stream_cipher, SHA256_hash, SHA256_hash_mac
from sphinxmixcrypto import SphinxNode
from sphinxmixcrypto.node import ReplayError, BlockSizeMismatchError
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


class TestSphinxMix():

    def setUpPParams(self):
        self.r = 5
        self.params = SphinxParams(
            self.r, group_class=GroupP,
            hash_func=SHA256_hash,
            hash_mac_func=SHA256_hash_mac,
            lioness_class=AES_Lioness,
            stream_cipher=AES_stream_cipher,
        )

        self.node_map = {}
        self.consensus = {}
        # Create some nodes
        for i in range(2 * self.r):
            node = SphinxNode(self.params)
            self.node_map[node.get_id()] = node
            self.consensus[node.get_id()] = node.public_key

        # Create a client
        self.alice_client = SphinxClient(self.params)
        # Pick a list of nodes to use
        self.route = rand_subset(self.node_map.keys(), self.r)

    def setUpECCParams(self):
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
        # Create some nodes
        for i in range(2 * self.r):
            node = SphinxNode(self.params)
            self.node_map[node.get_id()] = node
            self.consensus[node.get_id()] = node.public_key

        # Create a client
        self.alice_client = SphinxClient(self.params)
        # Pick a list of nodes to use
        self.route = rand_subset(self.node_map.keys(), self.r)

    def test_client_surb(self):
        self.setUpECCParams()
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
                print("result.tuple_next_hop")
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
        print("send_to_mix")
        return self.node_map[destination].unwrap(header, payload)

    def test_end_to_end_ecc(self):
        self.setUpECCParams()
        self.end_to_end()

    def test_end_to_end_p(self):
        self.setUpPParams()
        self.end_to_end()

    def end_to_end(self):
        message = b"this is a test"
        alpha, beta, gamma, delta = create_forward_message(self.params, self.route, self.consensus, self.route[-1], message)
        header = alpha, beta, gamma

        # Send it to the first node for processing
        result = self.node_map[self.route[0]].unwrap(header, delta)
        self.mixnet_test_state_machine(result)
        assert self.node_map[self.route[-1]].received[0] == message

        # Create a reply block for the client
        reply_route = rand_subset(self.node_map.keys(), self.r)
        nym = b"cypherpunk"
        nym_tuple = self.alice_client.create_nym(reply_route, self.consensus)
        self.params.nymserver.add_surb(nym, nym_tuple)

        # Send a message to it
        reply_message = b"this is a reply"
        nym_id = b"cypherpunk"
        print("Nymserver received message for [%s]" % nym_id)
        nym_result = self.params.nymserver.process(nym_id, reply_message)
        self.mixnet_test_state_machine(nym_result.message_result)
