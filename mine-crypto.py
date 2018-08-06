from __future__ import print_function
import time
import hashlib
import ecdsa
import sys
import base64
import socket
import argparse
import threading
import cPickle as pickle


class CryptoUtils(object):

    def __init__(self):
        pass

    @staticmethod
    def calculate_sha256(text):
        sha256 = hashlib.sha256()
        sha256.update(text)
        return sha256.hexdigest()

    @staticmethod
    def verify_ecdsa_sig(public_key, data, signature):
        try:
            public_key.verify(signature, data)
            return True
        except ecdsa.BadSignatureError:
            return False

    @staticmethod
    def apply_ecdsa(private_key, message):
        return private_key.sign(message)

    @staticmethod
    def get_string_from_key(key):
        return base64.b64encode(key.to_string()).decode("utf-8")


class Block(object):

    def __init__(self, timestamp, nonce, transactions, prev_block_hash):

        self.timestamp = timestamp
        self.nonce = nonce
        self.transactions = transactions
        self.prev_block_hash = prev_block_hash
        self.block_hash = None
        self.calculate_block_hash()

    def calculate_block_hash(self):
        tmp = str(self.nonce) + str(self.timestamp) + self.prev_block_hash

        for aTx in self.transactions:
            tmp += aTx.tx_id

        self.block_hash = CryptoUtils.calculate_sha256(tmp)

    def verify_txs(self):
        for aTx in self.transactions:
            if not aTx.verify_signature():
                return False
        return True

    def print_all(self):
        print("Timestamp: " + str(self.timestamp))
        print("Nonce: " + str(self.nonce))

        i = 0
        for aTx in self.transactions:
            print("Transaction {}:".format(i))
            aTx.print_all()
            i += 1
        print("Previous block hash: " + self.prev_block_hash)
        print("Block hash: " + self.block_hash)


class Chain(object):

    def __init__(self):
        self.blockchain = []
        self.difficulty = 5

    def mine_block(self, block):
        while not block.block_hash.startswith('0'*5):
            block.nonce += 1
            block.timestamp = time.time()
            block.calculate_block_hash()

        self.blockchain.append(block)

    def get_last_block_hash(self):
        return self.blockchain[-1].block_hash

    def is_chain_valid(self):
        for i in range(1, len(self.blockchain)):
            current_block = self.blockchain[i]
            prev_block = self.blockchain[i-1]

            cur_block_hash = current_block.block_hash
            current_block.calculate_block_hash()
            if not cur_block_hash == current_block.block_hash:
                return False
            if not prev_block.block_hash == current_block.prev_block_hash:
                return False
            if not current_block.prev_block_hash.startswith('0' * self.difficulty):
                return False
        return True

    def print_all(self):
        i = 0
        for block in self.blockchain:
            print("Block {}:".format(i))
            block.print_all()
            i += 1


class Transaction(object):

    count = 0

    def __init__(self, sender, recipient, value):
        self.sender = sender
        self.recipient = recipient
        self.value = value
        self.seq = Transaction.count
        Transaction.count += 1
        self.signature = None
        self.tx_id = None
        self.calculate_tx_id()

    def generate_signature(self, private_key):
        self.signature = CryptoUtils.apply_ecdsa(private_key, self.to_string())

    def verify_signature(self):
        return CryptoUtils.verify_ecdsa_sig(self.sender, self.to_string(), self.signature)

    def calculate_tx_id(self):
        self.tx_id = CryptoUtils.calculate_sha256(self.to_string())

    def to_string(self):
        return \
            CryptoUtils.get_string_from_key(self.sender) + CryptoUtils.get_string_from_key(self.recipient) + \
            str(self.value) + str(self.seq)

    def print_all(self):
        print("Transaction ID: " + self.tx_id)
        print("Sender: " + CryptoUtils.get_string_from_key(self.sender))
        print("Recipient: " + CryptoUtils.get_string_from_key(self.recipient))
        print("Value: " + str(self.value))


class Node(object):

    def __init__(self):
        self.private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.public_key = self.private_key.get_verifying_key()


# HELPER FUNCTIONS!
def parse_args():

    parser = argparse.ArgumentParser(description="Cryptomining simulation")

    parser.add_argument("-t", action="store", required=False, dest="TARGET_PORT",
                        help="target port to connect to'")

    parser.add_argument("-p", action="store", required=False, dest="PORT", help="port used for binding the server")

    _options = parser.parse_args()
    if (_options.TARGET_PORT is None and _options.PORT is None) or \
            (_options.TARGET_PORT is not None and _options.PORT is not None):
        parser.error('You have to either specify a port for a server session or a target port to connect to.')
    return _options


def handle_transaction(node, aChain):

    global nodes_socks
    while True:
        try:
            data = read(node)
        except:
            break

        if data == 'close':
            break
        else:
            aTx = data

        print("[*] Received a transaction!")

        new_block = Block(time.time(), 0, [aTx], aChain.get_last_block_hash())

        if new_block.verify_txs():
            aChain.mine_block(new_block)
            time.sleep(1)  # zZz

            write(node, "[*] Successfully added a block with your transaction to the chain")
            write(node, "[*] Block hash: {}".format(new_block.block_hash))
            time.sleep(1)

            # broadcast the chain
            for aNode in nodes_socks:
                write(aNode, aChain)

            print("[*] Block added to your chain")
            aChain.print_all()
        else:
            write(node, "[*] Invalid transactions")


def chain_verifier(aMiner):

    global chain
    while True:
        data = read(aMiner)
        if type(data).__name__ == 'Chain':
            new_chain = data
            if new_chain.is_chain_valid() and len(new_chain.blockchain) > len(chain.blockchain):
                print("[*] Chain is valid!")
                chain = new_chain
                chain.print_all()
            else:
                print("[*] Chain is not valid!")
        else:
            print(data)


def read(sock):
    f = sock.makefile('rb')
    data = pickle.load(f)
    f.close()
    return data


def write(sock, data):
    f = sock.makefile('wb')
    pickle.dump(data, f, pickle.HIGHEST_PROTOCOL)
    f.close()


if __name__ == "__main__":

    # START THE CRYPTO-MINING APPLICATION . . .

    HOST = 'localhost'
    options = parse_args()
    PORT = options.PORT

    if options.TARGET_PORT is None:

        # MINER LOGIC
        chain = Chain()
        genesis_block = Block(time.time(), 0, [], "0")
        chain.mine_block(genesis_block)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, int(PORT)))
        server.listen(5)
        print("[*] Waiting for a transaction")

        nodes_socks = []
        while True:
            node_sock, addr = server.accept()
            nodes_socks.append(node_sock)
            print("[*] Got a new connection!")
            print("[*] Address: {}".format(addr))
            # our miner is a pretty decent one and he will always accept your transaction :D

            node_handler = threading.Thread(target=handle_transaction, args=(node_sock, chain))
            node_handler.start()
    else:

        # USER LOGIC
        chain = Chain()
        aSender = Node()
        miner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        miner.connect((HOST, int(options.TARGET_PORT)))

        chain_handler = threading.Thread(target=chain_verifier, args=(miner, ))
        chain_handler.daemon = True
        chain_handler.start()

        while True:
            aRecipient = Node()
            print("[*] Input your transaction amount or type 'close' to exit!")
            _input = raw_input()

            if not _input == 'close':
                try:
                    _input = float(_input)
                except ValueError:
                    print("[*] Invalid value. Try again!")
                    continue
            else:
                sys.exit(0)

            tx = Transaction(aSender.public_key, aRecipient.public_key, _input)
            tx.generate_signature(aSender.private_key)

            write(miner, tx)
            time.sleep(1)  # zZz
            print("[*] Your transaction is being processed through the network")
            time.sleep(4)  # zZz
