from __future__ import print_function
import time
import hashlib
import ecdsa
import base64
import socket
import argparse
import threading
import pickle


class crypto_utils:

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


class Block:

    def __init__(self, timestamp, nonce, transactions, prev_blockhash):

        self.timestamp = timestamp
        self.nonce = nonce
        self.transactions = transactions
        self.prev_blockHash = prev_blockhash
        self.blockHash = None
        self.calculateBlockHash()

    def get_time_stamp(self):
        return self.timestamp

    def set_time_stamp(self, timestamp):
        self.timestamp = timestamp

    def get_nonce(self):
        return self.nonce

    def set_nonce(self, nonce):
        self.nonce = nonce

    def get_prev_blockHash(self):
        return self.prev_blockHash

    def get_blockHash(self):
        return self.blockHash

    def calculateBlockHash(self):
        tmp = str(self.nonce) + str(self.timestamp) + self.prev_blockHash

        for tx in self.transactions:
            tmp += tx.tx_id

        self.blockHash = crypto_utils.calculate_sha256(tmp)

    def verifyTxs(self):
        for tx in self.transactions:
            if not tx.verify_signature():
                return False
        return True

    def print_all(self):
        print("Timestamp: " + str(self.timestamp))
        print("Nonce: "     + str(self.nonce))
        i = 0
        for tx in self.transactions:
            print("Transaction {}:".format(i))
            tx.print_all()
            i += 1
        print("Previous block hash: "+ self.prev_blockHash)
        print("Block hash: " + self.blockHash)


class Chain:

    def __init__(self):
        self.blockchain = []
        self.difficulty = 5

    def mineBlock(self, block):

        while not block.get_blockHash().startswith('0'*5):
            block.set_nonce(block.get_nonce()+1)
            block.set_time_stamp(time.time())
            block.calculateBlockHash()

        self.blockchain.append(block)

    def get_last_block_hash(self):
        return self.blockchain[-1].get_blockHash()

    def isChainValid(self):

        for i in range(1, len(self.blockchain)):
            current_block = self.blockchain[i]
            prev_block = self.blockchain[i-1]

            cur_block_hash = current_block.get_blockHash()
            current_block.calculateBlockHash()
            if not cur_block_hash == current_block.get_blockHash():
                return False
            if not prev_block.get_blockHash() == current_block.get_prev_blockHash():
                return False
            if not current_block.get_blockHash().startswith('0' * self.difficulty):
                return False
        return True

    def print_all(self):
        for block in self.blockchain:
            print("Block:")
            block.print_all()


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
        self.signature = crypto_utils.apply_ecdsa(private_key, self.to_string())

    def verify_signature(self):
        return crypto_utils.verify_ecdsa_sig(self.sender, self.to_string(), self.signature)

    def calculate_tx_id(self):
        self.tx_id = crypto_utils.calculate_sha256(self.to_string())

    def to_string(self):
        return \
            crypto_utils.get_string_from_key(self.sender) + crypto_utils.get_string_from_key(self.recipient) + \
            str(self.value) + str(self.seq)

    def print_all(self):
        print("Transaction ID: "+ self.tx_id)
        print("Sender: " + crypto_utils.get_string_from_key(self.sender))
        print("Recipient: " + crypto_utils.get_string_from_key(self.recipient))
        print("Value: "+ str(self.value))


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

    options = parser.parse_args()
    if (options.TARGET_PORT is None and options.PORT is None) or \
            (not options.TARGET_PORT is None and not options.PORT is None):
        parser.error('You have to either specify a port for a server session or a target port to connect to.')
    return options


def handle_transaction(client_socket, aChain):

    while True:
        data = client_socket.recv(4096)
        tx = pickle.loads(data)
        new_block = Block(time.time(), 0, [tx], aChain.get_last_block_hash())

        if new_block.verifyTxs():
            aChain.mineBlock(new_block)
            client_socket.send("[*] Successfully added a block with your transaction to the chain")
            client_socket.send("[*] Block hash: {}".format(new_block.get_blockHash()))
            client_socket.send(pickle.dumps(aChain))
            print("[*] Block added to your chain")
            aChain.print_all()
        else:
            client_socket.send("[*] Invalid transactions")


if __name__ == "__main__":

    # START THE CRYPTO-MINING APPLICATION . . .

    HOST = 'localhost'
    options = parse_args()
    PORT = options.PORT

    if options.TARGET_PORT is None:

        # MINER LOGIC
        chain = Chain()
        genesis_block = Block(time.time(), 0, [], "0")
        chain.mineBlock(genesis_block)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, int(PORT)))
        server.listen(5)
        print("[*] Waiting for a transaction")

        while True:
            client, addr = server.accept()

            print("[*] got a transaction!")
            # our miner is a pretty decent one and he will always accept your transaction :D

            client_handler = threading.Thread(target=handle_transaction, args=(client, chain))
            client_handler.start()
    else:

        # USER LOGIC
        chain = Chain()
        sender = Node()
        while True:
            recipient = Node()
            amount = input("[*] Input your transaction amount: ")

            try:
                amount = float(amount)
            except ValueError:
                print("[*] Invalid value. Try again!")
                continue

            tx = Transaction(sender.public_key, recipient.public_key, 3)
            tx.generate_signature(sender.private_key)

            miner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            miner.connect((HOST, int(options.TARGET_PORT)))
            miner.send(pickle.dumps(tx))

            print(miner.recv(4096))
            print(miner.recv(4096))
            new_chain = pickle.load(miner.makefile("r"))

            if new_chain.isChainValid() and len(new_chain.blockchain) > len(chain.blockchain):
                print("[*] Chain is valid!")
                chain = new_chain
                chain.print_all()
            else:
                print("[*] Chain is not valid!")
