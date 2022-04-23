import json
import os
import random
from string import ascii_letters

from core.block import Block, LOWEST_BITS
from core.ecc import PrivateKey
from core.script import Script, p2pkh_script
from core.source import int_to_little_endian, decode_base58, little_endian_to_int, \
    hash256
from core.tx import TxIn, TxOut, Tx

from web.tesseract.models import User

COUNT_ZEROES = 4
WRONG_SYMBOLS = ['/', ',', '.', '?', '!', '@']
SATOSHI_CONSTANT = 100000000


class Client:
    def __init__(self, username, password, email, secret):
        self.id = 1
        self.username = username
        self.__password = hash256(bytes(password.encode())).hex()
        self.email = email
        self.secret = secret
        self.address = self.create_address()
        self.balance = 0
        self.testnet = True
        self.rights = None

        database = User.objects.all()
        for u in database:  #find documentation for parsing database names without for cycle
            pass
            # if username != u:
            #     user = User(username, email, password, self.address, self.secret,
            #                 self.balance, self.rights)
            #     user.save()


    @classmethod
    def generate_mnemonic(cls):
        mnemonic_phrase = ''.join(random.sample(ascii_letters, len(ascii_letters)))
        length = 5
        phrase = ' '.join(
            mnemonic_phrase[index:index + length] for index in range(0, len(mnemonic_phrase), 5))
        return phrase

    def save_user_data(self):
        with open(os.curdir + f'/client_info/{self.username}.testnet', 'w') as file:
            to_dump = {self.id: {'username': self.username, 'password': self.__password, 'email': self.email,
                                 'secret': self.secret}}
            s = json.dumps(to_dump, ensure_ascii=False, indent=4)
            file.write(s)

    def create_address(self, compressed=True):
        if isinstance(self.secret, int):
            secret = int(self.secret)
        else:
            secret = little_endian_to_int(hash256(bytes(str(self.secret), encoding='utf-8')))

        # print('Your formatted to secret key, keep it safe: {}'.format(secret))
        private_key = PrivateKey(secret)
        if compressed:
            addr = private_key.point.address(compressed=True, testnet=True)
        else:
            addr = private_key.point.address(compressed=False, testnet=True)

        return addr

    def create_sig(self, receiver_name, der=True):

        z = int.from_bytes(hash256(bytes(receiver_name, encoding='utf-8')), 'big')  # verify hash z
        p = PrivateKey(little_endian_to_int(hash256(bytes(self.secret))))
        if der:
            sig = p.sign(z).der()
        else:
            sig = p.sign(z)
        # print(sig)
        # print(p.point.verify(z, sig))
        return sig

    def create_coinbase_tx(self):
        prev_tx = b'\x00' * 32  # create coinbase tx
        prev_index = 0xffffffff
        block_height = 0
        cmds = [int_to_little_endian(block_height, 3), bytes(f'Mined by {self.username}', encoding='utf-8')]
        script_sig = Script(cmds)
        tx_ins = []
        tx_ins.append(TxIn(prev_tx, prev_index, script_sig))
        tx_outs = []
        amount = 50 * SATOSHI_CONSTANT
        h160 = decode_base58(self.address)
        script_pubkey = p2pkh_script(h160)
        tx_outs.append(TxOut(amount, script_pubkey))
        tx_obj = Tx(1, tx_ins, tx_outs, 0, testnet=True, segwit=False)
        self.balance += amount / SATOSHI_CONSTANT
        return tx_obj

    def mining_block(self, hexed_coinbase_tx):
        prev_block = b'\x00' * 32
        merkle_root = bytes.fromhex(hexed_coinbase_tx)
        number = 1
        nonce = int_to_little_endian(number, 4)
        block = Block(1, prev_block, merkle_root, 0, LOWEST_BITS, nonce)
        while not block.hash().hex().zfill(64).startswith('0' * 4):
            number += 1
            nonce = int_to_little_endian(number, 4)
            block = Block(1, prev_block, merkle_root, 0, LOWEST_BITS, nonce)
            block.hash().hex().zfill(64)
        else:
            # for i in range(10):
            #     GlobalCounter(block.hash().hex().zfill(64), hexed_coinbase_tx).write_data()
            #     i += 1
            return hash256(block.serialize())[::-1].hex().zfill(64)
            # return 'Block found: {}'.format(hash256(block.serialize())[::-1].hex().zfill(64))

    def create_tx(self, prev_tx_obj, amount, target=None):
        prev_tx = hash256(prev_tx_obj.serialize())[::-1]
        # prev_index = 0xffffffff
        prev_index = 1
        sig = self.create_sig('mirvan.testnet')
        cmds = [len(sig), sig, len(decode_base58(self.address)), decode_base58(self.address)]
        script_sig = Script(cmds)
        tx_ins = TxIn(prev_tx, prev_index, script_sig)
        priv = PrivateKey(self.secret)
        target_amount = amount * SATOSHI_CONSTANT
        target_address = 'muteChJaAaAdBEm4pgqf9sgGVqt4djt944'
        h160 = decode_base58(target_address)
        script_pubkey = p2pkh_script(h160)
        tx_outs = TxOut(target_amount, script_pubkey)
        tx_obj = Tx(1, [tx_ins], [tx_outs], locktime=0, testnet=self.testnet)
        self.balance -= target_amount / SATOSHI_CONSTANT

        # print(tx_obj.sign_input(0, priv))
        # print(tx_obj.sig_hash(0))
        # print(script_sig)
        return tx_obj.serialize().hex()
