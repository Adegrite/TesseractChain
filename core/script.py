from io import BytesIO
from logging import getLogger

from source import (
    encode_varint,
    h160_to_p2pkh_address,
    h160_to_p2sh_address,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    sha256,
)
from op import (
    op_equal,
    op_hash160,
    op_verify,
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
)

LOGGER = getLogger(__name__)


def p2pkh_script(h160):
    """Принимает хеш-код hash160 и возвращает сценарий ScriptPubkey для p2pkh"""
    return Script([0x76, 0xa9, h160, 0x88, 0xac])


def p2sh_script(h160):
    '''Takes a hash160 and returns the p2sh ScriptPubKey'''
    return Script([0xa9, h160, 0x87])


def p2wpkh_script(h160):
    '''Takes a hash160 and returns the p2wpkh ScriptPubKey'''
    return Script([0x00, h160])


def p2wsh_script(h256):
    """Принимает h160 и возвращает сценарий ScriptPubKey для p2wsh"""
    return Script([0x00, h256])


class Script:
    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def __add__(self, other):
        return Script(self.cmds + other.cmds)

    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    @classmethod
    def parse(cls, s):
        length = read_varint(s)
        cmds = []
        count = 0
        while count < length:
            current = s.read(1)
            count += 1
            current_byte = current[0]
            if 1 <= current_byte <= 75:  # NEXT N BYTES INCLUDES ELEMENT
                n = current_byte
                cmds.append(s.read(n))
                count += n
            elif current_byte == 76:  # OP_PUSHDATA1
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:  # OP_PUSHDATA2
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:  # OPERATION CODE
                op_code = current_byte
                cmds.append(op_code)
        if count != length:
            raise SyntaxError('Parsing script failed')
        return cls(cmds)

    def raw_serialize(self):
        result = b''
        for cmd in self.cmds:
            if type(cmd) == int:
                result += int_to_little_endian(cmd, 1)
            else:
                length = len(cmd)
                if length < 75:
                    result += int_to_little_endian(cmd, 1)
                elif 75 < length < 0x100:
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif 0x100 <= length <= 520:
                    result += int_to_little_endian(77, 2)
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError('too large element')
                result += cmd
        return result

    def serialize(self):
        result = self.raw_serialize()
        total = len(result)
        return encode_varint(total) + result

    def evaluate(self, z, witness):
        cmds = self.cmds[:]
        stack = []
        altstack = []
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            if type(cmd) == int:
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99, 100):
                    if not operation(stack, cmds):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (107, 108):
                    if not operation(stack, altstack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (172, 173, 174, 175):
                    if not operation(stack, z):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                else:
                    if not operation(stack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
            else:
                stack.append(cmd)
                if len(stack) == 3 and stack[0] == 0xa9 and type(stack[1]) == bytes and len(stack[1]) == 20 and stack[
                    2] == 0x87:
                    stack.pop()
                    h160 = stack.pop()
                    stack.pop()
                    if not op_hash160:
                        return False
                    stack.append(h160)
                    if not op_equal:
                        return False
                    if not op_verify:
                        LOGGER.info('bad p2sh h160')
                    redeem_script = encode_varint(len(cmd)) + cmd
                    stream = BytesIO(redeem_script)
                    cmds.extend(Script.parse(stream).cmds)

                if len(stack) == 2 and stack[0] == b'' and len(stack[1]) == 20:
                    h160 = stack.pop()
                    stack.pop()
                    cmds.extend(witness)
                    cmds.extend(p2pkh_script(h160).cmds)

                if len(stack) == 2 and stack[0] == b'' and len(stack[1]) == 32:
                    s256 = stack.pop()
                    stack.pop()
                    cmds.extend(witness[:-1])
                    witness_script = witness[-1]
                    if s256 != sha256(witness_script):
                        print('bad sha256 {} vs {}'.format(s256.hex(), sha256(witness_script).digest().hex()))
                        return False
                    stream = BytesIO(encode_varint(len(witness_script)) + witness_script)
                    witness_script_cmds = Script.parse(stream).cmds
                    cmds.extend(witness_script_cmds)

        if len(stack) == 0:
            return False
        if stack.pop() == b'':
            return False
        return True

    def is_p2pkh_script_pubkey(self):
        '''Returns whether this follows the
        OP_DUP OP_HASH160 <20 byte hash> OP_EQUALVERIFY OP_CHECKSIG pattern.'''
        # there should be exactly 5 cmds
        # OP_DUP (0x76), OP_HASH160 (0xa9), 20-byte hash, OP_EQUALVERIFY (0x88),
        # OP_CHECKSIG (0xac)
        return len(self.cmds) == 5 and self.cmds[0] == 0x76 \
               and self.cmds[1] == 0xa9 \
               and type(self.cmds[2]) == bytes and len(self.cmds[2]) == 20 \
               and self.cmds[3] == 0x88 and self.cmds[4] == 0xac

    def is_p2sh_script_pubkey(self):
        '''Returns whether this follows the
        OP_HASH160 <20 byte hash> OP_EQUAL pattern.'''
        # there should be exactly 3 cmds
        # OP_HASH160 (0xa9), 20-byte hash, OP_EQUAL (0x87)
        return len(self.cmds) == 3 and self.cmds[0] == 0xa9 \
               and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 20 \
               and self.cmds[2] == 0x87

    def is_p2wpkh_script_pubkey(self):
        return len(self.cmds) == 2 and self.cmds[0] == 0x00 \
               and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 20

    def is_p2wsh_script_pubkey(self):
        return len(self.cmds) == 2 and self.cmds[0] == 0x00 \
               and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 32

    def address(self, testnet=False):
        '''Returns the address corresponding to the script'''
        if self.is_p2pkh_script_pubkey():  # p2pkh
            # hash160 is the 3rd cmd
            h160 = self.cmds[2]
            # convert to p2pkh address using h160_to_p2pkh_address (remember testnet)
            return h160_to_p2pkh_address(h160, testnet)
        elif self.is_p2sh_script_pubkey():  # p2sh
            # hash160 is the 2nd cmd
            h160 = self.cmds[1]
            # convert to p2sh address using h160_to_p2sh_address (remember testnet)
            return h160_to_p2sh_address(h160, testnet)
        raise ValueError('Unknown ScriptPubKey')

    # script(сценарий) realize
# z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
# sec = bytes.fromhex('04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e\
# 4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34')
# sig = bytes.fromhex('3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f4048\
# 76325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fd\
# dbdce6feab601')
# script_pk = Script([sec, 0xac])
# script_sig = Script([sig])
# comb = script_sig + script_pk
# print(comb.evaluate(z))

# ch6 ex 3
# script_pubkey = Script([0x76, 0x76, 0x95, 0x93, 0x56, 0x87])
# script_sig = Script([0x52])
# combscript = script_sig + script_pubkey
# print(combscript.evaluate(0))
# end ex3

# ex4
# script = Script([0x6e,0x87, 0x91, 0x69, 0xa7, 0x7c, 0xa7, 0x87])
# print(script.evaluate(0, witness=False))
# stack = [1,2]
# stack.extend(stack[-2:])
# print(stack)
# end ex4
