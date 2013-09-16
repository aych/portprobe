#
# This module is a very basic SSH protocol handler.
#

import base64
import hashlib
import struct
import os
from protocol import Protocol

KEX_ALGORITHMS = ['diffie-hellman-group1-sha1']
HOST_KEY_ALGORITHMS = ['ssh-rsa', 'ssh-dss']
ENCRYPTION_ALGORITHMS = ['aes256-ctr', 'aes256-cbc', 'rijndael-cbc@lysator.liu.se', 'aes192-ctr', 'aes192-cbc',
                         'aes128-ctr', 'aes128-cbc', 'blowfish-ctr', 'blowfish-cbc', '3des-ctr', '3des-cbc',
                         'arcfour256', 'arcfour128']
MAC_ALGORITHMS = ['hmac-sha1', 'hmac-sha1-96', 'hmac-md5']
COMPRESSION_ALGORITHMS = ['none', 'zlib']

SSH_MSG_KEXINIT = 20
SSH_MSG_KEXDHINIT = 30
SSH_MSG_KEXDH_REPLY = 31


class PacketBuffer():
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read_byte(self):
        val = struct.unpack('B', self.data[self.pos])
        self.pos += 1
        return val

    def read_dword(self):
        val = struct.unpack('>L', self.data[self.pos:self.pos+4])
        self.pos += 4
        return val

    def read_string(self):
        length = struct.unpack(">L", self.data[self.pos:self.pos+4])
        val = self.data[self.pos+4:self.pos+4+length[0]]
        self.pos += 4 + length[0]
        return val

    def read_raw(self, length):
        val = self.data[self.pos:self.pos+length]
        self.pos += length
        return val


class SSHPacket():
    def __init__(self):
        self.length = 0
        self.payload_length = 0
        self.padding_length = 0
        self.payload = ''
        self.padding = ''

    def generate_padding(self, length):
        if length < 4:
            length += 8
        self.padding_length = length
        self.padding = os.urandom(length)

    def generate_packet(self):
        tmplen = 1 + self.payload_length
        self.generate_padding(tmplen % 16)
        self.length = tmplen + self.padding_length

        packet = struct.pack('>LB', self.length, self.padding_length) + self.payload + self.padding
        return packet

    def append_byte(self, byte):
        self.payload += struct.pack('B', byte)
        self.payload_length += 1

    def append_dword(self, dword):
        self.payload += struct.pack('>L', dword)
        self.payload_length += 4

    def append_string(self, string):
        length = len(string)
        self.payload += struct.pack('>L', length) + string
        self.payload_length += 4 + length

    def append_raw(self, raw_data):
        self.payload += raw_data
        self.payload_length += len(raw_data)


class SSHProtocol(Protocol):
    def __init__(self):
        Protocol.__init__(self)
        # Module-specific attributes
        self.attributes = {
            "NAME": 'ssh',
            "MODULE_SPEAKS_PROTOCOL": True,
            "PROTOCOL_DEFAULT_PORTS": [22],
            "PROTOCOL_SPEAKS_FIRST": True,
            "PATTERN": r"SSH-[^-]+-[^\s]+(\s.+)?"
        }
        self.compile_pattern()
        self.recv_header = False

    def on_recv(self, data, probe):
        self.buf += data
        reply = ''
        if not self.recv_header:
            self.recv_header = True
            if self.matches_protocol(data):
                probe.result['matched'] = True
                reply = 'SSH-2.0-PuTTY_Release_0.62\r\n'
                self.buf += reply
                probe.reply(reply)

                p = SSHPacket()
                p.append_byte(SSH_MSG_KEXINIT)
                # Cookie
                p.append_raw(os.urandom(16))
                p.append_string(','.join(KEX_ALGORITHMS))
                p.append_string(','.join(HOST_KEY_ALGORITHMS))
                p.append_string(','.join(ENCRYPTION_ALGORITHMS))
                p.append_string(','.join(ENCRYPTION_ALGORITHMS))
                p.append_string(','.join(MAC_ALGORITHMS))
                p.append_string(','.join(MAC_ALGORITHMS))
                p.append_string(','.join(COMPRESSION_ALGORITHMS))
                p.append_string(','.join(COMPRESSION_ALGORITHMS))
                # Languages
                p.append_dword(0)
                p.append_dword(0)
                # First packet follows?
                p.append_byte(0)
                # Reserved
                p.append_dword(0)
                reply = p.generate_packet()
        else:
            b = PacketBuffer(data)
            b.read_dword()  # Packet length
            b.read_byte()  # Padding length
            action = b.read_byte()[0]  # Action
            if action == SSH_MSG_KEXINIT:
                b.read_raw(16)  # Cookie
                options = {
                    'kex': b.read_string(),
                    'server_host_key': b.read_string(),
                    'encryption_client_server': b.read_string(),
                    'encryption_server_client': b.read_string(),
                    'mac_client_server': b.read_string(),
                    'mac_server_client': b.read_string(),
                    'compression_client_server': b.read_string(),
                    'compression_server_client': b.read_string(),
                    'languages_client_server': b.read_string(),
                    'languages_server_client': b.read_string()
                }

                # Determine the key type
                available_keys = [x for x in HOST_KEY_ALGORITHMS if x in options['server_host_key'].split(',')]
                if len(available_keys) == 0:
                    probe.result['error'] = True
                    probe.completed(self.buf)
                    return

                key_type = available_keys[0]
                probe.result['key_type'] = key_type

                prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF

                x = int(os.urandom(128).encode('hex'), 16)
                e = pow(2, x, prime)
                #v = hex(e)[2:-1]
                v = hex(e)[4:-1]
                v = '7f' + v  # If the first byte is >0x7f, the server disconnects.
                if len(v) % 2 == 1:
                    v = '0' + v

                v = v.decode('hex')

                p = SSHPacket()
                p.append_byte(SSH_MSG_KEXDHINIT)
                p.append_string(v)
                reply = p.generate_packet()
            elif action == SSH_MSG_KEXDH_REPLY:
                host_key = b.read_string()
                probe.result['key_fingerprint'] = hashlib.md5(host_key).hexdigest()
                probe.result['key_base64'] = base64.b64encode(host_key)
                probe.completed(self.buf)
            else:
                pass

        self.buf += reply
        probe.reply(reply)

    def on_close(self, probe):
        probe.result['error'] = True
        probe.completed(self.buf)


def get_instance():
    return SSHProtocol()

if __name__ == '__main__':
    #p = get_instance()
    p = SSHPacket()
    p.append_byte(SSH_MSG_KEXINIT)
    # Cookie
    p.append_raw(os.urandom(16))
    p.append_string('diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,'
                    'diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,rsa2048-sha256,rsa1024-sha1')
    p.append_string('ssh-rsa,ssh-dss')
    p.append_string('aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,aes192-cbc,'
                    'aes128-ctr,aes128-cbc,blowfish-ctr,blowfish-cbc,3des-ctr,3des-cbc,arcfour256,arcfour128')
    p.append_string('aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,aes192-cbc,aes128-ctr,aes128-cbc,'
                    'blowfish-ctr,blowfish-cbc,3des-ctr,3des-cbc,arcfour256,arcfour128')
    p.append_string('hmac-sha1,hmac-sha1-96,hmac-md5')
    p.append_string('hmac-sha1,hmac-sha1-96,hmac-md5')
    p.append_string('none,zlib')
    p.append_string('none,zlib')
    # Languages
    p.append_dword(0)
    p.append_dword(0)
    # First packet follows?
    p.append_byte(0)
    # Reserved
    p.append_dword(0)