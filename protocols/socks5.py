#
# This module is a very basic SOCKS5 wrapper that tests if the server allows unauthenticated proxying.
#
# TODO: Support other authentication methods?

import struct
from protocol import Protocol


class SOCKS5Protocol(Protocol):
    def __init__(self):
        Protocol.__init__(self)
        # Module-specific attributes
        self.attributes = {
            "NAME": 'socks5',
            "MODULE_SPEAKS_PROTOCOL": True,
            "PROTOCOL_DEFAULT_PORTS": [1080, 8080],
            "PROTOCOL_SPEAKS_FIRST": False,
            "PATTERN": r""
        }
        self.compile_pattern()

    def on_connect(self, probe):
        probe_test = struct.pack('BBB', 0x05, 0x01, 0x00)
        probe.reply(probe_test)

    def on_recv(self, data, probe):
        self.buf += data
        version, auth_type = struct.unpack('BB', data)
        if version == 0x05 and auth_type == 0x00:
            probe.result['version'] = 'SOCKS5'
            probe.result['authentication'] = 'No authentication'
            probe.result['matched'] = True

        probe.completed(self.buf)

    def on_close(self, probe):
        pass


def get_instance():
    return SOCKS5Protocol()

if __name__ == '__main__':
    p = SOCKS5Protocol()