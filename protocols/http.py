#
# This module is a very basic HTTP protocol handler that attempts to grab the page at the root with no other handling.
#
# TODO: Parse status codes so we can make some better decisions.
# TODO: Follow a default redirect based on status codes.

from protocol import Protocol


class HTTPProtocol(Protocol):
    def __init__(self):
        Protocol.__init__(self)
        # Module-specific attributes
        self.attributes = {
            "NAME": 'http',
            "MODULE_SPEAKS_PROTOCOL": True,
            "PROTOCOL_DEFAULT_PORTS": [80, 1080, 8080],
            "PROTOCOL_SPEAKS_FIRST": False,
            "PATTERN": r"^HTTP.+?\s\d{3}\s.+?"
        }
        self.compile_pattern()

    def on_connect(self, probe):
        probe.reply("GET / HTTP/1.0\r\n\r\n")

    def on_recv(self, data, probe):
        self.buf += data

    def on_close(self, probe):
        if self.matches_protocol(self.buf):
            probe.result['matched'] = True
        probe.completed(self.buf)


def get_instance():
    return HTTPProtocol()

if __name__ == '__main__':
    p = HTTPProtocol()