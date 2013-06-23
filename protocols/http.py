#
# This module is a very basic HTTP protocol handler that attempts to grab the page at the root with no other handling.
#
# TODO: Parse status codes so we can make some better decisions.
# TODO: Follow a default redirect based on status codes.

import re

# Module-specific attributes
attributes = {
    "NAME": 'http',
    "MODULE_SPEAKS_PROTOCOL": True,
    "PROTOCOL_DEFAULT_PORTS": [80, 1080, 8080],
    "PROTOCOL_SPEAKS_FIRST": False,
    "PATTERN": r"HTTP.+?\s\d{3}\s.+?"
}

regex = re.compile(attributes['PATTERN'])
buf = ''


def matches_protocol(packet):
    if regex.match(packet) is not None:
        return True
    else:
        return False


def on_connect(probe):
    probe.reply("GET / HTTP/1.0\r\n\r\n")


def on_recv(data, probe):
    global buf
    buf += data


def on_close(probe):
    global buf
    probe.completed(buf)

if __name__ == '__main__':
    pass