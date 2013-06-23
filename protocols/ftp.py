#
# This module is a very basic FTP protocol handler that attempts to log in anonymously and grab the
# directory it's in.
#
# TODO: Handle failed anonymous login
# TODO: Put the connection into passive mode and attempt to retrieve a directory list. (requires another socket)

import re

# Module-specific attributes
attributes = {
    "NAME": 'ftp',
    "MODULE_SPEAKS_PROTOCOL": True,
    "PROTOCOL_DEFAULT_PORTS": [21],
    "PROTOCOL_SPEAKS_FIRST": True,
    "PATTERN": r"\d{3}(\s|-).*"
}

regex = re.compile(attributes['PATTERN'])
buf = ''


def matches_protocol(packet):
    if regex.match(packet) is not None:
        return True
    else:
        return False


def on_recv(data, probe):
    global buf
    reply = ''
    buf += data

    lines = data.split('\n')
    for line in lines:
        if len(line) == 0:
            break
        command = line[0:3]

        if command == '220':
            reply = "USER anonymous\r\n"
        elif command == '331':
            reply = "PASS anonymous\r\n"
        elif command == '230':
            reply = "PWD\r\n"
        else:
            probe.completed(buf)
            return

    buf += reply
    probe.reply(reply)

if __name__ == '__main__':
    print matches_protocol("220 Microsoft FTP Service")