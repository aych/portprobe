#
# This module is a very basic FTP protocol handler that attempts to log in anonymously and grab the
# directory it's in.
#
# TODO: Handle failed anonymous login
# TODO: Put the connection into passive mode and attempt to retrieve a directory list. (requires another socket)

from protocol import Protocol


class FTPProtocol(Protocol):
    def __init__(self):
        Protocol.__init__(self)
        # Module-specific attributes
        self.attributes = {
            "NAME": 'ftp',
            "MODULE_SPEAKS_PROTOCOL": True,
            "PROTOCOL_DEFAULT_PORTS": [21],
            "PROTOCOL_SPEAKS_FIRST": True,
            "PATTERN": r"\d{3}(\s|-).*"
        }
        self.compile_pattern()

    def on_recv(self, data, probe):
        reply = ''
        self.buf += data

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
                probe.completed(self.buf)
                return

        self.buf += reply
        probe.reply(reply)


def get_instance():
    return FTPProtocol()

if __name__ == '__main__':
    p = get_instance()
    print p.matches_protocol("220 Microsoft FTP Service")