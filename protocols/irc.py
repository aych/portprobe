#
# This module is a very basic IRC protocol handler that attempts to connect to a server and get a list of channels.
#
from protocol import Protocol
from string import ascii_letters, digits
from random import choice


class IRCProtocol(Protocol):
    def __init__(self):
        Protocol.__init__(self)
        # Module-specific attributes
        self.attributes = {
            "NAME": 'irc',
            "MODULE_SPEAKS_PROTOCOL": True,
            "PROTOCOL_DEFAULT_PORTS": [6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 7000],
            "PROTOCOL_SPEAKS_FIRST": True,
            "PATTERN": r"[0-9A-Z:a-z-\s*._]+?:[0-9A-Z:a-z-\s*._]+?"
        }
        self.compile_pattern()
        self.unprocessed = ''
        self.registered = False

    def generate_name(self, length=8):
        chars = ascii_letters + digits
        return ''.join(choice(chars) for x in range(length))

    def on_recv(self, data, probe):
        reply = ''
        self.buf += data

        if len(self.unprocessed) > 0:
            data = self.unprocessed + data
            self.unprocessed = ''

        lines = data.split('\n')
        for i, line in enumerate(lines):
            if len(line) == 0:
                break

            if i == len(lines) - 1:
                self.unprocessed = line
                break

            params = line.split(':')
            if len(params[0]) == 0:
                cmdparams = params[1].split(' ')
                rest = line[line.find(':', 2) + 1:]
                cmd = cmdparams[1]

                if cmd.isdigit():
                    if cmd == '001':
                        pass
                    elif cmd == '004':
                        reply = "LIST\n"
                    elif cmd == '323':
                        probe.completed(self.buf)
                    else:
                        pass
                else:
                    if cmdparams[1] == '---':
                        pass
                    elif cmdparams[1] == 'NOTICE':
                        if cmdparams[2] in ['AUTH', '*']:
                            if not self.registered:
                                name = self.generate_name()
                                reply = "NICK {name}\n".format(name=name)
                                reply += "USER {name} 8 * :{name}\n".format(name=name)
                                self.registered = True
            else:
                cmd = params[0].rstrip(None)

                if cmd == 'PING':
                    reply = "PONG {}\n".format(params[1])
                else:
                    # Unrecognized non-command
                    pass
        if not probe.complete and len(reply) > 0:
            self.buf += reply
            probe.reply(reply)


def get_instance():
    return IRCProtocol()

if __name__ == '__main__':
    p = get_instance()
    print p.matches_protocol(":holmes.freenode.net NOTICE * :*** Looking up your hostname...")