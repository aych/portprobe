#
# This module is a very basic IRC protocol handler that attempts to connect to a server and get a list of channels.
#

import re

# Module-specific attributes
attributes = {
    "NAME": 'irc',
    "MODULE_SPEAKS_PROTOCOL": True,
    "PROTOCOL_DEFAULT_PORTS": [6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 7000],
    "PROTOCOL_SPEAKS_FIRST": True,
    "PATTERN": r"[0-9A-Z:a-z-\s*._]+?:[0-9A-Z:a-z-\s*._]+?"
}

regex = re.compile(attributes['PATTERN'])
buf = ''
unprocessed = ''
registered = False

def matches_protocol(packet):
    if regex.match(packet) is not None:
        return True
    else:
        return False


def on_recv(data, probe):
    global buf
    global unprocessed
    global registered
    reply = ''
    buf += data

    if len(unprocessed) > 0:
        data = unprocessed + data
        unprocessed = ''

    lines = data.split('\n')
    for i, line in enumerate(lines):
        if len(line) == 0:
            break

        if i == len(lines) - 1:
            unprocessed = line
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
                    probe.completed(buf)
                else:
                    pass
            else:
                if cmdparams[1] == '---':
                    pass
                elif cmdparams[1] == 'NOTICE':
                    if cmdparams[2] in ['AUTH', '*']:
                        if not registered:
                            reply = "NICK probey\n"
                            reply += "USER probey 8 * :probey\n"
                            registered = True
        else:
            cmd = params[0].rstrip(None)

            if cmd == 'PING':
                reply = "PONG {}\n".format(params[1])
            else:
                # Unrecognized non-command
                pass
    buf += reply
    probe.reply(reply)

if __name__ == '__main__':
    print matches_protocol(":holmes.freenode.net NOTICE * :*** Looking up your hostname...")