from __future__ import print_function

import glob
import imp
import os
import select
import socket

BUFFER_SIZE = 4096
SOCKET_TIMEOUT = 2


class PortProbe():
    def __init__(self):
        self.protocol_modules = {}
        self.speak_first = []
        self.speak_second = []
        self.s = None
        self.complete = False

        # Load the list of protocols
        protocol_list = glob.glob('protocols/*.py')
        for protocol in protocol_list:
            _path, _file = os.path.split(protocol)
            _module, _ext = os.path.splitext(_file)
            try:
                _file, _path, _description = imp.find_module(_module, ['protocols/'])
            except:
                raise

            try:
                obj = imp.load_module(_module, _file, _path, _description)
                self.protocol_modules[_module] = obj
            except:
                raise

        self.speak_first = [protocol for key, protocol in self.protocol_modules.items()
                            if protocol.attributes['PROTOCOL_SPEAKS_FIRST']]
        self.speak_second = [protocol for key, protocol in self.protocol_modules.items()
                             if not protocol.attributes['PROTOCOL_SPEAKS_FIRST']]

    def probe(self, ip, port):
        """

        :rtype : list
        """
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(SOCKET_TIMEOUT)
        self.s.connect((ip, port))
        data = None
        try:
            data = self.s.recv(BUFFER_SIZE)
        except socket.timeout:
            # This is probably a send-first protocol.
            # Can deal with this below at the data check.
            print("Probably send-first...")
            pass
        except:
            raise

        matches = []
        if data is not None:
            matches = [protocol for protocol in self.speak_first
                       if protocol.matches_protocol(data)]
        else:
            matches = self.speak_second

        print("Potential matches:", matches)

        if len(matches) == 0:
            # No protocols matched...
            pass
        elif len(matches) == 1:
            # Awesome, we can do something.
            # Does the plugin speak the protocol?
            if matches[0].attributes['MODULE_SPEAKS_PROTOCOL']:
                if matches[0].attributes['PROTOCOL_SPEAKS_FIRST']:
                    matches[0].on_recv(data, self)
                else:
                    matches[0].on_connect(self)
                while not self.complete:
                    rr, wr, er = select.select([self.s], [], [], SOCKET_TIMEOUT)
                    if len(rr) == 0:
                        break
                    for i in rr:
                        if i == self.s:
                            data = i.recv(BUFFER_SIZE)
                            if len(data) == 0:
                                matches[0].on_close(self)
                                break
                            matches[0].on_recv(data, self)
            else:
                if matches[0].attrbutes['PROTOCOL_SPEAKS_FIRST']:
                    self.completed(data)
        elif len(matches) > 1:
            # We're going to have to figure out which one to try.
            # Best guess based on port, otherwise, no clue...
            matches = [m for m in matches
                       if port in m.attributes['PROTOCOL_DEFAULT_PORTS']]

    def reply(self, data):
        self.s.send(data)

    def completed(self, buf):
        self.complete = True
        self.s.close()
        print("Probe complete: {buf}".format(buf=buf))

if __name__ == '__main__':
    from optparse import OptionParser

    parser = OptionParser()

    parser.add_option('-i', '--ip', dest='ip', help='IP being connected to')
    parser.add_option('-p', '--port', dest='port', help='Port to connect to')
    (options, args) = parser.parse_args()

    p = PortProbe()

    p.probe('74.125.225.168', 80) # Google HTTP
    #p.probe('64.4.17.176', 21) # Microsoft FTP
    #p.probe('63.245.215.46', 21) # Mozilla FTP
    #p.probe('213.232.93.3', 6667) # Freenode IRC
    #p.probe('130.239.18.160', 6667) # OFTC IRC