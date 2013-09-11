from __future__ import print_function

import glob
import imp
import json
import os
import select
import socket

BUFFER_SIZE = 4096
SOCKET_TIMEOUT = 2

# TODO: When the protocol speaks first and there are multiple matches, don't have it create a new socket to try the first one.


class PortProbe():
    def __init__(self, starting_callback, completion_callback, limit_probes=True):
        self.protocol_modules = {}
        self.speak_first = []
        self.speak_second = []
        self.s = None
        self.complete = False
        self.on_probe_start = starting_callback
        self.on_completed = completion_callback
        self.limit_probes = limit_probes

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
                self.protocol_modules[_module] = obj.get_instance()
            except:
                raise

        self.speak_first = [protocol for key, protocol in self.protocol_modules.items()
                            if protocol.attributes['PROTOCOL_SPEAKS_FIRST']]
        self.speak_second = [protocol for key, protocol in self.protocol_modules.items()
                             if not protocol.attributes['PROTOCOL_SPEAKS_FIRST']]

    def probe_connect(self, ip, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(SOCKET_TIMEOUT)
        try:
            self.s.connect((ip, port))
            return True
        except socket.error, e:
            # Connection refused
            if e.errno == 61:
                print("Connection refused for {ip}:{port}".format(ip=ip, port=port))
            else:
                print("Error connecting to {ip}:{port} -> {errno} {error}".format(ip=ip,
                                                                                port=port,
                                                                                errno=e.errno,
                                                                                error=e.message))
            return False

    def probe(self, ip, port):
        self.on_probe_start(ip, port)
        self.complete = False
        self.result = {"ip": ip, "port": port}
        if not self.probe_connect(ip, port):
            return

        data = None
        try:
            data = self.s.recv(BUFFER_SIZE)
        except socket.timeout:
            # This is probably a send-first protocol.
            # Can deal with this below at the data check.
            pass
        except:
            raise

        if data is not None:
            spoke_first = True
            matches = [protocol for protocol in self.speak_first
                       if protocol.matches_protocol(data)]
        else:
            spoke_first = False
            matches = self.speak_second

        if len(matches) == 0:
            # No protocols matched...
            pass
        elif len(matches) == 1:
            # Awesome, we can do something.
            # Does the plugin speak the protocol?
            prot = matches[0]
            self.result['protocol'] = prot.attributes['NAME']
            if prot.attributes['MODULE_SPEAKS_PROTOCOL']:
                if prot.attributes['PROTOCOL_SPEAKS_FIRST']:
                    prot.on_recv(data, self)
                else:
                    prot.on_connect(self)
                while not self.complete:
                    rr, wr, er = select.select([self.s], [], [], SOCKET_TIMEOUT)
                    if len(rr) == 0:
                        break
                    for i in rr:
                        if i == self.s:
                            data = i.recv(BUFFER_SIZE)
                            if len(data) == 0:
                                prot.on_close(self)
                                break
                            prot.on_recv(data, self)
            else:
                if prot.attributes['PROTOCOL_SPEAKS_FIRST']:
                    self.completed(data)
        elif len(matches) > 1:
            # We're going to have to figure out which one to try.
            # Best guess based on port, otherwise, no clue...
            self.s.close()
            if self.limit_probes:
                matches = [m for m in matches
                           if port in m.attributes['PROTOCOL_DEFAULT_PORTS']]
            for protocol in matches:
                self.probe_with_protocol(ip, port, protocol, spoke_first)

    def probe_with_protocol(self, ip, port, protocol, spoke_first):
        self.complete = False
        self.result = {"ip": ip, "port": port}
        self.result['protocol'] = protocol.attributes['NAME']
        if not self.probe_connect(ip, port):
            return

        if not spoke_first:
            protocol.on_connect(self)
        else:
            data = self.s.recv(BUFFER_SIZE)
            protocol.on_recv(data, self)

        while not self.complete:
            rr, wr, er = select.select([self.s], [], [], SOCKET_TIMEOUT)
            if len(rr) == 0:
                break
            for i in rr:
                if i == self.s:
                    data = i.recv(BUFFER_SIZE)
                    if len(data) == 0:
                        protocol.on_close(self)
                        break
                    protocol.on_recv(data, self)

    def reply(self, data):
        try:
            self.s.send(data)
        except socket.error, se:
            self.s.close()
            print("Error {error} while attempting reply: {data}".format(error=se.message, data=data))

    def completed(self, buf):
        self.result['buffer'] = buf
        self.on_completed(self.result)
        self.complete = True
        self.s.close()


def probe_start(ip, port):
    if options.output_file is not None:
        print("Probing {ip}:{port}".format(ip=ip, port=port))


def probe_complete(result):
    if options.json:
        output = json.dumps(result, ensure_ascii=False)
        if options.output_file is not None:
            with open(options.output_file, "a") as f:
                f.write(output)
                f.write("\n")
        else:
            print(output)
    else:
        print("{ip}:{port}:{protocol}\n{buffer}".format(ip=result['ip'],
                                                        port=result['port'],
                                                        protocol=result['protocol'],
                                                        buffer=result['buffer']))


if __name__ == '__main__':
    from optparse import OptionParser

    parser = OptionParser()

    parser.add_option('-i', '--ip',
                      dest='ip',
                      help='IP being connected to',
                      action='store',
                      type='string')
    parser.add_option('-p', '--port',
                      dest='port',
                      help='Port to connect to',
                      action='store',
                      type='int')
    parser.add_option('-f', '--file',
                      dest='file',
                      help='File of IP:port pairs (implies --json)',
                      action='store',
                      type='string')
    parser.add_option('-o', '--output-file',
                      dest='output_file',
                      help='File to export results to',
                      action='store',
                      type='string')
    parser.add_option('-j', '--json',
                      dest='json',
                      help='Output as JSON',
                      default=False,
                      action='store_true')
    parser.add_option('-l', '--limit-probes',
                      dest='limit_probes',
                      help='Limit probes to protocols known to operate on this port',
                      default=False,
                      action='store_true')
    (options, args) = parser.parse_args()

    p = PortProbe(probe_start, probe_complete, options.limit_probes)

    if options.file is not None:
        options.json = True
        with open(options.file) as f:
            for line in f:
                if len(line) > 0 and ':' in line:
                    (ip, port) = line.split(':')
                    p.probe(ip, int(port))
    elif options.ip is not None and options.port is not None:
        p.probe(options.ip, options.port)

    #p.probe('74.125.225.168', 80) # Google HTTP
    #p.probe('64.4.17.176', 21) # Microsoft FTP
    #p.probe('63.245.215.46', 21) # Mozilla FTP
    #p.probe('213.232.93.3', 6667) # Freenode IRC
    #p.probe('130.239.18.160', 6667) # OFTC IRC