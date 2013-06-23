import re


class Protocol():
    def __init__(self):
        self.attributes = {}
        self.buf = ''

    def compile_pattern(self):
        self.regex = re.compile(self.attributes['PATTERN'])

    def matches_protocol(self, packet):
        if self.regex.match(packet) is not None:
            return True
        else:
            return False