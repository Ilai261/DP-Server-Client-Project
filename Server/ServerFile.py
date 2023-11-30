# this is the class that represents files sent to the server
# written by Ilai Azaria

import Utilities


class ServerFile:
    # initiates the file object
    def __init__(self, uuid=b'', filename='', pathname='', verified=False):
        self.uuid = uuid
        self.filename = filename
        self.pathname = pathname
        self.verified = verified

    def __str__(self):
        return ('Client uuid: ' + str(self.uuid.hex()) + '\nfile name: ' +
                Utilities.str_no_null_terminator(self.filename) + '\npath name: ' +
                Utilities.str_no_null_terminator(self.pathname)
                + '\nverified: ' + str(bool(self.verified)) + '\n')
