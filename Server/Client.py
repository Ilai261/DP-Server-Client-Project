# this is the client class file
# written by Ilai Azaria
import Utilities
import base64


# this class represents a client as an object
class Client:
    # initiates client values
    def __init__(self, name, uuid=b'', public_key=b'', last_seen='', aes_key=''):
        self.name = str(name)
        self.uuid = uuid
        self.public_key = public_key
        self.last_seen = last_seen
        self.aes_key = aes_key

    def __str__(self):
        return ('Client ' + Utilities.str_no_null_terminator(self.name) + ': \nuuid: ' + str(self.uuid.hex())
                + '\npublic key: ' + str(base64.b64encode(self.public_key).decode('ascii')) +
                '\nlast seen: ' + str(self.last_seen) + '\naes key: ' + str(self.aes_key) + '\n')
