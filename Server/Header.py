# this is the header class file
# written by Ilai Azaria

import struct


# this class represents a client request header
class Header:
    REQUEST_HEADER_FORMAT = '<16scHI'
    REQUEST_HEADER_SIZE = 23

    # initiated the header
    def __init__(self, array, header_format=REQUEST_HEADER_FORMAT, header_size=REQUEST_HEADER_SIZE):
        self.client_id, self.version, self.request_code, self.payload_size = struct.unpack(header_format,
                                                                                           array[:header_size])
        self.client_id = self.client_id
        self.version = int.from_bytes(self.version, byteorder='little')
        self.request_size = self.payload_size + header_size
        self.header_format = header_format
        self.header_size = header_size

    def __str__(self):
        return ('client id: ' + str(self.client_id.hex()) + ' version: ' + str(self.version) + ' request code: ' +
                str(self.request_code) + ' payload size: ' + str(self.payload_size))


if __name__ == '__main__':
    x = b'55555555555555553222333'
    print('x as bytearray:', x)
    header = Header(x)
    print('x as header:', header)
    print('request size: ', header.request_size)
