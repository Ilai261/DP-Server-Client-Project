# this is the request class file
# written by Ilai Azaria

from Header import Header


# this class represents a client request
class Request:
    # initiated the request object
    def __init__(self, header, data):
        self.header = header
        self.payload = data[header.header_size: len(data)]

    def __str__(self):
        return str(self.header) + ' payload: ' + str(self.payload)


if __name__ == '__main__':
    x = b'55555555555555553222333hello im a payload'
    head = Header(x)
    request = Request(head, x)

    print('header:', head)
    print('request:', request)
