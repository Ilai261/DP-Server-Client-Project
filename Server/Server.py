# this is the server class file
# written by Ilai Azaria

import selectors
from Client import Client
from Header import Header
from Request import Request
import struct
import Utilities

SERVER_VERSION = 3
BUFF_SIZE = 1024
REGISTER_REQUEST_CODE = 1025
SEND_PUBLIC_KEY_REQUEST_CODE = 1026
LOGIN_REQUEST_CODE = 1027
FILE_REQUEST_CODE = 1028
CRC_VALID_REQUEST_CODE = 1029
CRC_INVALID_REQUEST_CODE = 1030
CRC_INVALID_4TH_TIME_REQUEST_CODE = 1031
REGISTER_REQUEST_PAYLOAD_SIZE = 255
PUBLIC_KEY_REQUEST_PAYLOAD_SIZE = 415
FILE_REQUEST_STATIC_PAYLOAD_SIZE = 259
LOGIN_REQUEST_PAYLOAD_SIZE = 255

ERROR_REPLY_2107_CODE = 2107
ERROR_REPLY_2101_CODE = 2101
REPLY_2100_CODE = 2100
REPLY_2102_CODE = 2102
REPLY_2103_CODE = 2103
REPLY_2104_CODE = 2104
REPLY_2105_CODE = 2105
REPLY_2106_CODE = 2106
UUID_SIZE = 16

ERROR_REPLY_2107 = struct.pack('<bHI', SERVER_VERSION, ERROR_REPLY_2107_CODE, 0)
ERROR_REPLY_2101 = struct.pack('<bHI', SERVER_VERSION, ERROR_REPLY_2101_CODE, 0)


# returns the reply of when registration is successful
def registration_successful(client_id):
    payload_size = UUID_SIZE
    return struct.pack('<bHI16s', SERVER_VERSION, REPLY_2100_CODE, payload_size, client_id)


# returns the reply of when public key request is successful
def public_key_successful(client_id, aes_key):
    payload_size = UUID_SIZE + len(aes_key)
    return struct.pack('<bHI16s' + str(len(aes_key)) + 's', SERVER_VERSION, REPLY_2102_CODE, payload_size,
                       client_id, aes_key)


# returns the reply of when file request is successful
def get_file_successful(client_id, file_size, filename, crc):
    payload_size = 279
    return struct.pack('<bHI16sI255sI', SERVER_VERSION, REPLY_2103_CODE, payload_size, client_id, file_size, filename,
                       int(crc))


# returns the reply of when server sends an approval message to client
def approval_reply(client_id):
    payload_size = UUID_SIZE
    return struct.pack('<bHI16s', SERVER_VERSION, REPLY_2104_CODE, payload_size, client_id)


# returns the reply of when login is successful
def login_successful(client_id, aes_key):
    payload_size = UUID_SIZE + len(aes_key)
    return struct.pack('<bHI16s' + str(len(aes_key)) + 's', SERVER_VERSION, REPLY_2105_CODE, payload_size,
                       client_id, aes_key)


# returns the reply of when login is unsuccessful
def login_unsuccessful(client_id):
    payload_size = UUID_SIZE
    return struct.pack('<bHI16s', SERVER_VERSION, REPLY_2106_CODE, payload_size, client_id)


# this is the server class, the main class of this program
class Server:
    # a server object has a socket, a selector and a db
    def __init__(self, sock, selector, database):
        self.sock = sock
        self.selector = selector
        self.database = database

    # sets up the server for work with its selector
    def setup_server(self):
        # Register the listening socket for accepting connections
        self.selector.register(self.sock, selectors.EVENT_READ, self.accept)
        try:
            while True:
                events = self.selector.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
        except KeyboardInterrupt:
            print("Server terminated.")

    # accepts read events to selector
    def accept(self, sock, mask):
        conn, addr = sock.accept()
        print('Accepted connection from', addr, '\n')
        conn.setblocking(False)
        self.selector.register(conn, selectors.EVENT_READ, self.read)

    # takes care directly of read events
    def read(self, conn, mask):
        # here we have the code that does server functions!
        try:
            # recv buffer every time
            data = conn.recv(BUFF_SIZE)

            if data:
                # code to get to_read, using header
                header = Header(data)
                # updates last_seen
                self.database.update_last_seen(header.client_id)
                to_read = header.request_size - min(len(data), BUFF_SIZE)

                # get the whole request into data
                while to_read > 0:
                    read_curr = min(to_read, BUFF_SIZE)
                    data += conn.recv(read_curr)
                    to_read -= read_curr

                # this line creates an object of the request we just got
                request = Request(header, data)
                # this block calls the appropriate function
                reply_data = self.get_request_function(request)(request)

                conn.sendall(reply_data)
                print('sent reply!\n')

            else:  # maybe we don't need an else, may induce bugs
                print('closing', conn)
                self.selector.unregister(conn)
                conn.close()

        except ConnectionResetError:  # sudden close
            print('Connection closed by client')
            self.selector.unregister(conn)
            conn.close()
        except ConnectionAbortedError:  # sudden close
            print('Connection closed by client')
            self.selector.unregister(conn)
            conn.close()

    # this function returns the appropriate function to take care of the request
    def get_request_function(self, request):
        request_codes = {REGISTER_REQUEST_CODE: self.register_client, SEND_PUBLIC_KEY_REQUEST_CODE: self.get_public_key,
                         LOGIN_REQUEST_CODE: self.login_client, FILE_REQUEST_CODE: self.get_file,
                         CRC_VALID_REQUEST_CODE: self.crc_valid_actions,
                         CRC_INVALID_REQUEST_CODE: self.crc_invalid_actions,
                         CRC_INVALID_4TH_TIME_REQUEST_CODE: self.crc_invalid_4th_time_actions}

        return request_codes.get(request.header.request_code)

    # this function registers a client
    def register_client(self, request):
        print('register request:\n')
        print('payload size:', len(request.payload))
        # checks if payload is right size
        if len(request.payload) != REGISTER_REQUEST_PAYLOAD_SIZE:
            print('register request from', request.header.client_id, 'includes inappropriate payload size...'
                                                                     'sending reply 2107\n')
            return ERROR_REPLY_2107
        else:
            # check if username (payload) exists, if yes return reply 2101.
            # if not then create new uuid for this username, add the client, and return reply 2100.
            name_payload_format = '<255s'
            try:
                str_payload, = struct.unpack(name_payload_format, request.payload)
            except Exception:
                return ERROR_REPLY_2107

            # parse the username
            str_payload = Utilities.bytes_one_null_terminator(str_payload)
            str_payload = str(str_payload, 'ascii')

            # create client object and call to add client in db class
            added_client = Client(str_payload)
            successful, client_id = self.database.add_client(added_client)

            # send appropriate reply to client
            if successful:
                print('added client name:', Utilities.str_no_null_terminator(added_client.name))
                reply_2100 = registration_successful(client_id.bytes)
                # create folder for user files
                folder_successful = Utilities.create_folder(Utilities.str_no_null_terminator(added_client.name))
                if not folder_successful:
                    print('folder creation unsuccessful, sending reply 2107')
                    return ERROR_REPLY_2107
                else:
                    print('sending uuid to client')
                    return reply_2100
            else:
                print('register unsuccessful, sending reply 2101')
                return ERROR_REPLY_2101

    # this function takes care of public key request
    def get_public_key(self, request):
        print('public key request:\n')
        # checks if payload is right size
        print('payload size:', len(request.payload))
        if len(request.payload) != PUBLIC_KEY_REQUEST_PAYLOAD_SIZE:
            print('public key request from', request.header.client_id, 'includes inappropriate payload size...'
                                                                       'sending reply 2107\n')
            return ERROR_REPLY_2107
        # gets the payload, unpacks it, calls to function from db
        else:
            public_key_payload_format = '<255s160s'
            try:
                name, public_key = struct.unpack(public_key_payload_format, request.payload)
            except Exception:
                return ERROR_REPLY_2107
            print(Utilities.str_no_null_terminator(str(Utilities.bytes_one_null_terminator(name), 'ascii')),
                  'has sent public key, creating aes key, encrypting it and sending back...\n')
            client_id = request.header.client_id
            successful, encrypted_aes_key = self.database.add_public_key(client_id, public_key)

            # send appropriate reply to client
            if successful:
                reply_2102 = public_key_successful(client_id, encrypted_aes_key)
                print('public key request successful, sending back encrypted aes key')
                return reply_2102
            else:
                print('public key request unsuccessful, sending back reply 2107')
                return ERROR_REPLY_2107

    # this is the function that adds a file to the server
    def get_file(self, request):
        # get static payload, get file. decrypt the file and write it into the client file. then call for
        # database function to save the file name and path, and send back answer with crc
        print('file request:\n')
        data_payload = request.payload[:FILE_REQUEST_STATIC_PAYLOAD_SIZE]
        file_payload_data_format = '<I255s'
        # unpack the static file payload
        try:
            encrypted_file_size, filename = struct.unpack(file_payload_data_format, data_payload)
        except Exception:
            return ERROR_REPLY_2107
        # parse the filename
        one_null_filename = Utilities.bytes_one_null_terminator(filename)
        one_null_filename = str(one_null_filename, 'ascii')

        # get the encrypted file from payload
        encrypted_file = request.payload[FILE_REQUEST_STATIC_PAYLOAD_SIZE:]
        client_id = request.header.client_id
        # call to db function
        successful, crc = self.database.create_file(client_id, encrypted_file, one_null_filename)

        # send appropriate reply to client
        if successful:
            print('file storing successful, sending back crc')
            reply_2103 = get_file_successful(client_id, encrypted_file_size, filename, int(crc))
            return reply_2103
        else:
            print('file storing unsuccessful, sending reply 2107')
            return ERROR_REPLY_2107

    # this function logins (reconnects) a client
    def login_client(self, request):
        print('login request:\n')
        # checks if payload is right size
        print('payload size:', len(request.payload))
        if len(request.payload) != LOGIN_REQUEST_PAYLOAD_SIZE:
            print('login request from', request.header.client_id, 'includes inappropriate payload size...'
                                                                  'sending reply 2107\n')
            return ERROR_REPLY_2107
        else:
            # unpack the payload
            login_payload_format = '<255s'
            try:
                name, = struct.unpack(login_payload_format, request.payload)
            except Exception:
                return ERROR_REPLY_2107
            # get the username and print it
            str_payload = Utilities.bytes_one_null_terminator(name)
            name = str(str_payload, 'ascii')
            print('login request from:', Utilities.str_no_null_terminator(name), 'has been received')
            client_id = request.header.client_id
            # call to db function
            successful, encrypted_aes_key = self.database.get_aes_key(client_id, name)

            # send appropriate reply to client
            if successful:
                print('login request successful, sending reply 2105')
                reply_2105 = login_successful(client_id, encrypted_aes_key)
                return reply_2105
            else:
                print('login request unsuccessful, sending reply 2106')
                reply_2106 = login_unsuccessful(client_id)
                return reply_2106

    # this function takes care of valid crc request
    def crc_valid_actions(self, request):
        print('crc valid request:\n')
        # unpacks request
        client_id = request.header.client_id
        payload_format = '<255s'
        try:
            filename, = struct.unpack(payload_format, request.payload)
        except Exception:
            return ERROR_REPLY_2107
        # parses filename
        one_null_filename = Utilities.bytes_one_null_terminator(filename)
        one_null_filename = str(one_null_filename, 'ascii')

        # call to db function to change verified to true
        print('changing the file status to verified')
        successful = self.database.set_verified(client_id, one_null_filename, True)

        # send appropriate reply to client
        if successful:
            reply_2104 = approval_reply(client_id)
            print('change successful, updating client')
            return reply_2104
        else:
            return ERROR_REPLY_2107

    # this function takes care of invalid crc request
    def crc_invalid_actions(self, request):
        print('crc invalid request:\n')
        # unpacks request
        client_id = request.header.client_id
        payload_format = '<255s'
        try:
            filename, = struct.unpack(payload_format, request.payload)
        except Exception:
            return ERROR_REPLY_2107
        # parses filename
        filename = str(Utilities.str_no_null_terminator(filename), 'ascii')

        # prints the message from client and acknowledges
        print('crc from client', Utilities.str_no_null_terminator(self.database.client_list[client_id].name) +
              ',', 'file:', filename, 'was invalid\n')
        reply_2104 = approval_reply(client_id)
        print('acknowledging the client')
        return reply_2104

    # this function takes care of the crc invalid for the 4th time request
    def crc_invalid_4th_time_actions(self, request):
        print('crc invalid 4th time request:\n')
        # unpacks request
        client_id = request.header.client_id
        payload_format = '<255s'
        try:
            filename, = struct.unpack(payload_format, request.payload)
        except Exception:
            return ERROR_REPLY_2107
        # parses the filename
        one_null_filename = Utilities.bytes_one_null_terminator(filename)
        one_null_filename = str(one_null_filename, 'ascii')

        # calls the db function
        successful = self.database.set_verified(client_id, one_null_filename, False)

        # send appropriate reply to client
        if successful:
            reply_2104 = approval_reply(client_id)
            print('changing the file status to unverified')
            return reply_2104
        else:
            print('changing the file status to unverified')
            return ERROR_REPLY_2107


if __name__ == '__main__':
    print(ERROR_REPLY_2107)
    print(struct.unpack("<bHI", ERROR_REPLY_2107))
    x = struct.pack("<bhl", 1, 2, 3)
    print(x)
