# this is the main file
# written by Ilai Azaria
import socket
import Utilities
import selectors
from Server import Server
from Database import Database

HOST = ''
DATABASE_FILEPATH = 'defensive.db'
PORT_FILEPATH = 'port.info'

# Create a selector
selector = selectors.DefaultSelector()


def main():
    # read port.info
    port = Utilities.check_port_info(PORT_FILEPATH)

    # checks defensive.db, if it doesn't exist creates the file and creates tables
    Utilities.check_database_exists(DATABASE_FILEPATH)
    database = Database(DATABASE_FILEPATH)
    database.read_client_table()  # puts data on RAM
    database.read_file_table()
    # Create a socket and make it listen with a selector in server object
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, port))
        s.listen()
        # Make the listening socket non-blocking
        s.setblocking(False)

        server = Server(s, selector, database)  # initiate server
        print(f"Server is listening on: {port}")  # print the port that the server is listening on
        server.setup_server()


if __name__ == '__main__':
    main()
