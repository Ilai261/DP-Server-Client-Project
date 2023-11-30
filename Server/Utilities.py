# This is the file for general utility functions
# written by Ilai Azaria

import os
import sqlite3

DATABASE_FILEPATH = 'defensive.db'
PORT_FILEPATH = 'port.info'


# This function checks if the port file exists, if it does returns the port as int.
# else creates the file and puts port 1357 into it
def check_port_info(port_filepath):
    try:
        with open(port_filepath, 'r') as port_file:
            port = port_file.read()
            if (not port.isdigit()) or (int(port) < 1 or int(port) > 65535):
                raise TypeError
            return int(port)
    except FileNotFoundError:
        print("file port.info doesnt exist, creating a new one with default port 1357...")
        return create_default_port(port_filepath)
    except TypeError:
        print("content of port.info is not of appropriate value, creating a new one with default port 1357...")
        return create_default_port(port_filepath)


# creates the default port file
def create_default_port(port_filepath):
    with open(port_filepath, 'w') as port_file:
        port_file.write('1357')
        return 1357


# checks if defensive.db exists, if not creates it
def check_database_exists(database_filepath):
    try:
        with open(database_filepath, 'r'):
            return True
    except FileNotFoundError:
        print("database file not found, creating new one...")
        with open(database_filepath, 'w'):
            pass


# gets a string with null terminator and returns it without one
def str_no_null_terminator(string):
    null_terminator_index = string.find('\0')  # Find the index of the null terminator
    if null_terminator_index != -1:
        return string[:null_terminator_index]
    else:
        return string


# gets a byte array with null terminator and returns a cut of it from the beginning to the first '\0'
def bytes_one_null_terminator(bytes):
    return bytes.split(b'\x00', 1)[0] + b'\x00'


# creates a folder
def create_folder(folder_name):
    # Check if the folder already exists, and if not, create it
    if not os.path.exists(folder_name):
        if len(os.getcwd()) + len(folder_name) > 254:
            print('cant create folder, filepath size is too big')
            return False
        os.makedirs(folder_name)
        print(f"Folder '{folder_name}' created successfully in the current directory.")
        return True
    else:
        print(f"Folder '{folder_name}' already exists in the current directory.")
        return False


# removes quotes from string
def remove_quotes(s):
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    else:
        return s


if __name__ == '__main__':
    print(check_port_info(PORT_FILEPATH))
    check_database_exists(DATABASE_FILEPATH)
