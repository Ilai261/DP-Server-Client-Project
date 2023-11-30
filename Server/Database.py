# this is the database class file
# written by Ilai Azaria

import os
import sqlite3
from Crypto.Util import Padding
import Utilities
import cksum
from Client import Client
from ServerFile import ServerFile
import uuid
from datetime import datetime
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

# constants
AES_KEY_SIZE = 16
UUID_SIZE = 16

CLIENT_NAME_LOCATION = 0
CLIENT_UUID_LOCATION = 1
CLIENT_PUBLICKEY_LOCATION = 2
CLIENT_LASTSEEN_LOCATION = 3
CLIENT_AESKEY_LOCATION = 4

FILE_UUID_LOCATION = 0
FILE_FILENAME_LOCATION = 1
FILE_PATHNAME_LOCATION = 2
FILE_VERIFIED_LOCATION = 3


# this function generates an aes key
def generate_aes_key():
    aes_key = os.urandom(AES_KEY_SIZE)
    return aes_key


# this function encrypts an aes key using a public key
def encrypt_aes_key(public_key, aes_key):
    key = RSA.import_key(public_key)
    return PKCS1_OAEP.new(key).encrypt(aes_key)


# this function decrypts a file that was encrypted with an aes key
def decrypt_aes_file(aes_key, encrypted_file):
    aes = AES.new(aes_key, AES.MODE_CBC, iv=bytes(AES_KEY_SIZE))
    decrypted_file = Padding.unpad(aes.decrypt(encrypted_file), AES.block_size)
    return decrypted_file


# this is the database class for taking care of db actions with sqlite3
class Database:
    # db class variables are the filename of the db file, and two dictionaries of client and file objects
    def __init__(self, database_filename):
        self.file = database_filename
        self.client_list = {}
        self.file_list = {}

    # checks if specific client name exists, if not gives uuid, gives lastSeen, adds to client table and returns true.
    # if yes then returns false and does nothing
    def add_client(self, client):
        try:
            # connects to file with sqlite
            with sqlite3.connect(self.file) as connection_obj:
                cursor_obj = connection_obj.cursor()
                # searches for client with this new client's name
                cursor_obj.execute(""" SELECT * FROM CLIENTS WHERE Name = ? """, (client.name,))
                connection_obj.commit()
                row = cursor_obj.fetchone()
                if row is not None:  # if client already exists don't add
                    cursor_obj.close()
                    return False, b''
                # if client doesn't exist add it
                else:
                    unique_id = uuid.uuid5(uuid.NAMESPACE_DNS, client.name)  # creates unique id based on string given
                    current_datetime = datetime.now()
                    # inserts the new client with his new uuid and last seen value
                    cursor_obj.execute(""" INSERT INTO CLIENTS (Name, Uuid, Last_Seen) VALUES (?, ?, ?) """,
                                       (client.name, unique_id.bytes, current_datetime))
                    connection_obj.commit()
                    cursor_obj.close()
                    # create new client object in RAM
                    client.uuid = unique_id.bytes
                    client.last_seen = current_datetime
                    # add the client to the client list,
                    # and create a new dictionary of files of this client in the file list
                    self.client_list[unique_id.bytes] = client
                    self.file_list[unique_id.bytes] = {}
                    # print new client list
                    print(
                        '----------------------------------------new client list----------------------------------------')
                    for c in self.client_list:
                        print(self.client_list[c])
                    # returns true as adding was successful and the new uuid
                    return True, unique_id
        except sqlite3.Error as e:
            print("sqlite error:", e)

    # adds the public key and new aes key to the client in the db and RAM,
    # creates new aes key and encrypts it. returns the encrypted aes key
    def add_public_key(self, client_id, public_key):
        try:
            # connects to the file with sqlite
            with sqlite3.connect(self.file) as connection_obj:
                cursor_obj = connection_obj.cursor()
                # searches for a client with this uuid
                cursor_obj.execute(""" SELECT * FROM CLIENTS WHERE Uuid = ? """, (client_id,))
                row = cursor_obj.fetchone()
                # if there is no such client returns false
                if row is None:
                    cursor_obj.close()
                    return False, b''
                # if there is a client with this uuid adds to it the public key and aes key
                else:
                    # adds pubkey
                    cursor_obj.execute(""" UPDATE CLIENTS SET Public_Key = ? WHERE Uuid = ? """,
                                       (public_key, client_id))
                    connection_obj.commit()
                    # adds aes key
                    aes_key = generate_aes_key()
                    cursor_obj.execute(""" UPDATE CLIENTS SET Aes_Key = ? WHERE Uuid = ? """, (aes_key, client_id))
                    connection_obj.commit()
                    # encrypts aes key
                    encrypted_aes_key = encrypt_aes_key(public_key, aes_key)

                cursor_obj.close()
                # update the client in RAM
                self.client_list[client_id].public_key = public_key
                self.client_list[client_id].aes_key = aes_key
                # return true as action was successful and the encrypted aes key
                return True, encrypted_aes_key
        except sqlite3.Error as e:
            print("sqlite error:", e)

    # create a new file with the name requested in the specific client's folder, write the file sent from client to it,
    # and add everything to the db and RAM
    def create_file(self, client_id, encrypted_file, filename):
        try:
            # connects to the file with sqlite
            with sqlite3.connect(self.file) as connection_obj:
                cursor_obj = connection_obj.cursor()
                aes_key = self.client_list[client_id].aes_key
                decrypted = decrypt_aes_file(aes_key, encrypted_file)  # the decrypted file

                # parsing the filename
                no_null_filename = Utilities.str_no_null_terminator(filename)
                no_null_no_quotes_filename = Utilities.remove_quotes(no_null_filename)

                # create the file, put into it decrypted, and save it in the file list and database. return crc
                username = Utilities.str_no_null_terminator(self.client_list[client_id].name)
                filepath = os.getcwd() + '\\' + username + '\\' + no_null_no_quotes_filename
                file_exists = os.path.exists(filepath)
                try:
                    with open(filepath, 'wb') as file:
                        file.write(decrypted)
                except Exception:
                    print('error in creating file for client ', client_id.hex())
                    return False, ''  # return false if couldn't create the file
                file_obj = ServerFile(client_id, no_null_no_quotes_filename + '\0', filepath + '\0')

                # add to db or update db
                if not file_exists:
                    cursor_obj.execute("""INSERT INTO FILES (Uuid, File_Name, Path_Name, Verified) VALUES (?, ?, ?, 
                    ?) """,
                                       (client_id, no_null_no_quotes_filename + '\0', filepath + '\0', False))
                    connection_obj.commit()
                else:
                    cursor_obj.execute("""UPDATE FILES SET File_Name = ?, Path_Name = ?, Verified = ? WHERE Uuid = ? 
                    """,
                                       (no_null_no_quotes_filename + '\0', filepath + '\0', False, client_id))
                    connection_obj.commit()
                # add to RAM
                self.file_list[client_id][no_null_no_quotes_filename + '\0'] = file_obj
                # print new file list
                print('----------------------------------------new file list----------------------------------------')
                for f, k in self.file_list.items():
                    for file in k:
                        print('file owner: ' + Utilities.str_no_null_terminator(self.client_list[f].name) + '\n'
                              + str(k[file]))
                crc = cksum.readfile(filepath)

                cursor_obj.close()
                # returns the file crc and true as adding was successful
                return True, crc
        except sqlite3.Error as e:
            print("sqlite error:", e)

    # check if client id with this username exists, and then check if public key is valid. if yes return true
    # and the new encrypted aes key, add it to db and RAM. else return false
    def get_aes_key(self, client_id, name):
        # check if user exists
        try:
            user_exists = self.client_list[client_id].name == name
        except Exception:
            return False, b''
        # if it exists then add new aes key and return the encrypted version
        if user_exists:
            public_key = self.client_list[client_id].public_key
            # try creating new aes key, return error if couldn't do so
            try:
                aes_key = generate_aes_key()
                encrypted_aes_key = encrypt_aes_key(public_key, aes_key)
            except Exception:
                # delete client from list, so it could register again if there is error in login
                self.client_list[client_id] = None
                # delete from db
                # connects to the file with sqlite
                with sqlite3.connect(self.file) as connection_obj:
                    cursor_obj = connection_obj.cursor()
                    cursor_obj.execute(""" DELETE FROM CLIENTS WHERE Uuid = ? """, (client_id,))
                    connection_obj.commit()
                    cursor_obj.close()
                return False, b''
            # if pub_key is valid and user exists, add the aes_key to the db and RAM, and return it.
            # connects to the file with sqlite
            try:
                with sqlite3.connect(self.file) as connection_obj:
                    cursor_obj = connection_obj.cursor()
                    cursor_obj.execute(""" UPDATE CLIENTS SET Aes_Key = ? WHERE Uuid = ? """, (aes_key, client_id))
                    connection_obj.commit()
                    # adds to the RAM
                    self.client_list[client_id].aes_key = aes_key
                    cursor_obj.close()
            except sqlite3.Error as e:
                print("sqlite error:", e)
            # return true and the encrypted aes key as everything went correctly
            return True, encrypted_aes_key

    # set the verified value according to the call parameters in db and RAM
    def set_verified(self, client_id, filename, verified_value):
        # connects to the file with sqlite
        try:
            with sqlite3.connect(self.file) as connection_obj:
                cursor_obj = connection_obj.cursor()
                # parses the filename
                no_null_filename = Utilities.str_no_null_terminator(filename)
                no_null_no_quotes_filename = Utilities.remove_quotes(no_null_filename)

                # update the files table
                try:
                    cursor_obj.execute(""" UPDATE FILES SET Verified = ? WHERE Uuid = ? AND File_Name = ? """,
                                       (verified_value, client_id, no_null_no_quotes_filename + '\0'))
                    connection_obj.commit()
                except Exception:
                    username = Utilities.str_no_null_terminator(self.client_list[client_id].name)
                    print('error in updating the verified value of', username + ',', 'file:',
                          no_null_no_quotes_filename + '\n')
                    return False
                # add to RAM
                self.file_list[client_id][no_null_no_quotes_filename + '\0'].verified = verified_value
                # close cursor and return true
                cursor_obj.close()
                return True
        except sqlite3.Error as e:
            print("sqlite error:", e)

    # updates the user with the parameter uuid's last seen to now
    def update_last_seen(self, client_id):
        try:
            # connects to the file with sqlite
            with sqlite3.connect(self.file) as connection_obj:
                cursor_obj = connection_obj.cursor()
                # searches for client with this uuid
                cursor_obj.execute(""" SELECT * FROM CLIENTS WHERE Uuid = ? """, (client_id,))
                row = cursor_obj.fetchone()
                curr_time = datetime.now()
                # if there is no such client return false
                if row is None:
                    cursor_obj.close()
                    return False
                # if a client is found change its last seen to now
                else:
                    cursor_obj.execute(""" UPDATE CLIENTS SET Last_Seen = ? WHERE Uuid = ? """,
                                       (curr_time, client_id))

                cursor_obj.close()
                # read the new client table
                self.client_list[client_id].last_seen = curr_time
                return True
        except sqlite3.Error as e:
            print("sqlite error:", e)

    # checks if client table exists, if yes reads it to the list, if not calls to creator
    def read_client_table(self):
        try:
            # connects to the file with sqlite
            with sqlite3.connect(self.file) as connection_obj:
                cursor_obj = connection_obj.cursor()
                try:
                    # reads the db to ram and then prints client table from RAM
                    self.read_table(cursor_obj, """ SELECT * FROM CLIENTS """, Client)
                    print('----------------------------------------client list----------------------------------------')
                    for c in self.client_list:
                        print(self.client_list[c])
                except sqlite3.OperationalError:
                    print('no client table exists, creating new table:')
                    self.create_client_table()
                cursor_obj.close()
        except sqlite3.Error as e:
            print("sqlite error:", e)

    # checks if file table exists, if yes reads it to the list, if not calls to creator
    def read_file_table(self):
        try:
            # connects to the file with sqlite
            with sqlite3.connect(self.file) as connection_obj:
                cursor_obj = connection_obj.cursor()
                try:
                    # reads the db to ram and then prints client table from RAM
                    self.read_table(cursor_obj, """ SELECT * FROM FILES """, ServerFile)
                    print('----------------------------------------file list----------------------------------------')
                    for f, k in self.file_list.items():
                        for file in k:
                            print('file owner: ' + Utilities.str_no_null_terminator(self.client_list[f].name) + '\n'
                                  + str(k[file]))
                except sqlite3.OperationalError:
                    print('no file table exists, creating new table:')
                    self.create_file_table()
                cursor_obj.close()
        except sqlite3.Error as e:
            print("sqlite error:", e)

    # creates client table
    def create_client_table(self):
        print("Creating client table...")
        self.create_table(""" CREATE TABLE CLIENTS (Name NVARCHAR(255), Uuid BLOB(16),
                                Public_Key BLOB(160), Last_Seen TIMESTAMP, Aes_Key BLOB(16)); """)

    # creates file table
    def create_file_table(self):
        print("Creating file table...")
        self.create_table(""" CREATE TABLE FILES (Uuid BLOB(16), File_Name NVARCHAR(255),
                                Path_Name NVARCHAR(255), Verified BOOL); """)

    # executes a given query (in this project use to create a table)
    def create_table(self, query):
        try:
            # connects to the file with sqlite
            with sqlite3.connect(self.file) as connection_obj:
                cursor_obj = connection_obj.cursor()
                cursor_obj.execute(query)
                cursor_obj.close()
        except sqlite3.Error as e:
            print("sqlite error:", e)

    # read a table into RAM
    def read_table(self, cursor, query, obj):
        # if the object is a client then we work on client list
        if obj == Client:
            self.client_list = {}
        # if it's a file then we will create a dictionary of dictionaries of the files, each key in the first
        # level of dictionary is a client uuid, and it points to a dictionary of filenames of files this client
        # has uploaded to the server
        else:
            self.file_list = {}
            cursor.execute(""" SELECT * FROM CLIENTS """)
            rows = cursor.fetchall()
            # create the nested dictionary
            self.file_list = {row[CLIENT_UUID_LOCATION]: {} for row in rows}
        cursor.execute(query)
        rows = cursor.fetchall()
        # add the objects accordingly
        for row in rows:
            if obj == Client:
                added_obj = obj(row[CLIENT_NAME_LOCATION], row[CLIENT_UUID_LOCATION], row[CLIENT_PUBLICKEY_LOCATION],
                                row[CLIENT_LASTSEEN_LOCATION], row[CLIENT_AESKEY_LOCATION])
                self.client_list[row[CLIENT_UUID_LOCATION]] = added_obj
            else:
                added_obj = obj(row[FILE_UUID_LOCATION], row[FILE_FILENAME_LOCATION], row[FILE_PATHNAME_LOCATION],
                                row[FILE_VERIFIED_LOCATION])
                self.file_list[row[FILE_UUID_LOCATION]][row[FILE_FILENAME_LOCATION]] = added_obj


if __name__ == '__main__':
    client = Client('hello1')
    database = Database('defensive.db')
    database.read_file_table()
    database.read_client_table()
    x = database.add_client(client)
    print(x)
    uuid = uuid.uuid5(uuid.NAMESPACE_DNS, 'hello1')
    uuid = uuid.bytes
    x = database.add_public_key(uuid, b'123')
    print(x)
    x = database.update_last_seen(uuid)
    print(x)
