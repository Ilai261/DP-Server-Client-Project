// this is the client class .cpp file
// written by Ilai Azaria

#include "Client.h"

// sets the socket reference of this client in constructor
Client::Client(tcp::socket& socket) : s(socket)
{
}

// based on login, registers or reconnects the client
void Client::runClient()
{
	if (!login)
	{
		registerClient();
	}
	else
	{
		loginClient();
	}
}

// this functions registers the client
void Client::registerClient()
{
	cout << "registering to the server...\n\n";
	cout << "sending register request...\n\n";

	// sends first register request
	std::vector<char> replyVec;
	replyVec = sendAndReceiveRegistration();

	// parses reply header
	ReplyHeader replyHeader;
	memcpy_s(&replyHeader, REPLY_HEADER_SIZE, replyVec.data(), REPLY_HEADER_SIZE);

	if (replyHeader.code == REPLY_2100_CODE) // if registration successful
	{
		// here we write the uuid into the me.info file (and create it) and set the client uuid to the one the server sent
		RegistrationReply registerReply;
		memcpy_s(&registerReply, REPLY_2100_SIZE, replyVec.data(), REPLY_2100_SIZE);
		// copies clientId into uuid of this client
		memcpy_s(this->uuid, UUID_SIZE, registerReply.payload.clientID, UUID_SIZE);

		// print the reply
		std::cout << "reply header:\n" << "server version: " << (unsigned int)registerReply.header.version << std::endl << "reply code: " << registerReply.header.code
			<< std::endl << "payload size: " << registerReply.header.payloadSize << std::endl << std::endl;

		// create me.info and put name and uuid and private key in it (we also create the public key and put it in the client object)
		cout << "creating private key and putting it in me.info with the uuid, creating priv.key and putting in it the private key...\n\n";
		createMeInfo();
		//create priv.key
		createPrivkey();

		// moving on to public key request
		cout << "sending public key request to the server...\n\n";
		replyVec = sendAndReceivePublicKey();
		ReplyHeader replyHeader;
		memcpy_s(&replyHeader, REPLY_HEADER_SIZE, replyVec.data(), REPLY_HEADER_SIZE);

		if (replyHeader.code == REPLY_2102_CODE) // this is the case where everything went good
		{
			PublicKeyReply publicKeyReply;
			memcpy_s(&publicKeyReply, REPLY_2102_SIZE, replyVec.data(), REPLY_2102_SIZE);

			// print the reply
			std::cout << "reply header:\n" << "server version: " << (unsigned int)publicKeyReply.header.version << std::endl << "reply code: " << publicKeyReply.header.code
				<< std::endl << "payload size: " << publicKeyReply.header.payloadSize << "\n\n";
			cout << "Server sent back encrypted aes key, request was successful" << std::endl;

			// get aes key with a vector
			std::vector<char> aesKeyVector;
			aesKeyVector.assign(replyVec.begin() + REPLY_2102_HEADER_CLIENTID_SIZE, replyVec.end());

			// decrypt the aes key using the private key from priv.key, then save it in aesKey
			RSAPrivateWrapper rsapriv_other(Base64Wrapper::decode(this->base64PrivateKey));
			std::string aesKeyLocal = rsapriv_other.decrypt(aesKeyVector.data(), aesKeyVector.size());
			this->aesKey = aesKeyLocal;

			// put key into wrapper
			AESWrapper aesKeyWrapper = AESWrapper((const unsigned char*)this->aesKey.c_str(), AESWrapper::DEFAULT_KEYLENGTH);

			// sends file and calculated crc to finish the program
			sendFileAndCrc();

		}
		else // if public key request not successful
		{
			std::cout << "reply header: " << (unsigned int)replyHeader.version << std::endl << replyHeader.code << std::endl << replyHeader.payloadSize << std::endl << "public key sending has failed. Terminating the program...\n";
		}
	}
	else // if registration not successful
	{
		// terminate and print the reply
		std::cout << "reply header: " << (unsigned int)replyHeader.version << std::endl << replyHeader.code << std::endl << replyHeader.payloadSize << std::endl << "registration has failed. Terminating the program...\n";
	}
}


// this function reconnects the client
void Client::loginClient()
{
	cout << "logging in to the server...\n\n";

	// sends the first login request
	std::vector<char> replyVec;
	replyVec = sendAndReceiveLogin();

	// parses the reply header
	ReplyHeader replyHeader;
	memcpy_s(&replyHeader, REPLY_HEADER_SIZE, replyVec.data(), REPLY_HEADER_SIZE);

	if (replyHeader.code == REPLY_2105_CODE) // case where all went good
	{
		// continue login
		ValidLoginReply validLoginReply;
		memcpy_s(&validLoginReply, REPLY_2105_SIZE, replyVec.data(), REPLY_2105_SIZE);

		// print the reply
		std::cout << "reply header:\n" << "server version: " << (unsigned int)validLoginReply.header.version << std::endl << "reply code: " << validLoginReply.header.code
			<< std::endl << "payload size: " << validLoginReply.header.payloadSize << "\n\n";

		cout << "login has been successful, server sent encrypted aes key. decrypting it and sending encrypted file to the server: \n\n";

		// get aes key with a vector
		std::vector<char> aesKeyVector;
		aesKeyVector.assign(replyVec.begin() + REPLY_2105_HEADER_CLIENTID_SIZE, replyVec.end());

		// decrypt the aes key using the private key from priv.key, then save it in aesKey
		RSAPrivateWrapper rsapriv_other(Base64Wrapper::decode(this->base64PrivateKey));
		std::string aesKeyLocal = rsapriv_other.decrypt(aesKeyVector.data(), ENCRYPTED_AES_KEY_SIZE);
		this->aesKey = aesKeyLocal;

		// put key into wrapper
		AESWrapper aesKeyWrapper = AESWrapper((const unsigned char*)this->aesKey.c_str(), AESWrapper::DEFAULT_KEYLENGTH);

		// sends file and calculated crc to finish the program
		sendFileAndCrc();
		
	}
	else // if login failed
	{
		// register this client
		this->registerClient();
	}
}


// this is the function that sends registration requests and receives replies according to the protocol
std::vector<char> Client::sendAndReceiveRegistration()
{
	int sendCount = 0;
	// set the request
	RegistrationRequest request;
	strcpy_s(request.payload.name, this->name);

	std::vector<char> replyVec;
	while (sendCount < MAX_SEND_COUNT)
	{
		// send it
		boost::asio::write(s, boost::asio::buffer(reinterpret_cast<uint8_t*>(&request), sizeof(request)));

		// read the reply
		replyVec = readReply();

		// parses the reply header
		ReplyHeader replyHeader;
		memcpy_s(&replyHeader, REPLY_HEADER_SIZE, replyVec.data(), REPLY_HEADER_SIZE);

		if (replyHeader.code == REPLY_2100_CODE) // if all went good
		{
			return replyVec;
		}
		else if (replyHeader.code == REPLY_2101_CODE) // if registration failed
		{
			cout << "Server responded with an error\n" << "Error in register request: Server responded that registeration has failed code 2101...\n";
			return replyVec;
		}
		else // if the server sends 2107 tries again
		{
			cout << "server responded with an error\n";
			sendCount++;
		}
	}
	// if failed with 2107 4 times
	cout << "Error in register request: Server responded that register has failed 3 times...\n";
	return replyVec;
}


// this is the function that sends login requests and receives replies according to the protocol
std::vector<char> Client::sendAndReceiveLogin()
{
	// send the name to the server
	int sendCount = 0;
	// set the request
	LoginRequest request;

	// sets the request
	memcpy_s(request.header.clientID, UUID_SIZE, this->uuid, UUID_SIZE);
	strcpy_s(request.payload.name, this->name);

	std::vector<char> replyVec;
	while (sendCount < MAX_SEND_COUNT)
	{
		// send it
		boost::asio::write(s, boost::asio::buffer(reinterpret_cast<uint8_t*>(&request), sizeof(request)));

		//read the reply
		replyVec = readReply();

		// parses the reply header
		ReplyHeader replyHeader;
		memcpy_s(&replyHeader, REPLY_HEADER_SIZE, replyVec.data(), REPLY_HEADER_SIZE);

		if (replyHeader.code == REPLY_2105_CODE) // case where all went good
		{
			return replyVec;
		}
		else if (replyHeader.code == REPLY_2106_CODE) // if login failed
		{
			cout << "Server responded with an error\n" << "Error in login request: Server responded that login has failed code 2106, registering...\n";
			return replyVec;
		}
		else // if the server sends 2107 tries again
		{
			cout << "server responded with an error\n";
			sendCount++;
		}
	}
	// if failed with 2107 4 times
	cout << "Error in login request: Server responded that login has failed 3 times, initiating register...\n";
	return replyVec;
}


// this is the function that sends public key requests and receives replies according to the protocol
std::vector<char> Client::sendAndReceivePublicKey()
{
	// send the name and public key to the server
	int sendCount = 0;
	// set the request
	PublicKeyRequest request;
	memcpy_s(request.header.clientID, UUID_SIZE, this->uuid, UUID_SIZE);
	strcpy_s(request.payload.name, this->name);
	memcpy_s(request.payload.publicKey, RSAPublicWrapper::KEYSIZE, this->publicKey, RSAPublicWrapper::KEYSIZE);

	std::vector<char> replyVec;
	while (sendCount < MAX_SEND_COUNT)
	{
		// send it
		boost::asio::write(s, boost::asio::buffer(reinterpret_cast<uint8_t*>(&request), sizeof(request)));

		// read the reply
		replyVec = readReply();

		// parse its header
		ReplyHeader replyHeader;
		memcpy_s(&replyHeader, REPLY_HEADER_SIZE, replyVec.data(), REPLY_HEADER_SIZE);

		if (replyHeader.code == REPLY_2102_CODE) // if all went good
		{
			return replyVec;
		}
		else
		{
			// try sending again
			cout << "server responded with an error\n";
			sendCount++;
		}
	}
	// if failed 4 times
	return replyVec;
	
}


// this is the function that sends file requests and receives replies according to the protocol
void Client::sendFileAndCrc()
{
	// put the file into a string, encrypt the string, put it into the struct, put payload size filename uuid and file size into the struct, then send
	std::vector<char> replyVec = sendAndReceiveFile();
	ReplyHeader replyHeader;
	memcpy_s(&replyHeader, REPLY_HEADER_SIZE, replyVec.data(), REPLY_HEADER_SIZE);

	if (replyHeader.code == REPLY_2103_CODE) // case where file sent successfully
	{
		// check if crc was successful eventually
		if (this->crcSuccessful)
		{
			// crc check was successful
			// send request 1029
			cout << "sending to the server that crc is valid\n\n";
			replyVec = sendAndReceiveCrcValid();

			// parse the reply header
			ReplyHeader replyHeader;
			memcpy_s(&replyHeader, REPLY_HEADER_SIZE, replyVec.data(), REPLY_HEADER_SIZE);

			if (replyHeader.code == REPLY_2104_CODE) // server acknowledged, finished successfully
			{
				cout << "client has finished working succesfully, approval from the server has been received!\n";
			}
			else // server has not acknowledged
			{
				cout << "server responded with an error, client has finished working successfuly but no approval from the server has been received...\n";
			}
		}
		else
		{
			// crc check was not successful with error in the crc itself
			cout << "crc check was not successful 3 times, aboring...\n";
			// send request 1031
			cout << "sending to the server that crc is invalid\n\n";
			replyVec = sendAndReceiveCrcInvalid4thTime();

			// parse the reply header
			ReplyHeader replyHeader;
			memcpy_s(&replyHeader, REPLY_HEADER_SIZE, replyVec.data(), REPLY_HEADER_SIZE);

			if (replyHeader.code == REPLY_2104_CODE) // server acknowledged, finished 
			{
				cout << "client has finished working unsuccesfully (crc was invalid 4 times), approval from the server has been received...\n";
			}
			else // server has not acknowledged
			{
				cout << "server responded with an error, client has finished working unsuccessfuly (crc was invalid 4 times)"
					<< "but no approval from the server has been received...\n";
			}
		}
	}
	else
	{
		// crc check was not successful with error in the server
		cout << "Server responded with an error, crc check was not successful 3 times, aborting...\n";
		// send request 1031
		replyVec = sendAndReceiveCrcInvalid4thTime();

		// parses the reply header
		ReplyHeader replyHeader;
		memcpy_s(&replyHeader, REPLY_HEADER_SIZE, replyVec.data(), REPLY_HEADER_SIZE);

		if (replyHeader.code == REPLY_2104_CODE) // server acknowledged, finished 
		{
			cout << "client has finished working unsuccesfully (server responded with an error 4 times), approval from the server has been received...\n";
		}
		else // server has not acknowledged
		{
			cout << "server responded with an error, client has finished working unsuccessfuly (server responded with an error 4 times)"
				<< "but no approval from the server has been received...\n";
		}
	}
}


// put the file into a string, encrypt the string, put it into the struct, put payload size filename uuid and file size into the struct, then send
std::vector<char> Client::sendAndReceiveFile()
{
	//send count
	int sendCount = 0;
	// variables for reading the file and reply
	std::vector<char> replyVec;
	std::string file;
	std::ifstream myfile(this->filePath);
	if (myfile.is_open())
	{
		// read the file into a string and calculate crc
		file = readFileIntoString(this->filePath);
		this->crc = readfile(this->filePath);
		cout << "file crc calculated" << std::endl;

		// create aes wrapper and ecnrypted file
		AESWrapper aesKeyWrapper = AESWrapper((const unsigned char*)this->aesKey.c_str(), AESWrapper::DEFAULT_KEYLENGTH);
		std::string encryptedFile = aesKeyWrapper.encrypt(file.c_str(), file.length());

		// send the file request to the server
		int sendCount = 0;
		// set the request
		FileRequest request;
		memcpy_s(request.header.clientID, UUID_SIZE, this->uuid, UUID_SIZE);
		request.header.payloadSize = FILE_REQUEST_PAYLOAD_SIZE + encryptedFile.length();
		cout << "encrypted file size to send: " << encryptedFile.length() << " bytes" << std::endl;
		request.payload.fileSize = encryptedFile.length();
		strcpy_s(request.payload.fileName, this->fileName);

		std::vector<uint8_t> requestVector(REQUEST_HEADER_SIZE + FILE_REQUEST_PAYLOAD_SIZE);
		memcpy_s(requestVector.data(), REQUEST_HEADER_SIZE + FILE_REQUEST_PAYLOAD_SIZE, &request, REQUEST_HEADER_SIZE + FILE_REQUEST_PAYLOAD_SIZE); // copy the struct to the vector
		uint8_t* encryptedMessageContentBuffer = new uint8_t[encryptedFile.length()];
		memcpy_s(encryptedMessageContentBuffer, encryptedFile.length(), encryptedFile.c_str(), encryptedFile.length());

		requestVector.insert(requestVector.end(), encryptedMessageContentBuffer, encryptedMessageContentBuffer + encryptedFile.length()); // insert file into vector to send

		std::cout << "sending encrypted file...\n\n";
		while (sendCount < MAX_SEND_COUNT)
		{
			// send it
			boost::asio::write(s, boost::asio::buffer(requestVector, requestVector.size()));

			// read the reply
			replyVec = readReply();

			// parse its header
			ReplyHeader replyHeader;
			memcpy_s(&replyHeader, REPLY_HEADER_SIZE, replyVec.data(), REPLY_HEADER_SIZE);

			if (replyHeader.code == REPLY_2103_CODE) // case where all went good
			{
				// parse the reply header
				FileCrcReply fileCrcReply;
				memcpy_s(&fileCrcReply, REPLY_2103_SIZE, replyVec.data(), REPLY_2103_SIZE);
				std::cout << "reply header:\n" << "server version: " << (unsigned int)fileCrcReply.header.version << std::endl << "reply code: " << fileCrcReply.header.code
					<< std::endl << "payload size: " << fileCrcReply.header.payloadSize << "\n\n";

				// get the server crc check
				std::string serverCrc = std::to_string(fileCrcReply.payload.replyCrc);
				if (serverCrc == this->crc) // check if server crc == client crc
				{
					// send valid crc
					cout << "valid crc!\n";
					this->crcSuccessful = true;
					return replyVec;
				}
				else
				{
					// send invalid crc
					cout << "invalid crc!\n";
					// prepare request
					CrcInvalidRequest request;
					memcpy_s(request.header.clientID, UUID_SIZE, this->uuid, UUID_SIZE);
					strcpy_s(request.payload.fileName, this->fileName);
					// send it
					boost::asio::write(s, boost::asio::buffer(reinterpret_cast<uint8_t*>(&request), sizeof(request)));
					sendCount++;
				}
			}
			else
			{
				// reply code invalid, try sending again
				cout << "server responded with an error\n";
				sendCount++;
			}
		}
		// send 4th time failed crc
		cout << "4th time invalid crc, aborting...\n";
		this->crcSuccessful = false;
		return replyVec;
	}
	else
	{
		cout << "coudln't open file to send, aborting...\n";
		//couldn't open file, abort
	}
	return replyVec;
}


// this is the function that sends crc valid requests and receives replies according to the protocol
std::vector<char> Client::sendAndReceiveCrcValid()
{
	int sendCount = 0;
	std::vector<char> replyVec;

	// prepare request
	CrcValidRequest request;
	memcpy_s(request.header.clientID, UUID_SIZE, this->uuid, UUID_SIZE);
	strcpy_s(request.payload.fileName, this->fileName);
	
	while (sendCount < MAX_SEND_COUNT)
	{
		// send it
		boost::asio::write(s, boost::asio::buffer(reinterpret_cast<uint8_t*>(&request), sizeof(request)));

		// read the reply
		replyVec = readReply();

		// parse its header
		ReplyHeader replyHeader;
		memcpy_s(&replyHeader, REPLY_HEADER_SIZE, replyVec.data(), REPLY_HEADER_SIZE);

		if (replyHeader.code == REPLY_2104_CODE) // case where server acknowledged
		{
			return replyVec;
		}
		else // error, send again
		{
			cout << "server responded with an error\n";
			sendCount++;
		}
	}
	// if error received for 4 times
	return replyVec;
}


// this is the function that sends crc invalid for 4th time requests and receives replies according to the protocol
std::vector<char> Client::sendAndReceiveCrcInvalid4thTime()
{
	int sendCount = 0;
	std::vector<char> replyVec;

	// prepare request
	CrcInvalid4thTimeRequest request;
	memcpy_s(request.header.clientID, UUID_SIZE, this->uuid, UUID_SIZE);
	strcpy_s(request.payload.fileName, this->fileName);

	// send it
	boost::asio::write(s, boost::asio::buffer(reinterpret_cast<uint8_t*>(&request), sizeof(request)));

	while (sendCount < MAX_SEND_COUNT)
	{
		// send it
		boost::asio::write(s, boost::asio::buffer(reinterpret_cast<uint8_t*>(&request), sizeof(request)));

		// read the reply
		replyVec = readReply();

		// parse its header
		ReplyHeader replyHeader;
		memcpy_s(&replyHeader, REPLY_HEADER_SIZE, replyVec.data(), REPLY_HEADER_SIZE);

		if (replyHeader.code == REPLY_2104_CODE) // case where server acknowledged
		{
			return replyVec;
		}
		else // error, send again
		{
			cout << "server responded with an error\n";
			sendCount++;
		}
	}
	// if error received for 4 times
	return replyVec;
}


// this is the function that reads a reply of any size from the server into a char vector
std::vector<char> Client::readReply()
{

	char reply[BUFFER_SIZE];
	std::vector<char> replyVec;

	size_t currReplyLength = s.read_some(boost::asio::buffer(reply, BUFFER_SIZE)); // reads up to buffer size bytes
	ReplyHeader* replyHeader = (ReplyHeader*)reply; // parses header to get size of reply
	unsigned int payloadSize = replyHeader->payloadSize;
	unsigned int replySize = payloadSize + REPLY_HEADER_SIZE; // calculates reply size

	replyVec.insert(replyVec.end(), reply, reply + std::min(BUFFER_SIZE, replySize)); // adds buffer to vector

	unsigned int toRead = replySize - std::min(replyVec.size(), (size_t)BUFFER_SIZE); // calculates how much left to read

	// this loop does practically the same as above until nothing is left to be read
	while (toRead > 0)
	{
		unsigned int readCurr = std::min(toRead, BUFFER_SIZE);
		clear(reply, BUFFER_SIZE);
		currReplyLength = s.read_some(boost::asio::buffer(reply, BUFFER_SIZE));

		replyVec.insert(replyVec.end(), reply, reply + readCurr);
		toRead -= readCurr;
	}
	// returns the reply vector
	return replyVec;

}


// this function creates the me.info file
void Client::createMeInfo()
{
	std::ofstream myFile("me.info");

	if (myFile.is_open())
	{
		// write to the file
		std::string stringName = this->name;
		std::string stringUuid(hexifyStr((const unsigned char*)uuid, UUID_SIZE));
		myFile << stringName.c_str() << std::endl << stringUuid << std::endl;
	}
	else
	{
		cout << "error in creating me.info\n";
	}

	// create the two rsa keys
	RSAPrivateWrapper rsapriv;

	// get public key and put it in this client
	char pubkeybuff[RSAPublicWrapper::KEYSIZE];
	rsapriv.getPublicKey(pubkeybuff, RSAPublicWrapper::KEYSIZE);
	memcpy_s(this->publicKey, RSAPublicWrapper::KEYSIZE, pubkeybuff, RSAPublicWrapper::KEYSIZE);

	// create rsa encryptor (may not be neccesary here)
	RSAPublicWrapper rsapub(pubkeybuff, RSAPublicWrapper::KEYSIZE);

	// get the private key and encode it as base64 (base64 in not necessary for an RSA decryptor.) and put it in client
	std::string base64key = Base64Wrapper::encode(rsapriv.getPrivateKey());
	this->base64PrivateKey = base64key;

	// write the base64privatekey into me.info
	myFile << this->base64PrivateKey;

	// close the file
	myFile.close();
}

// this function creates the priv.key file
void Client::createPrivkey()
{
	std::ofstream myFile("priv.key");

	if (myFile.is_open())
	{
		myFile << this->base64PrivateKey;
	}
	else
	{
		cout << "error in creating priv.key\n";
	}
}


// this function checks if transfer.info is valid
bool Client::checkTransferInfo(std::string& address, std::string& port)
{
	std::ifstream myfile("transfer.info");
	std::string line;
	if (myfile.is_open())
	{
		// gets address and port
		std::getline(myfile, line);
		std::stringstream split(line);

		std::getline(split, line, ':');
		address = line;
		cout << "trying to connect to the server at-> " << line;

		std::getline(split, line, ':');
		port = line;
		cout << ":" << line << std::endl;

		std::getline(myfile, line);
		//name size - 1 is 254, we will need to add a \n so max is 254 for now
		if (line.size() > NAME_SIZE - 1)
		{
			cout << "transfer.info is corrupted, name size is too big... can't connect to the server" << std::endl;
			return false;
		}
		else
		{
			// print name
			cout << "username is: " << line << std::endl;
		}

		std::getline(myfile, line);
		//same here with filepath size - 1
		if (line.size() > FILEPATH_SIZE - 1)
		{
			cout << "transfer.info is corrupted, file path size is too big... can't connect to the server" << std::endl;
			return false;
		}
		else
		{
			// print filepath
			cout << "filepath is: " << line << "\n\n";
		}
		return true;
	}
	else // if the file can't be opened abort
	{
		cout << "No transfer.info file, can't connect to the server..." << std::endl;
		return false;
	}
}


// this is the function that sets the username and filepath based on transer.info
void Client::setNameAndFilepath()
{
	std::ifstream myfile("transfer.info");
	std::string line;
	if (myfile.is_open())
	{
		std::getline(myfile, line);
		
		// gets username
		std::getline(myfile, line);
		strcpy_s(name, line.c_str());

		std::getline(myfile, line);

		// get filename from filepath and save it
		std::filesystem::path p(line.c_str());
		
		strcpy_s(this->filePath, line.c_str());
		std::stringstream thisFileName;

		// gets filename from filepath
		thisFileName << p.filename();
		strcpy_s(this->fileName, thisFileName.str().c_str());
	}
}


// this is the function that checks if me.info is valid
bool Client::checkMeInfo()
{
	std::ifstream myfile("me.info");
	std::string line;
	if (myfile.is_open())
	{
		// sets the username and compares to trasnfer.info name previously added
		std::getline(myfile, line);
		if (line != this->name)
		{
			cout << "names in me.info and transfer.info are different, using transfer.info to register and deleting me.info and priv.key...\n";
			try
			{
				// deletes me.info and priv.key if error is found so user can register
				myfile.close();
				std::remove("me.info");
				myfile = std::ifstream("priv.key");
				if (myfile.is_open())
				{
					myfile.close();
					std::remove("priv.key");
				}
			}
			catch(std::exception& e)
			{
				cout << "error in deleting the files...\n";
			}
			return false;
		}
		cout << "username from me.info is: " << line << std::endl;
		//putting values
		std::getline(myfile, line);

		memcpy_s(this->uuid, UUID_SIZE, boost::algorithm::unhex(line).data(), UUID_SIZE);

		// reading the base64 private key
		std::ostringstream ss;
		ss << myfile.rdbuf(); 
		line = ss.str();
		this->base64PrivateKey = line;
		cout << "private key from me.info has been received\n\n";

		return true;
	}
	else
	{
		cout << "me.info doesn't exist, registering to the server using transfer.info and deleting priv.key if exists...\n";
		try
		{
			// deletes priv.key
			myfile = std::ifstream("priv.key");
			if (myfile.is_open())
			{
				myfile.close();
				std::remove("priv.key");
			}
		}
		catch (std::exception& e)
		{
			cout << "error in deleting the priv.key file (reason for trying: me.info doesn't exist)...\n";
		}
		return false;
	}
}


// this is the function that reads a file into a string
std::string Client::readFileIntoString(const std::string& filepath)
{
	std::ifstream file(filepath, std::ios::binary); // Open the file for input

	if (file.is_open())
	{
		std::string content((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>())); // read
		file.close(); // Close the file
		return content;
	}
	else 
	{
		cout << "Error: Unable to open the file." << std::endl;
		return ""; // Return an empty string in case of an error
	}
}


// this is the function that checks priv.key
bool Client::checkPrivKey()
{
	std::ifstream myfile("priv.key");
	std::string line;
	if (myfile.is_open())
	{
		// reads the file
		std::ostringstream ss;
		ss << myfile.rdbuf();
		line = ss.str();

		if (line != this->base64PrivateKey) // if priv.key key is different than the one from me.info
		{
			cout << "key in priv.key is different than key in me.info, deleting those files and registering using transfer.info...\n";
			try
			{
				// remove both files for the user to be able to register
				myfile.close();
				std::remove("priv.key");
				myfile = std::ifstream("me.info");
				if (myfile.is_open())
				{
					myfile.close();
					std::remove("me.info");
				}
			}
			catch (std::exception& e)
			{
				cout << "error in deleting the files...\n";
			}
			return false;
		}
		else // if everything is right, will login
		{
			// printing
			cout << "me.info and priv.key are valid...\n\n";
			return true;
		}
	}
	else // if file couldn't be opened (doesn't exist)
	{
		cout << "priv.key doesn't exist, registering to the server using transfer.info...\n";
		try
		{
			// delete me.info so user could register
			myfile = std::ifstream("me.info");
			if (myfile.is_open())
			{
				myfile.close();
				std::remove("me.info");
			}
		}
		catch (std::exception& e)
		{
			cout << "error in deleting the me.info file (reason for trying: priv.key doesn't exist)...\n";
		}
		return false;
	}
}

// the class destructor, closes the socket
Client::~Client()
{
	s.close();
}



