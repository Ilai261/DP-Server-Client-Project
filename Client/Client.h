// this is the client class .h file
// written by Ilai Azaria
#pragma once


#include <base64.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/algorithm/hex.hpp>
#include "sha.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include <iomanip>
#include "FormatStructs.h"
#include <sstream>
#include <string>
#include "Utilities.h"
#include <filesystem>
#include "cksum_new.h"

using boost::asio::ip::tcp;
using std::cout, std::endl;


// this is the client class, main class of the client program
class Client
{

// all of the client variables
private:
	tcp::socket& s;

	char name[NAME_SIZE];
	char uuid[UUID_SIZE];
	char fileName[FILEPATH_SIZE];
	char filePath[FILEPATH_SIZE];
	std::string base64PrivateKey;
	char publicKey[RSAPublicWrapper::KEYSIZE];
	std::string aesKey; 
	std::string crc;
	bool crcSuccessful;
public:
	bool login;

// client public functions
public:
	void runClient();
	static bool checkTransferInfo(std::string& address, std::string& port);
	bool checkMeInfo();
	bool checkPrivKey();
	void setNameAndFilepath();
	Client(tcp::socket& s);
	~Client();

// client private functions
private:
	//here we will have private functions that make 'runClient'
	std::vector<char> readReply();
	void registerClient();
	void loginClient();
	std::vector<char> sendAndReceiveRegistration();
	std::vector<char> sendAndReceiveLogin();
	void createMeInfo();
	void createPrivkey();
	std::vector<char> sendAndReceivePublicKey();
	std::vector<char> sendAndReceiveFile();
	std::vector<char> sendAndReceiveCrcValid();
	std::vector<char> sendAndReceiveCrcInvalid4thTime();
	std::string readFileIntoString(const std::string& filename);
	void sendFileAndCrc();





};