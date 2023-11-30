// this is the structs and constants .h file
// written by Ilai Azaria
#pragma once
#pragma pack(1)


#include <iostream>

// these are all the constants of the program

const unsigned int BUFFER_SIZE = 1024;
const unsigned int MAX_SEND_COUNT = 4;
const unsigned int REQUEST_HEADER_SIZE = 23;

const unsigned int UUID_SIZE = 16;
const unsigned int NAME_SIZE = 255;
const unsigned int CLIENT_VERSION = 3;
const unsigned int FILEPATH_SIZE = 255;
const unsigned int FILENAME_SIZE = 255;

const unsigned int REPLY_HEADER_SIZE = 7;
const unsigned int REPLY_2100_SIZE = 23;
const unsigned int REPLY_2100_CODE = 2100;

const unsigned int REPLY_2101_CODE = 2101;

const unsigned int REGISTER_REQUEST_CODE = 1025;
const unsigned int LOGIN_REQUEST_CODE = 1027;
const unsigned int CRC_VALID_REQUEST_CODE = 1029;
const unsigned int CRC_INVALID_REQUEST_CODE = 1030;
const unsigned int CRC_INVALID_4TH_REQUEST_CODE = 1031;


const unsigned int REPLY_2102_SIZE = 151; // in case aes key is 128 bytes
const unsigned int REPLY_2102_CODE = 2102;
const unsigned int REPLY_2102_HEADER_CLIENTID_SIZE = 23;
const unsigned int PUBLIC_KEY_REQUEST_CODE = 1026;
const unsigned int PUBLIC_KEY_REQUEST_PAYLOAD_SIZE = 415;
const unsigned int ENCRYPTED_AES_KEY_SIZE = 128; // in all checks this has been the size, altough this is not assured

const unsigned int FILE_REQUEST_CODE = 1028;
const unsigned int FILE_REQUEST_PAYLOAD_SIZE = 259;

const unsigned int REPLY_2103_CODE = 2103;
const unsigned int REPLY_2103_SIZE = 286;

const unsigned int REPLY_2104_CODE = 2104;

const unsigned int REPLY_2105_SIZE = 151;
const unsigned int REPLY_2105_CODE = 2105;
const unsigned int REPLY_2105_HEADER_CLIENTID_SIZE = 23;

const unsigned int REPLY_2106_CODE = 2106;

// the reply header
struct ReplyHeader
{
	uint8_t version;
	uint16_t code;
	uint32_t payloadSize;
};

// the payload of the reply to registeration request
struct RegistrationReplyPayload
{
	char clientID[UUID_SIZE];
};

// the payload of the public key request
struct PublicKeyRequestPayload
{
	char name[NAME_SIZE];
	char publicKey[RSAPublicWrapper::KEYSIZE];
};

// the reply to the registration request
struct RegistrationReply
{
	ReplyHeader header;
	RegistrationReplyPayload payload;
};

// the payload of the reply to public key request (aes key field is not used in practice)
struct PublicKeyReplyPayload
{
	char clientID[UUID_SIZE];
	char aesKey[ENCRYPTED_AES_KEY_SIZE];
};

// the reply to the public key request
struct PublicKeyReply
{
	ReplyHeader header;
	PublicKeyReplyPayload payload;
};

// the request header
struct RequestHeader
{
	char clientID[UUID_SIZE];
	uint8_t version = CLIENT_VERSION;
	uint16_t code;
	uint32_t payloadSize;
};

// the payload of the registration request
struct RegistrationRequestPayload
{
	char name[NAME_SIZE];
};

// the registration request
struct RegistrationRequest
{
	RequestHeader header = {"ignore", CLIENT_VERSION, REGISTER_REQUEST_CODE, NAME_SIZE};
	RegistrationRequestPayload payload;
};

// the public key request
struct PublicKeyRequest
{
	RequestHeader header = { "", CLIENT_VERSION, PUBLIC_KEY_REQUEST_CODE, PUBLIC_KEY_REQUEST_PAYLOAD_SIZE };
	PublicKeyRequestPayload payload;

};

// the payload of the file send request (not including the file itself)
struct FileRequestPayload
{
	uint32_t fileSize;
	char fileName[FILENAME_SIZE];
};

// the file send request
struct FileRequest
{
	RequestHeader header = { "", CLIENT_VERSION, FILE_REQUEST_CODE, 0 };
	FileRequestPayload payload;
};

// the file with crc reply payload
struct FileCrcReplyPayload
{
	char clientID[UUID_SIZE];
	uint32_t fileSize;
	char fileName[FILENAME_SIZE];
	uint32_t replyCrc;
};

// the file with crc reply
struct FileCrcReply
{
	ReplyHeader header;
	FileCrcReplyPayload payload;
};

// the crc request payload template
struct CrcRequestPayload
{
	char fileName[FILENAME_SIZE];
};

// the crc valid request
struct CrcValidRequest
{
	RequestHeader header = {"", CLIENT_VERSION, CRC_VALID_REQUEST_CODE, FILENAME_SIZE};
	CrcRequestPayload payload;
};

// the crc invalid request
struct CrcInvalidRequest
{
	RequestHeader header = { "", CLIENT_VERSION, CRC_INVALID_REQUEST_CODE, FILENAME_SIZE };
	CrcRequestPayload payload;
};

// the crc invalid 4th time request
struct CrcInvalid4thTimeRequest
{
	RequestHeader header = { "", CLIENT_VERSION, CRC_INVALID_4TH_REQUEST_CODE, FILENAME_SIZE };
	CrcRequestPayload payload;
};

// the login request payload
struct LoginRequestPayload
{
	char name[NAME_SIZE];
};

// the login request
struct LoginRequest
{
	RequestHeader header = {"", CLIENT_VERSION, LOGIN_REQUEST_CODE, NAME_SIZE};
	LoginRequestPayload payload;
};

// the reply of when login is valid payload
struct ValidLoginReplyPayload
{
	char clientID[UUID_SIZE];
	char aesKey[ENCRYPTED_AES_KEY_SIZE];
};

// the reply of when login is valid
struct ValidLoginReply
{
	ReplyHeader header;
	PublicKeyReplyPayload payload;
};




