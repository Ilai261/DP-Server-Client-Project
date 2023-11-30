// this is the main .cpp file of the client program
// written by Ilai Azaria

#include <base64.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
#include "sha.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include <iomanip>
#include "FormatStructs.h"
#include "Client.h"
#include "Utilities.h"

using boost::asio::ip::tcp;



int main()
{
	//checks tranfer.info and me.info and calls client accordingly (decides between register and login)

	std::string address, port;
	bool transferValid = Client::checkTransferInfo(address, port); // checks if transfer.info is valid
	if (transferValid)
	{
		// tries to connect the server
		boost::asio::io_context io_context;
		tcp::socket s(io_context);
		tcp::resolver resolver(io_context);
		try
		{
			boost::asio::connect(s, resolver.resolve(address, port));
		}
		catch (std::exception& e)
		{
			std::cerr << "Exception in connecting to the server socket, try checking transfer.info file:\n\n " << e.what() << "\n";
			exit(1);
		}
		
		// if manages to connect check me.info and priv.key if they exist, and register\login based on those files
		// the functions below set the boolean variable of login accordingly
		Client thisClient(s);
		thisClient.setNameAndFilepath();
		bool login = thisClient.checkMeInfo();
		login = thisClient.checkPrivKey();
		thisClient.login = login;
		// runs the client
		thisClient.runClient();
	}


}
