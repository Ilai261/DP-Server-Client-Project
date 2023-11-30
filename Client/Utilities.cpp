// this is the utility functions .cpp file
// written by Ilai Azaria

#include "Utilities.h"

// this function takes a char array and returns a hex representation of it
std::string hexifyStr(const unsigned char* buffer, unsigned int length)
{
	std::stringstream s("");
	std::ios::fmtflags f(s.flags());
	s << std::hex;
	for (size_t i = 0; i < length; i++)
		s << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "" : "");
	s.flags(f);
	return s.str();
}

//this function clears a buffer
void clear(char message[], int length)
{
	for (int i = 0; i < length; i++)
		message[i] = '\0';
}

// this function prints a hex representation of a char array
void hexify(const unsigned char* buffer, unsigned int length)
{
	std::ios::fmtflags f(std::cout.flags());
	std::cout << std::hex;
	for (size_t i = 0; i < length; i++)
		std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : "");
	std::cout << std::endl;
	std::cout.flags(f);
}
