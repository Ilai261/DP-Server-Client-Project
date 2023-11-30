// this is the utility functions .h file
// written by Ilai Azaria
#pragma once



#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <sstream>

void hexify(const unsigned char* buffer, unsigned int length);
std::string hexifyStr(const unsigned char* buffer, unsigned int length);
void clear(char message[], int length);
