#ifndef SHA IMPLEMENTATION_H
#define SHA IMPLEMENTATION_H

#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <array>
#include <cstdlib>
#include <ctime>
#include "../pch.h"

std::string toHexString(const std::array<uint8_t, 32>& hash);
std::string computeHash(unsigned char* startAddress, size_t size);
std::string AuthcomputeHash(unsigned char* startAddress, size_t size);
std::string DebugcomputeHash(unsigned char* startAddress, size_t size);
std::string StreamcomputeHash(unsigned char* startAddress, size_t size);
#endif 