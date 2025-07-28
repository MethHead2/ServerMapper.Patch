#ifndef HASH_HELPER_H
#define HASH_HELPER_H

#include <vector>
#include <string>
#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <fstream>
#pragma comment(lib, "Bcrypt.lib")
#include "../pch.h" // protection

// Helper function to compute SHA-256 hash
std::vector<BYTE> ComputeSHA256Hash(const std::string& filePath);

// Helper function to convert hash to a string for comparison
std::string HashToString(const std::vector<BYTE>& hash);

// Read expected hash from configuration file
std::string ReadExpectedHash(const std::string& filePath);

#endif // HASH_HELPER_H