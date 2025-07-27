#ifndef HASH_UTILS_H
#define HASH_UTILS_H

#include <vector>
#include <string>
#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <fstream>
#pragma comment(lib, "Bcrypt.lib")
#include "../pch.h"

// Function to compute SHA-256 hash of a file
std::vector<BYTE> ComputeSHA256Hash(const std::wstring& filePath);

#endif // HASH_UTILS_H